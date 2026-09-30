"""Exact, short-lived native approval for one corrected captured-version copy.

This executor is separate from the investigator. Its private session owns paths,
tokens and bytes; the durable journal owns at-most-once claims and observations.
No model or HTTP request can invoke it, and restart cannot restore write authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

from systemsense.application.local_json_task import resolve_selected_json_task
from systemsense.application.native_file_capture import (
    NativeFileCaptureError,
    exchange_native_helper,
)
from systemsense.domain.time import utc_now
from systemsense.platform.windows.selected_file import (
    SelectedFileCapture,
    _path_components,
    _ReadFailure,
    _validate_json_bytes,
)
from systemsense.platform.windows.selected_file_copy import SelectedFileCopyResult
from systemsense.platform.windows.selected_file_copy_worker import NativeCopyRequest
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

# The private byte/lexical validators stay inside the fixed native executor.
# pyright: reportPrivateUsage=false


class JsonRepairError(ValueError):
    """Safe protocol error without private paths or byte content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _hash(value: str | bytes) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def json_copy_available(capture: SelectedFileCapture) -> bool:
    now = utc_now()
    captured = capture.observation.collection_completed_at
    contents = capture._private_bytes()
    return (
        captured <= now < captured + timedelta(minutes=5)
        and contents is not None
        and contents.startswith(b"\xef\xbb\xbf")
        and _validate_json_bytes(contents[3:])[0] == "valid_json"
    )


@dataclass(repr=False)
class _Offer:
    preview: dict[str, object]
    output: bytes = field(repr=False)
    offer_token: str = field(repr=False)
    destination: str | None = field(default=None, repr=False)
    proposal_token: str | None = field(default=None, repr=False)
    proposal_digest: str | None = None
    operation_id: str | None = None
    revoked: bool = False


class NativeJsonRepairSession:
    def __init__(self, database: Path) -> None:
        self.database = database
        self._lock = threading.RLock()
        self._offers: dict[str, _Offer] = {}

    def recover_interrupted(self) -> None:
        # Authority is never persisted. A new owner reports uncertainty, never retries.
        with SQLiteStore(self.database) as store, store.transaction():
            for operation_id, encoded in store.connection.execute(
                "SELECT operation_id, record_json FROM json_copy_operations WHERE status='pending'"
            ).fetchall():
                record = json.loads(encoded)
                record["status"] = "uncertain"
                record["error_code"] = "owner_interrupted"
                store.connection.execute(
                    "UPDATE json_copy_operations SET status='uncertain', record_json=?, "
                    "completed_at=? WHERE operation_id=?",
                    (_canonical(record), utc_now().isoformat(), operation_id),
                )

    def prepare(self, case_id: str, capture: SelectedFileCapture) -> dict[str, object]:
        now = utc_now()
        observed = capture.observation
        expiry = observed.collection_completed_at + timedelta(minutes=5)
        if not observed.collection_completed_at <= now < expiry:
            raise JsonRepairError("expired")
        contents = capture._private_bytes()
        if (
            contents is None
            or not contents.startswith(b"\xef\xbb\xbf")
            or _validate_json_bytes(contents[3:])[0] != "valid_json"
        ):
            raise JsonRepairError("ineligible")
        with SQLiteStore(self.database) as store:
            state = InvestigationRepository(store).load(case_id)
            if state.status.value != "complete" or state.task_observation_reference is None:
                raise JsonRepairError("busy")
            task = resolve_selected_json_task(
                store, case_id=state.case_id, reference=state.task_observation_reference
            )
            row = store.connection.execute(
                "SELECT record_json FROM evidence WHERE case_id=? AND evidence_id=?",
                (case_id, str(task.evidence_id)),
            ).fetchone()
            if row is None:
                raise JsonRepairError("source_unavailable")
            facts = {item["name"]: item["value"] for item in json.loads(str(row[0]))["facts"]}
            if facts.get("selected_file") != observed.model_dump(mode="json"):
                raise JsonRepairError("ineligible")
        output = contents[3:]
        preview: dict[str, object] = {
            "case_id": case_id,
            "operation": "remove_utf8_bom_copy",
            "capture_sha256": observed.content_sha256,
            "captured_at": observed.collection_completed_at.isoformat().replace("+00:00", "Z"),
            "source_size_bytes": len(contents),
            "output_sha256": _hash(output),
            "output_size_bytes": len(output),
            "expires_at": expiry.isoformat().replace("+00:00", "Z"),
        }
        with self._lock:
            if len(self._offers) >= 128:
                raise JsonRepairError("unavailable")
            token = secrets.token_urlsafe(32)
            self._offers[token] = _Offer(preview, output, token)
        return {"type": "json_repair_prepared", "offer_token": token, "preview": dict(preview)}

    def _offer(self, token: str, *, proposal: bool = False, require_live: bool = True) -> _Offer:
        offer = (
            next((item for item in self._offers.values() if item.proposal_token == token), None)
            if proposal
            else self._offers.get(token)
        )
        if offer is None or offer.revoked:
            raise JsonRepairError("source_unavailable")
        if require_live and utc_now() >= datetime.fromisoformat(str(offer.preview["expires_at"])):
            raise JsonRepairError("expired")
        return offer

    def bind(self, token: str, destination: str) -> dict[str, object]:
        try:
            _path_components(destination)
            if any(
                ord(char) < 32
                or ord(char) == 127
                or char in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
                for char in destination
            ):
                raise ValueError("unsupported")
        except (ValueError, OSError, _ReadFailure):
            raise JsonRepairError("scope_blocked") from None
        with self._lock:
            offer = self._offer(token)
            if offer.proposal_token is not None:
                raise JsonRepairError("invalid_request")
            offer.destination = destination
            offer.proposal_token = secrets.token_urlsafe(32)
            offer.proposal_digest = _hash(
                _canonical(
                    {
                        "preview": offer.preview,
                        "destination_path_sha256": _hash(destination),
                        "nonce": offer.proposal_token,
                    }
                )
            )
            return {
                "type": "json_repair_bound",
                "proposal_token": offer.proposal_token,
                "proposal_digest": offer.proposal_digest,
                "destination_path_sha256": _hash(destination),
                "preview": dict(offer.preview),
            }

    def abandon(self, token: str) -> None:
        with self._lock:
            offer = self._offer(token, require_live=False)
            if offer.operation_id is not None:
                raise JsonRepairError("invalid_request")
            offer.revoked = True
            offer.output = b""
            offer.destination = None

    def _read(self, operation_id: str) -> dict[str, object]:
        with SQLiteStore(self.database) as store:
            row = store.connection.execute(
                "SELECT record_json FROM json_copy_operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise JsonRepairError("unavailable")
            value = cast("dict[str, object]", json.loads(str(row[0])))
        return {
            key: value[key]
            for key in (
                "operation_id",
                "status",
                "verification",
                "capture_sha256",
                "source_size_bytes",
                "output_sha256",
                "output_size_bytes",
                "evidence_ids",
            )
        } | {"type": "json_repair_result"}

    def status(self, token: str) -> dict[str, object]:
        with self._lock:
            offer = self._offer(token, proposal=True, require_live=False)
            if offer.operation_id is None:
                raise JsonRepairError("invalid_request")
            return self._read(offer.operation_id)

    def execute(self, token: str, digest: str, cancellation: threading.Event) -> dict[str, object]:
        with self._lock:
            offer = self._offer(token, proposal=True, require_live=False)
            if not secrets.compare_digest(digest, offer.proposal_digest or ""):
                raise JsonRepairError("invalid_request")
            if offer.operation_id is not None:
                return self._read(offer.operation_id)
            self._offer(token, proposal=True)
            if cancellation.is_set() or offer.destination is None:
                raise JsonRepairError("unavailable")
            operation_id = "copy_" + uuid4().hex
            record: dict[str, object] = {
                **offer.preview,
                "operation_id": operation_id,
                "status": "pending",
                "verification": None,
                "evidence_ids": [],
                "proposal_digest": digest,
                "destination_path_sha256": _hash(offer.destination),
                "claimed_at": utc_now().isoformat(),
                "error_code": None,
                "observation": None,
            }
            request = NativeCopyRequest(
                destination_path=offer.destination,
                contents_base64=base64.b64encode(offer.output).decode("ascii"),
                output_sha256=str(record["output_sha256"]),
            )
            with SQLiteStore(self.database) as store, store.transaction():
                store.connection.execute(
                    "INSERT INTO json_copy_operations(operation_id,case_id,proposal_digest,"
                    "status,record_json,claimed_at) VALUES(?,?,?,'pending',?,?)",
                    (
                        operation_id,
                        str(record["case_id"]),
                        digest,
                        _canonical(record),
                        str(record["claimed_at"]),
                    ),
                )
            # Commit consumes the grant before any filesystem mutation.
            offer.operation_id = operation_id
            offer.output = b""
            offer.destination = None
        try:
            output = exchange_native_helper(
                "systemsense.platform.windows.selected_file_copy_worker",
                request.model_dump_json().encode("utf-8"),
                cancellation,
            )
            observed = SelectedFileCopyResult.model_validate_json(output)
            if (
                observed.expected_content_sha256 != record["output_sha256"]
                or observed.expected_size_bytes != record["output_size_bytes"]
            ):
                raise ValueError("copy_result_binding_invalid")
            record.update(
                status="verified"
                if observed.outcome == "verified"
                else "failed"
                if observed.outcome == "not_created"
                else "uncertain",
                error_code=observed.error_code,
                observation=observed.model_dump(mode="json"),
            )
            record["evidence_ids"] = ["copy_ev_" + uuid4().hex]
            if observed.outcome == "verified":
                record["verification"] = "independent_output_read"
        except (NativeFileCaptureError, ValueError):
            record.update(status="uncertain", error_code="helper_result_unavailable")
        record["completed_at"] = utc_now().isoformat()
        with SQLiteStore(self.database) as store, store.transaction():
            store.connection.execute(
                "UPDATE json_copy_operations SET status=?,record_json=?,completed_at=? "
                "WHERE operation_id=? AND status='pending'",
                (
                    str(record["status"]),
                    _canonical(record),
                    str(record["completed_at"]),
                    operation_id,
                ),
            )
        return self._read(operation_id)


def saved_json_copy_receipts(store: SQLiteStore, case_id: str) -> list[dict[str, object]]:
    """User-visible repair observations, separate from diagnostic evidence/probe claims."""
    return [
        cast("dict[str, object]", json.loads(str(row[0])))
        for row in store.connection.execute(
            "SELECT record_json FROM json_copy_operations WHERE case_id=? ORDER BY claimed_at",
            (case_id,),
        ).fetchall()
    ]
