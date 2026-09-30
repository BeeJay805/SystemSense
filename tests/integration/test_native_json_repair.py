"""Exact native approval, durable single-use claims and real owned Windows copies."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from systemsense.application import native_json_repair
from systemsense.application.bootstrap import default_investigator
from systemsense.application.native_file_capture import NativeFileCaptureError
from systemsense.application.native_json_repair import JsonRepairError, NativeJsonRepairSession
from systemsense.application.service import ApplicationService
from systemsense.platform.windows.selected_file import capture_selected_file
from systemsense.storage.sqlite_store import SQLiteStore

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows native copy")
# Exercise private capture custody and disabled-executor boundaries intentionally.
# pyright: reportPrivateUsage=false


def test_approved_copy_is_exact_private_and_single_use(tmp_path: Path) -> None:
    source = tmp_path / "private-source.json"
    source.write_bytes(b'\xef\xbb\xbf{"private_canary":true}')
    destination = tmp_path / "copie-入力.json"
    database = tmp_path / "cases.db"
    with_service = ApplicationService(
        database, factory=default_investigator, enable_local_json=True
    )
    try:
        case_id = str(with_service.start_local_json_case(str(source))["case_id"])
        with_service.wait(timeout=20)
        repair = NativeJsonRepairSession(database)
        assert with_service._selected_file is not None
        capture = with_service._selected_file[1]
        offer = repair.prepare(case_id, capture)
        assert not destination.exists()
        bound = repair.bind(str(offer["offer_token"]), str(destination))
        assert not destination.exists()
        # The grant is for captured bytes. Never silently reopen the source.
        source.write_bytes(b'{"newer":1}')
        result = repair.execute(
            str(bound["proposal_token"]), str(bound["proposal_digest"]), threading.Event()
        )
        assert result["status"] == "verified"
        assert result["verification"] == "independent_output_read"
        assert result["evidence_ids"]
        assert destination.read_bytes() == b'{"private_canary":true}'
        assert source.read_bytes() == b'{"newer":1}'
        # Repeated execute can read a receipt, but cannot write again.
        destination.write_bytes(b"later changed")
        assert (
            repair.execute(
                str(bound["proposal_token"]), str(bound["proposal_digest"]), threading.Event()
            )
            == result
        )
        assert destination.read_bytes() == b"later changed"
        assert repair.status(str(bound["proposal_token"])) == result
        with SQLiteStore(database) as store:
            durable = str(
                store.connection.execute("SELECT record_json FROM json_copy_operations").fetchone()[
                    0
                ]
            )
            assert "private_canary" not in durable
            assert str(source) not in durable and str(destination) not in durable
            assert str(bound["proposal_token"]) not in durable
            assert (
                json.loads(durable)["observation"]["verification_check"]["outcome"] == "valid_json"
            )
            assert (
                json.loads(durable)["output_sha256"]
                == hashlib.sha256(b'{"private_canary":true}').hexdigest()
            )
        NativeJsonRepairSession(database).recover_interrupted()
        assert repair.status(str(bound["proposal_token"]))["status"] == "verified"
    finally:
        with_service.close()


def test_rebinding_abandonment_and_invalid_digest_never_write(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b"\xef\xbb\xbf{}")
    app = ApplicationService(
        tmp_path / "cases.db", factory=default_investigator, enable_local_json=True
    )
    try:
        case_id = str(app.start_local_json_case(str(source))["case_id"])
        app.wait(timeout=20)
        repair = NativeJsonRepairSession(app.database)
        assert app._selected_file is not None
        offer = repair.prepare(case_id, app._selected_file[1])
        destination = tmp_path / "copy.json"
        bound = repair.bind(str(offer["offer_token"]), str(destination))
        with pytest.raises(JsonRepairError):
            repair.bind(str(offer["offer_token"]), str(tmp_path / "different.json"))
        with pytest.raises(JsonRepairError):
            repair.execute(str(bound["proposal_token"]), "0" * 64, threading.Event())
        repair.abandon(str(offer["offer_token"]))
        with pytest.raises(JsonRepairError):
            repair.execute(
                str(bound["proposal_token"]), str(bound["proposal_digest"]), threading.Event()
            )
        assert not destination.exists()
    finally:
        app.close()


@pytest.mark.parametrize("contents", [b"{}", b"\xef\xbb\xbf{", b"\xef\xbb\xbf\xff"])
def test_only_exact_bom_with_valid_remainder_is_eligible(tmp_path: Path, contents: bytes) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(contents)
    app = ApplicationService(
        tmp_path / "cases.db", factory=default_investigator, enable_local_json=True
    )
    try:
        case_id = str(app.start_local_json_case(str(source))["case_id"])
        app.wait(timeout=20)
        with pytest.raises(JsonRepairError):
            NativeJsonRepairSession(app.database).prepare(
                case_id, capture_selected_file(str(source))
            )
    finally:
        app.close()


@pytest.mark.parametrize("interrupted", [False, True])
def test_uncertain_execution_is_never_retried_after_failure_or_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupted: bool
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b"\xef\xbb\xbf{}")
    app = ApplicationService(
        tmp_path / "cases.db", factory=default_investigator, enable_local_json=True
    )
    calls: list[int] = []

    def fail(*_args: object) -> bytes:
        calls.append(1)
        if interrupted:
            raise KeyboardInterrupt("simulated owner loss after durable claim")
        raise NativeFileCaptureError("timeout")

    try:
        case_id = str(app.start_local_json_case(str(source))["case_id"])
        app.wait(timeout=20)
        assert app._selected_file is not None
        repair = NativeJsonRepairSession(app.database)
        offer = repair.prepare(case_id, app._selected_file[1])
        bound = repair.bind(str(offer["offer_token"]), str(tmp_path / "copy.json"))
        token, digest = str(bound["proposal_token"]), str(bound["proposal_digest"])
        monkeypatch.setattr(native_json_repair, "exchange_native_helper", fail)
        if interrupted:
            with pytest.raises(KeyboardInterrupt):
                repair.execute(token, digest, threading.Event())
            assert repair.status(token)["status"] == "pending"
            restarted = NativeJsonRepairSession(app.database)
            restarted.recover_interrupted()
            with pytest.raises(JsonRepairError):
                restarted.execute(token, digest, threading.Event())
        else:
            assert repair.execute(token, digest, threading.Event())["status"] == "uncertain"
        assert repair.execute(token, digest, threading.Event())["status"] == "uncertain"
        assert calls == [1]
    finally:
        app.close()


def test_private_pipe_is_exact_and_requires_enabled_executor(tmp_path: Path) -> None:
    import importlib.util
    from uuid import uuid4

    spec = importlib.util.spec_from_file_location(
        "repair_launcher", Path(__file__).parents[2] / "desktop/backend/launcher.py"
    )
    assert spec and spec.loader
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    source = tmp_path / "source.json"
    source.write_bytes(b"\xef\xbb\xbf{}")
    app = ApplicationService(
        tmp_path / "cases.db",
        factory=default_investigator,
        enable_local_json=True,
        enable_json_copy=True,
    )

    def call(kind: str, **fields: str) -> dict[str, object]:
        return launcher.handle_native_command(
            app, {"type": kind, "request_id": str(uuid4()), **fields}
        )

    try:
        case_id = str(app.start_local_json_case(str(source))["case_id"])
        app.wait(timeout=20)
        copy_view = cast("dict[str, Any]", app.get_case(case_id)["json_copy"])
        assert copy_view["available"] is True
        assert (
            call("json_repair_prepare", case_id=case_id, selected_path=str(source))["error_code"]
            == "invalid_request"
        )
        prepared = call("json_repair_prepare", case_id=case_id)
        bound = call(
            "json_repair_bind_destination",
            offer_token=str(prepared["offer_token"]),
            destination_path=str(tmp_path / "out.json"),
        )
        token = str(bound["proposal_token"])
        assert (
            call("json_repair_execute", proposal_token=token, proposal_digest="入力")["error_code"]
            == "invalid_request"
        )
        result = call(
            "json_repair_execute",
            proposal_token=token,
            proposal_digest=str(bound["proposal_digest"]),
        )
        assert result["status"] == "verified"
        copy_view = cast("dict[str, Any]", app.get_case(case_id)["json_copy"])
        assert copy_view["receipts"][0]["evidence_ids"] == result["evidence_ids"]
        app._enable_json_copy = False
        assert call("json_repair_prepare", case_id=case_id)["error_code"] == "unavailable"
    finally:
        app.close()


def test_concurrent_execution_can_only_launch_one_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b"\xef\xbb\xbf{}")
    app = ApplicationService(
        tmp_path / "cases.db", factory=default_investigator, enable_local_json=True
    )
    entered, release = threading.Event(), threading.Event()
    exchange = native_json_repair.exchange_native_helper
    calls: list[int] = []

    def controlled(worker: str, request: bytes, cancellation: threading.Event) -> bytes:
        calls.append(1)
        entered.set()
        assert release.wait(5)
        return exchange(worker, request, cancellation)

    try:
        case_id = str(app.start_local_json_case(str(source))["case_id"])
        app.wait(timeout=20)
        assert app._selected_file is not None
        repair = NativeJsonRepairSession(app.database)
        offer = repair.prepare(case_id, app._selected_file[1])
        destination = tmp_path / "new.json"
        bound = repair.bind(str(offer["offer_token"]), str(destination))
        token, digest = str(bound["proposal_token"]), str(bound["proposal_digest"])
        monkeypatch.setattr(native_json_repair, "exchange_native_helper", controlled)
        with ThreadPoolExecutor(max_workers=1) as executor:
            first = executor.submit(repair.execute, token, digest, threading.Event())
            try:
                assert entered.wait(5)
                assert repair.execute(token, digest, threading.Event())["status"] == "pending"
                assert not destination.exists()
            finally:
                release.set()
            assert first.result(timeout=10)["status"] == "verified"
        assert calls == [1]
        assert destination.read_bytes() == b"{}"
    finally:
        release.set()
        app.close()


def test_expired_capture_and_fresh_recapture_cannot_reuse_case_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(b"\xef\xbb\xbf{}")
    app = ApplicationService(
        tmp_path / "cases.db", factory=default_investigator, enable_local_json=True
    )
    try:
        case_id = str(app.start_local_json_case(str(source))["case_id"])
        app.wait(timeout=20)
        assert app._selected_file is not None
        capture = app._selected_file[1]
        repair = NativeJsonRepairSession(app.database)
        with pytest.raises(JsonRepairError, match="ineligible"):
            repair.prepare(case_id, capture_selected_file(str(source)))
        offer = repair.prepare(case_id, capture)
        later = capture.observation.collection_completed_at + timedelta(minutes=6)
        monkeypatch.setattr(native_json_repair, "utc_now", lambda: later)
        with pytest.raises(JsonRepairError, match="expired"):
            repair.prepare(case_id, capture)
        with pytest.raises(JsonRepairError, match="expired"):
            repair.bind(str(offer["offer_token"]), str(tmp_path / "out.json"))
        assert not (tmp_path / "out.json").exists()
    finally:
        app.close()
