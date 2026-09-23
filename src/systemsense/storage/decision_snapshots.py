"""Private, exact next-probe decision inputs for review and replay.

The captured request already passed through the bounded/redacted model-facing
contracts. A snapshot is not a label, a probe outcome, or safe public export.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from systemsense.decision.contracts import DecisionRequest
from systemsense.decision.laya import LayaDecisionProvider, eligible_laya_candidates
from systemsense.domain.probes import ProbeManifest
from systemsense.domain.time import utc_now
from systemsense.storage.sqlite_store import SQLiteStore

_SERIALIZER_VERSION = "decision-request-json-v1"
_LAYA_PROJECTION_VERSION = "laya-preworker-v1"
_CAPTURE_BUSY_TIMEOUT_MS = 25


@dataclass(frozen=True, slots=True)
class ProbeManifestRef:
    probe_id: str
    manifest_version: int | None
    implementation_id: str | None
    catalog_sha256: str | None

    @classmethod
    def from_manifest(cls, probe_id: str, manifest: ProbeManifest | None) -> ProbeManifestRef:
        if manifest is None:
            return cls(probe_id, None, None, None)
        if manifest.probe_id != probe_id:
            raise ValueError("manifest probe ID does not match decision candidate")
        canonical = json.dumps(
            manifest.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return cls(
            probe_id=probe_id,
            manifest_version=manifest.version,
            implementation_id=manifest.implementation_id,
            catalog_sha256=hashlib.sha256(canonical).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class DecisionSnapshot:
    snapshot_id: str
    case_id: str
    state_version: int
    correlation_id: str
    captured_at: datetime
    request: DecisionRequest
    request_sha256: str
    candidate_probe_ids: tuple[str, ...]
    probe_manifest_refs: tuple[ProbeManifestRef, ...]
    laya_state: dict[str, object]
    laya_evidence: tuple[dict[str, str], ...]
    laya_candidates: tuple[dict[str, str], ...]
    laya_projection_sha256: str
    schema_version: int = 1
    serializer_version: str = _SERIALIZER_VERSION
    laya_projection_version: str = _LAYA_PROJECTION_VERSION


def decision_request_json(request: DecisionRequest) -> str:
    """Canonical typed request, preserving meaningful candidate/evidence order."""

    payload = request.model_dump(mode="json")
    # Pydantic renders frozensets as arrays; normalize only those unordered fields.
    # Candidate and evidence arrays remain in the exact order passed to the provider.
    for field in ("target_traits", "fresh_probe_ids", "completed_probe_ids"):
        payload[field] = sorted(payload[field])
    for probe in payload["available_probes"]:
        probe["keywords"] = sorted(probe["keywords"])
        probe["target_traits"] = sorted(probe["target_traits"])
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def decision_request_sha256(request: DecisionRequest) -> str:
    """Digest of the full request, not the smaller replay visible-evidence hash."""

    return hashlib.sha256(decision_request_json(request).encode("utf-8")).hexdigest()


def _projection_json(
    state: dict[str, object],
    evidence: tuple[dict[str, str], ...],
    candidates: tuple[dict[str, str], ...],
) -> str:
    return json.dumps(
        {"state": state, "evidence": evidence, "candidates": candidates},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


class DecisionSnapshotRepository:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def capture(
        self,
        request: DecisionRequest,
        *,
        probe_manifest_refs: tuple[ProbeManifestRef, ...],
    ) -> DecisionSnapshot:
        if request.attention_only:
            raise ValueError("attention-only requests are not next-probe snapshots")
        candidate_ids = tuple(probe.probe_id for probe in request.available_probes)
        if tuple(ref.probe_id for ref in probe_manifest_refs) != candidate_ids:
            raise ValueError("manifest references must match ordered decision candidates")
        request_json = decision_request_json(request)
        digest = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        laya_state = LayaDecisionProvider.state_for_laya(request)
        laya_evidence = LayaDecisionProvider.evidence_fragments_for_laya(request)
        laya_candidates = tuple(
            {"probe_id": capability.probe_id, "description": capability.description}
            for capability in eligible_laya_candidates(request)
        )
        projection_digest = hashlib.sha256(
            _projection_json(laya_state, laya_evidence, laya_candidates).encode("utf-8")
        ).hexdigest()
        snapshot = DecisionSnapshot(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            case_id=str(request.case_id),
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            captured_at=utc_now(),
            request=request,
            request_sha256=digest,
            candidate_probe_ids=candidate_ids,
            probe_manifest_refs=probe_manifest_refs,
            laya_state=laya_state,
            laya_evidence=laya_evidence,
            laya_candidates=laya_candidates,
            laya_projection_sha256=projection_digest,
        )
        connection = self.store.connection
        timeout_row = connection.execute("PRAGMA busy_timeout").fetchone()
        if timeout_row is None:
            raise RuntimeError("SQLite busy timeout is unavailable")
        prior_busy_timeout_ms = int(timeout_row[0])
        connection.execute(f"PRAGMA busy_timeout = {_CAPTURE_BUSY_TIMEOUT_MS}")
        try:
            with self.store.transaction():
                connection.execute(
                    """INSERT INTO decision_snapshots (
                       snapshot_id, case_id, schema_version, serializer_version,
                       state_version, correlation_id, captured_at, request_json,
                       request_sha256, candidate_probe_ids_json, probe_manifest_refs_json,
                       laya_projection_version, laya_state_json, laya_evidence_json,
                       laya_candidates_json, laya_projection_sha256
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        snapshot.snapshot_id,
                        snapshot.case_id,
                        snapshot.schema_version,
                        snapshot.serializer_version,
                        snapshot.state_version,
                        snapshot.correlation_id,
                        snapshot.captured_at.isoformat(),
                        request_json,
                        digest,
                        json.dumps(candidate_ids, separators=(",", ":")),
                        json.dumps(
                            [
                                {
                                    "probe_id": ref.probe_id,
                                    "manifest_version": ref.manifest_version,
                                    "implementation_id": ref.implementation_id,
                                    "catalog_sha256": ref.catalog_sha256,
                                }
                                for ref in probe_manifest_refs
                            ],
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        _LAYA_PROJECTION_VERSION,
                        json.dumps(
                            laya_state, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                        ),
                        json.dumps(laya_evidence, separators=(",", ":"), ensure_ascii=False),
                        json.dumps(laya_candidates, separators=(",", ":"), ensure_ascii=False),
                        projection_digest,
                    ),
                )
        finally:
            connection.execute(f"PRAGMA busy_timeout = {prior_busy_timeout_ms}")
        return snapshot

    def snapshots(self, *, case_id: str, limit: int = 100) -> tuple[DecisionSnapshot, ...]:
        """Internal case-scoped replay access; no transport/export integration."""

        if not 1 <= limit <= 500:
            raise ValueError("snapshot limit must be between 1 and 500")
        rows = self.store.connection.execute(
            """SELECT snapshot_id, case_id, schema_version, serializer_version,
                      state_version, correlation_id, captured_at, request_json,
                      request_sha256, candidate_probe_ids_json, probe_manifest_refs_json,
                      laya_projection_version, laya_state_json, laya_evidence_json,
                      laya_candidates_json, laya_projection_sha256
               FROM decision_snapshots WHERE case_id = ?
               ORDER BY captured_at, snapshot_id LIMIT ?""",
            (case_id, limit),
        ).fetchall()
        snapshots: list[DecisionSnapshot] = []
        for row in rows:
            if (
                int(row[2]) != 1
                or str(row[3]) != _SERIALIZER_VERSION
                or str(row[11]) != _LAYA_PROJECTION_VERSION
            ):
                raise ValueError("decision snapshot serializer version unsupported")
            request_json = str(row[7])
            request = DecisionRequest.model_validate_json(request_json)
            digest = str(row[8])
            if hashlib.sha256(request_json.encode("utf-8")).hexdigest() != digest:
                raise ValueError("decision snapshot request digest mismatch")
            if (
                str(request.case_id) != str(row[1])
                or request.state_version != int(row[4])
                or request.correlation_id != str(row[5])
            ):
                raise ValueError("decision snapshot request binding mismatch")
            candidates = tuple(json.loads(str(row[9])))
            refs = tuple(ProbeManifestRef(**ref) for ref in json.loads(str(row[10])))
            if candidates != tuple(probe.probe_id for probe in request.available_probes):
                raise ValueError("decision snapshot candidate order mismatch")
            if tuple(ref.probe_id for ref in refs) != candidates:
                raise ValueError("decision snapshot manifest binding mismatch")
            if any(
                ref.catalog_sha256 is not None
                and (
                    len(ref.catalog_sha256) != 64
                    or any(ch not in "0123456789abcdef" for ch in ref.catalog_sha256)
                )
                for ref in refs
            ):
                raise ValueError("decision snapshot manifest digest invalid")
            laya_state = cast(dict[str, object], json.loads(str(row[12])))
            laya_evidence = tuple(cast(list[dict[str, str]], json.loads(str(row[13]))))
            laya_candidates = tuple(cast(list[dict[str, str]], json.loads(str(row[14]))))
            projection_digest = hashlib.sha256(
                _projection_json(laya_state, laya_evidence, laya_candidates).encode("utf-8")
            ).hexdigest()
            if projection_digest != str(row[15]):
                raise ValueError("decision snapshot projection digest mismatch")
            expected_projection = _projection_json(
                LayaDecisionProvider.state_for_laya(request),
                LayaDecisionProvider.evidence_fragments_for_laya(request),
                tuple(
                    {"probe_id": probe.probe_id, "description": probe.description}
                    for probe in eligible_laya_candidates(request)
                ),
            )
            if _projection_json(laya_state, laya_evidence, laya_candidates) != expected_projection:
                raise ValueError("decision snapshot projection does not match frozen request")
            captured_at = datetime.fromisoformat(str(row[6]))
            if captured_at.tzinfo is None or captured_at.utcoffset() != UTC.utcoffset(None):
                raise ValueError("decision snapshot capture time must be UTC")
            snapshots.append(
                DecisionSnapshot(
                    snapshot_id=str(row[0]),
                    case_id=str(row[1]),
                    schema_version=int(row[2]),
                    serializer_version=str(row[3]),
                    state_version=int(row[4]),
                    correlation_id=str(row[5]),
                    captured_at=captured_at,
                    request=request,
                    request_sha256=digest,
                    candidate_probe_ids=candidates,
                    probe_manifest_refs=refs,
                    laya_state=laya_state,
                    laya_evidence=laya_evidence,
                    laya_candidates=laya_candidates,
                    laya_projection_sha256=projection_digest,
                    laya_projection_version=str(row[11]),
                )
            )
        return tuple(snapshots)
