"""Private, exact next-probe decision inputs for review and replay.

The captured request already passed through the bounded/redacted model-facing
contracts. A snapshot is not a label, a probe outcome, or safe public export.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from systemsense.decision.contracts import DecisionPresentationTrace, DecisionRequest
from systemsense.decision.laya import LayaDecisionProvider, eligible_laya_candidates
from systemsense.domain.probes import ProbeManifest
from systemsense.domain.time import utc_now
from systemsense.inference.laya_runtime import LayaAttentionMicrobatch
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
    request_frozen_at: datetime | None = None
    presentation_trace: DecisionTraceReadback | None = None
    schema_version: int = 1
    serializer_version: str = _SERIALIZER_VERSION
    laya_projection_version: str = _LAYA_PROJECTION_VERSION


@dataclass(frozen=True, slots=True)
class DecisionExecutionLink:
    """Observed post-snapshot run, not the fast provider's selected action or a label."""

    snapshot_id: str
    execution_id: str
    case_id: str
    probe_id: str
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class DecisionTraceReadback:
    """Integrity-checked metadata, never itself a training label or token proof."""

    trace: DecisionPresentationTrace
    trace_sha256: str
    probe_candidates_complete: bool
    evidence_pages_complete: bool
    worker_presentations_complete: bool
    cache_origins_complete: bool
    worker_inference_present: bool
    # Until a pinned Laya implementation parity test confirms the worker's
    # inferred token lengths, digest readback cannot admit training data.
    training_admissible: bool = False

    @property
    def cache_only(self) -> bool:
        return not self.worker_inference_present and self.cache_origins_complete


def _trace_json(trace: DecisionPresentationTrace) -> str:
    return json.dumps(
        trace.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _trace_coverage(
    trace: DecisionPresentationTrace,
    evidence: tuple[dict[str, str], ...],
    candidates: tuple[dict[str, str], ...],
) -> tuple[bool, bool, bool, bool, bool]:
    if trace.format_id != "laya-worker-attention-v1" or trace.provider.provider_id != (
        "laya-local-decision"
    ):
        raise ValueError("decision presentation trace format/provider unsupported")
    payload = trace.payload
    raw = payload.get("microbatches")
    if set(payload) != {"microbatches"} or not isinstance(raw, list) or not raw or len(raw) > 32:
        raise ValueError("decision presentation trace payload invalid")
    try:
        batches = tuple(LayaAttentionMicrobatch.model_validate(item) for item in raw)
    except ValueError as error:
        raise ValueError("decision presentation trace microbatch invalid") from error
    if [item.model_dump(mode="json") for item in batches] != raw:
        raise ValueError("decision presentation trace contains noncanonical fields")
    seen: dict[str, list[str]] = {"evidence": [], "probe": []}
    next_index = {"evidence": 0, "probe": 0}
    for batch in batches:
        if batch.batch_index != next_index[batch.phase]:
            raise ValueError("decision presentation trace batch order invalid")
        next_index[batch.phase] += 1
        seen[batch.phase].extend(batch.candidate_ids)
        presentation = batch.worker_presentation
        if presentation is not None and any(
            not re.fullmatch(r"item_[0-9]+_piece_[0-9]+", item.question_id)
            for item in presentation.questions
        ):
            raise ValueError("decision presentation trace question ID invalid")
    expected_evidence = [item["fragment_id"] for item in evidence]
    expected_probes = [item["probe_id"] for item in candidates]
    if seen["evidence"] != expected_evidence[: len(seen["evidence"])]:
        raise ValueError("decision presentation trace evidence binding mismatch")
    if seen["probe"] != expected_probes[: len(seen["probe"])]:
        raise ValueError("decision presentation trace probe binding mismatch")
    return (
        seen["probe"] == expected_probes,
        seen["evidence"] == expected_evidence,
        all(not batch.inference_ids or batch.worker_presentation is not None for batch in batches),
        all(
            origin.presentation_sha256 is not None
            for batch in batches
            for origin in batch.cached_origins
        ),
        any(batch.inference_ids and batch.worker_presentation is not None for batch in batches),
    )


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
        request_frozen_at: datetime | None = None,
        presentation_trace: DecisionPresentationTrace | None = None,
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
        trace_json: str | None = None
        trace_sha256: str | None = None
        trace_coverage: tuple[bool, bool, bool, bool, bool] | None = None
        if presentation_trace is not None:
            presentation_trace = DecisionPresentationTrace.model_validate(
                presentation_trace.model_dump(mode="json")
            )
            trace_coverage = _trace_coverage(presentation_trace, laya_evidence, laya_candidates)
            trace_json = _trace_json(presentation_trace)
            trace_sha256 = hashlib.sha256(trace_json.encode("utf-8")).hexdigest()
        captured_at = utc_now()
        if request_frozen_at is not None and (
            request_frozen_at.tzinfo is None
            or request_frozen_at.utcoffset() != UTC.utcoffset(None)
            or request_frozen_at > captured_at
        ):
            raise ValueError("request freeze time must be UTC and precede snapshot capture")
        snapshot = DecisionSnapshot(
            snapshot_id=f"decision_snapshot_{uuid4().hex}",
            case_id=str(request.case_id),
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            captured_at=captured_at,
            request=request,
            request_sha256=digest,
            candidate_probe_ids=candidate_ids,
            probe_manifest_refs=probe_manifest_refs,
            laya_state=laya_state,
            laya_evidence=laya_evidence,
            laya_candidates=laya_candidates,
            laya_projection_sha256=projection_digest,
            request_frozen_at=request_frozen_at,
            presentation_trace=(
                DecisionTraceReadback(presentation_trace, trace_sha256, *trace_coverage)
                if presentation_trace is not None
                and trace_sha256 is not None
                and trace_coverage is not None
                else None
            ),
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
                       laya_candidates_json, laya_projection_sha256, request_frozen_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                        request_frozen_at.isoformat() if request_frozen_at is not None else None,
                    ),
                )
                if presentation_trace is not None and trace_json is not None:
                    connection.execute(
                        """INSERT INTO decision_presentation_traces (
                           snapshot_id, schema_version, provider_id, format_id,
                           request_sha256, projection_sha256, trace_json, trace_sha256
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            snapshot.snapshot_id,
                            presentation_trace.schema_version,
                            presentation_trace.provider.provider_id,
                            presentation_trace.format_id,
                            digest,
                            projection_digest,
                            trace_json,
                            trace_sha256,
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
                      laya_candidates_json, laya_projection_sha256, request_frozen_at
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
            request_frozen_at = (
                datetime.fromisoformat(str(row[16])) if row[16] is not None else None
            )
            if request_frozen_at is not None and (
                request_frozen_at.tzinfo is None
                or request_frozen_at.utcoffset() != UTC.utcoffset(None)
                or request_frozen_at > captured_at
            ):
                raise ValueError("decision snapshot freeze chronology is invalid")
            presentation_trace = self._presentation_trace_for_snapshot(
                snapshot_id=str(row[0]),
                request_sha256=digest,
                projection_sha256=projection_digest,
                evidence=laya_evidence,
                candidates=laya_candidates,
            )
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
                    request_frozen_at=request_frozen_at,
                    presentation_trace=presentation_trace,
                )
            )
        return tuple(snapshots)

    def _presentation_trace_for_snapshot(
        self,
        *,
        snapshot_id: str,
        request_sha256: str,
        projection_sha256: str,
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
    ) -> DecisionTraceReadback | None:
        row = self.store.connection.execute(
            """SELECT schema_version, provider_id, format_id, request_sha256,
                      projection_sha256, trace_json, trace_sha256
               FROM decision_presentation_traces WHERE snapshot_id = ?""",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return None
        trace_json = str(row[5])
        trace_sha256 = str(row[6])
        if hashlib.sha256(trace_json.encode("utf-8")).hexdigest() != trace_sha256:
            raise ValueError("decision presentation trace digest mismatch")
        if str(row[3]) != request_sha256 or str(row[4]) != projection_sha256:
            raise ValueError("decision presentation trace snapshot binding mismatch")
        try:
            trace = DecisionPresentationTrace.model_validate_json(trace_json)
        except ValueError as error:
            raise ValueError("decision presentation trace payload invalid") from error
        if (
            int(row[0]) != trace.schema_version
            or str(row[1]) != trace.provider.provider_id
            or str(row[2]) != trace.format_id
            or trace_json != _trace_json(trace)
        ):
            raise ValueError("decision presentation trace envelope mismatch")
        return DecisionTraceReadback(
            trace, trace_sha256, *_trace_coverage(trace, evidence, candidates)
        )

    def execution_links(self, snapshot_id: str) -> tuple[DecisionExecutionLink, ...]:
        """Read factual post-snapshot runs; unlinked candidates remain unknown.

        A deep-brain redirect or deterministic exploration may select a linked
        run. Neither execution nor selection proves that a probe was useful.
        """

        rows = self.store.connection.execute(
            """SELECT link.snapshot_id, link.execution_id, link.case_id, link.probe_id,
                      link.schema_version, snapshot.case_id, snapshot.state_version,
                      snapshot.candidate_probe_ids_json, execution.case_id,
                      execution.probe_id, execution.state_version,
                      snapshot.captured_at, execution.started_at, execution.finished_at
               FROM decision_execution_links AS link
               JOIN decision_snapshots AS snapshot ON snapshot.snapshot_id = link.snapshot_id
               JOIN probe_executions AS execution ON execution.execution_id = link.execution_id
               WHERE link.snapshot_id = ? ORDER BY link.execution_id""",
            (snapshot_id,),
        ).fetchall()
        result: list[DecisionExecutionLink] = []
        for row in rows:
            if (
                int(row[4]) != 1
                or str(row[2]) != str(row[5])
                or str(row[2]) != str(row[8])
                or str(row[3]) != str(row[9])
                or str(row[3]) not in json.loads(str(row[7]))
                or int(row[10]) <= int(row[6])
            ):
                raise ValueError("decision execution link binding mismatch")
            try:
                captured_at, started_at, finished_at = (
                    datetime.fromisoformat(str(row[index])) for index in (11, 12, 13)
                )
            except ValueError as error:
                raise ValueError("decision execution link chronology is invalid") from error
            if (
                any(
                    stamp.tzinfo is None or stamp.utcoffset() != UTC.utcoffset(None)
                    for stamp in (captured_at, started_at, finished_at)
                )
                or not captured_at <= started_at <= finished_at
            ):
                raise ValueError("decision execution link chronology is invalid")
            result.append(
                DecisionExecutionLink(
                    snapshot_id=str(row[0]),
                    execution_id=str(row[1]),
                    case_id=str(row[2]),
                    probe_id=str(row[3]),
                    schema_version=int(row[4]),
                )
            )
        return tuple(result)
