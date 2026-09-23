from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.decision.contracts import (
    DecisionPresentationTrace,
    DecisionRequest,
    ProbeCapability,
    ProviderIdentity,
    presentation_payload_sha256,
)
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaCachedOrigin,
    LayaQuestionPresentation,
    LayaWorkerPresentation,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.decision_snapshots import DecisionSnapshotRepository, ProbeManifestRef
from systemsense.storage.sqlite_store import SQLiteStore


def _request(*, evidence_pages: int = 0) -> DecisionRequest:
    now = datetime.now(UTC)
    ids = tuple(EvidenceId.new() for _ in range(evidence_pages))
    return DecisionRequest(
        case_id=CaseId.new(),
        state_version=0,
        correlation_id="trace_test",
        deadline_at=now + timedelta(minutes=1),
        symptom="private case text must not enter hash-only trace",
        evidence_ids=ids,
        evidence_context=tuple(
            EvidenceContext(
                evidence_id=item,
                probe_id="core.system",
                observed_at=now,
                captured_at=now,
                summary="private observation text must not enter hash-only trace",
                facts={},
                status=EvidenceContextStatus.OBSERVED,
            )
            for item in ids
        ),
        available_probes=(
            ProbeCapability(
                probe_id="core.system",
                description="read-only system snapshot",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=1000,
        max_probes=1,
    )


def _worker(item_id: str) -> LayaWorkerPresentation:
    return LayaWorkerPresentation(
        presentation_sha256="a" * 64,
        fitted_state_sha256="b" * 64,
        questions_sha256="c" * 64,
        presented_item_ids=(item_id,),
        fitted_state_tokens=12,
        state_tokens_original=14,
        state_fields_omitted=1,
        state_list_items_omitted=0,
        questions=(
            LayaQuestionPresentation(
                question_id="item_0_piece_0",
                item_id=item_id,
                question_sha256="d" * 64,
                instruction_tokens=20,
                instruction_presented_tokens=18,
                criteria_tokens=8,
                criteria_presented_tokens=8,
                state_presented_tokens=12,
            ),
        ),
    )


def _trace(batches: tuple[LayaAttentionMicrobatch, ...]) -> DecisionPresentationTrace:
    payload: dict[str, JsonValue] = {
        "microbatches": [item.model_dump(mode="json") for item in batches]
    }
    return DecisionPresentationTrace(
        provider=ProviderIdentity(
            provider_id="laya-local-decision", provider_version="1", role="fast_decision"
        ),
        format_id="laya-worker-attention-v1",
        payload=payload,
        payload_sha256=presentation_payload_sha256(payload),
    )


def _capture(
    store: SQLiteStore,
    request: DecisionRequest,
    trace: DecisionPresentationTrace,
) -> str:
    store.create_case(
        case_id=str(request.case_id),
        kind="general",
        symptom=request.symptom,
        created_at=datetime.now(UTC).isoformat(),
    )
    snapshot = DecisionSnapshotRepository(store).capture(
        request,
        probe_manifest_refs=(ProbeManifestRef.from_manifest("core.system", None),),
        request_frozen_at=datetime.now(UTC) - timedelta(seconds=2),
        presentation_trace=trace,
    )
    return snapshot.snapshot_id


def test_hash_only_trace_roundtrip_separates_probe_and_evidence_coverage(tmp_path: Path) -> None:
    request = _request(evidence_pages=2)
    first = str(request.evidence_ids[0])
    fragment = f"{first}:0:preview:0"
    trace = _trace(
        (
            LayaAttentionMicrobatch(
                phase="evidence",
                batch_index=0,
                candidate_ids=(fragment,),
                inference_ids=(fragment,),
                worker_presentation=_worker(fragment),
            ),
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("core.system",),
                cache_hit_ids=("core.system",),
                cached_origins=(
                    LayaCachedOrigin(item_id="core.system", presentation_sha256="e" * 64),
                ),
            ),
        )
    )
    with SQLiteStore(tmp_path / "trace.db") as store:
        snapshot_id = _capture(store, request, trace)
        row = store.connection.execute(
            "SELECT trace_json FROM decision_presentation_traces WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        assert row is not None
        assert "private case text" not in row[0]
        assert "private observation text" not in row[0]
        assert "a" * 64 in row[0]  # exact worker-reported presentation digest
        snapshot = DecisionSnapshotRepository(store).snapshots(case_id=str(request.case_id))[0]
        assert snapshot.request_frozen_at is not None
        assert snapshot.request_frozen_at <= snapshot.captured_at
        readback = snapshot.presentation_trace
        assert readback is not None
        assert readback.trace == trace
        assert readback.probe_candidates_complete is True
        assert readback.evidence_pages_complete is False
        assert readback.worker_presentations_complete is True
        assert readback.cache_origins_complete is True
        assert readback.worker_inference_present is True
        assert readback.cache_only is False
        assert readback.training_admissible is False


def test_trace_readback_rejects_tampering_and_future_freeze_time(tmp_path: Path) -> None:
    request = _request()
    trace = _trace(
        (
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("core.system",),
                inference_ids=("core.system",),
                worker_presentation=_worker("core.system"),
            ),
        )
    )
    with SQLiteStore(tmp_path / "tamper.db") as store:
        snapshot_id = _capture(store, request, trace)
        repository = DecisionSnapshotRepository(store)
        assert repository.snapshots(case_id=str(request.case_id))[0].presentation_trace
        store.connection.execute("DROP TRIGGER decision_presentation_traces_no_update")
        store.connection.execute(
            "UPDATE decision_presentation_traces SET trace_json = '{}' WHERE snapshot_id = ?",
            (snapshot_id,),
        )
        with pytest.raises(ValueError, match="trace digest mismatch"):
            repository.snapshots(case_id=str(request.case_id))
        store.connection.execute("DROP TRIGGER decision_snapshots_no_update")
        store.connection.execute(
            "UPDATE decision_snapshots SET request_frozen_at = ? WHERE snapshot_id = ?",
            ((datetime.now(UTC) + timedelta(days=1)).isoformat(), snapshot_id),
        )
        with pytest.raises(ValueError, match="freeze chronology"):
            repository.snapshots(case_id=str(request.case_id))


def test_cache_origin_only_trace_is_not_training_admissible(tmp_path: Path) -> None:
    request = _request()
    trace = _trace(
        (
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("core.system",),
                cache_hit_ids=("core.system",),
                cached_origins=(
                    LayaCachedOrigin(item_id="core.system", presentation_sha256="e" * 64),
                ),
            ),
        )
    )
    with SQLiteStore(tmp_path / "cache-only.db") as store:
        _capture(store, request, trace)
        readback = (
            DecisionSnapshotRepository(store)
            .snapshots(case_id=str(request.case_id))[0]
            .presentation_trace
        )
        assert readback is not None
        assert readback.probe_candidates_complete is True
        assert readback.evidence_pages_complete is True
        assert readback.worker_inference_present is False
        assert readback.cache_only is True
        assert readback.training_admissible is False
        store.connection.execute("DELETE FROM cases WHERE case_id = ?", (str(request.case_id),))
        assert store.connection.execute(
            "SELECT COUNT(*) FROM decision_presentation_traces"
        ).fetchone() == (0,)


def test_trace_rejects_unknown_candidate_even_with_recomputed_digest(tmp_path: Path) -> None:
    request = _request()
    trace = _trace(
        (
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("unregistered.executable",),
                inference_ids=("unregistered.executable",),
                worker_presentation=_worker("unregistered.executable"),
            ),
        )
    )
    with SQLiteStore(tmp_path / "binding.db") as store:
        store.create_case(
            case_id=str(request.case_id),
            kind="general",
            symptom=request.symptom,
            created_at=datetime.now(UTC).isoformat(),
        )
        with pytest.raises(ValueError, match="probe binding mismatch"):
            DecisionSnapshotRepository(store).capture(
                request,
                probe_manifest_refs=(ProbeManifestRef.from_manifest("core.system", None),),
                presentation_trace=trace,
            )
        assert store.connection.execute("SELECT COUNT(*) FROM decision_snapshots").fetchone() == (
            0,
        )
