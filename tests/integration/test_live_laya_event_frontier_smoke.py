"""Opt-in pinned-Laya smoke for the mounted schema-30 event-attention turn."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from benchmarks.real_laya_event_latency import (
    _await_gpu_capacity,  # pyright: ignore[reportPrivateUsage]
    _managed_providers,  # pyright: ignore[reportPrivateUsage]
    _percentile,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.investigation_state import InvestigationState, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.decision.contracts import EvidenceContext
from systemsense.domain.ids import EvidenceId
from systemsense.domain.time import utc_now
from systemsense.inference.host_telemetry import read_host_telemetry
from systemsense.inference.profile import load_inference_profile
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_catalog_attention_loop import (
    _fill_case,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_event_frontier_loop import (
    _omit_until_selected,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator


def _emit_report(report: dict[str, object]) -> None:
    encoded = json.dumps(report, sort_keys=True, allow_nan=False)
    report_path = os.environ.get("SYSTEMSENSE_LIVE_LAYA_EVENT_REPORT")
    if report_path is not None:
        destination = Path(report_path)
        if not destination.is_absolute():
            raise ValueError("live Laya event report path must be absolute")
        with destination.open("x", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
    print(encoded)


def _base_revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        check=True,
        shell=False,
        timeout=3,
    )
    return result.stdout.strip()


def _capture_focused_turn(
    app: Investigator, target: EvidenceId, marks: dict[str, int]
) -> Callable[
    [InvestigationState, tuple[EvidenceContext, ...], int],
    tuple[InvestigationState, tuple[EvidenceContext, ...], bool],
]:
    original_turn = app._event_frontier_turn  # pyright: ignore[reportPrivateUsage]

    def timed_turn(
        current: InvestigationState,
        focused: tuple[EvidenceContext, ...],
        owner_started_version: int,
    ) -> tuple[InvestigationState, tuple[EvidenceContext, ...], bool]:
        result = original_turn(current, focused, owner_started_version)
        if "turn_completed_ns" not in marks and any(
            str(item) == str(target) for item in result[0].fast_catalog_selected_ids
        ):
            marks["turn_completed_ns"] = time.perf_counter_ns()
        return result

    return timed_turn


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_LAYA_EVENT_FRONTIER") != "1",
    reason="explicit opt-in managed CUDA Laya schema-30 event smoke",
)
def test_real_laya_mounted_event_turn_delivers_stored_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_path = os.environ.get("SYSTEMSENSE_LIVE_LAYA_PROFILE")
    if profile_path is None:
        pytest.skip("explicit SYSTEMSENSE_LIVE_LAYA_PROFILE is required")
    profile = load_inference_profile(Path(profile_path))
    initial_gate, _initial_wait_ms = _await_gpu_capacity(
        profile.laya.cuda_device_index, allow_ambient_gpu=True
    )
    if initial_gate is not None:
        pytest.skip(f"GPU resource gate blocked before prewarm: {initial_gate}")
    providers, _admission = _managed_providers(profile)
    try:
        prewarm_started = time.perf_counter_ns()
        providers.prewarm_laya(timeout_seconds=90)
        prewarm_ms = (time.perf_counter_ns() - prewarm_started) / 1_000_000
        assert providers.frontier_ranker is not None
        with SQLiteStore(tmp_path / "real-laya-event-turn.db") as store:
            base = investigator(store)
            app = Investigator(
                store=store,
                runtime=base.runtime,
                capabilities=base.capabilities,
                decision=base.decision,
                reasoning=base.reasoning,
                knowledge=providers.knowledge,
                frontier_ranker=providers.frontier_ranker,
            )
            state = app.create(objective="Investigate a recent disk observation", budget_ms=20_000)
            target = _fill_case(store, str(state.case_id), count=1, target_index=1)
            generation = store.connection.execute(
                "SELECT generation FROM evidence_case_generations WHERE case_id=?",
                (str(state.case_id),),
            ).fetchone()
            assert generation is not None
            frontier = SearchFrontierRepository(store)
            with store.transaction():
                event = frontier.append_result_event(
                    state.case_id,
                    source_evidence_id=target,
                    source_execution_id=None,
                    versions=RelevantVersionsV1(objective=1, evidence=int(generation[0])),
                )
            persisted_ns = time.perf_counter_ns()
            assert isinstance(event, FrontierEventV1)
            state = app._save(  # pyright: ignore[reportPrivateUsage]
                state.model_copy(update={"status": InvestigationStatus.RUNNING}),
                "started",
                "Read-only synthetic event turn started.",
            )
            before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
            assert str(target) not in {str(item.evidence_id) for item in before}
            turn_started_ns = time.perf_counter_ns()

            updated, after, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
                state, before, state.state_version
            )
            committed_ns = time.perf_counter_ns()

            turns = frontier.investigator_turns(state.case_id, event.event_id)
            assert handled and len(turns) == 1
            outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
            assert outcome is not None and outcome.outcome == "focused_delivery"
            assert outcome.resulting_checkpoint_version == updated.state_version
            assert str(target) in {str(item.evidence_id) for item in after}
            assert len(outcome.frontier_item_ids) == 1
            assert (
                frontier.readback(outcome.frontier_item_ids[0]).status is FrontierStatus.SATISFIED
            )
            assert any(
                call.detail == "event_frontier_retrieval" and not call.degraded
                for call in updated.provider_calls
            )
            assert (
                store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0
            )
            print(
                json.dumps(
                    {
                        "kind": "real_laya_schema30_stored_retrieval_smoke",
                        "prewarm_ms": prewarm_ms,
                        "persisted_event_to_checkpoint_ms": (committed_ns - persisted_ns)
                        / 1_000_000,
                        "turn_entry_to_checkpoint_ms": (committed_ns - turn_started_ns) / 1_000_000,
                        "diagnostic_utility_claim": False,
                        "measurement_admission_claim": False,
                        "completed_at": utc_now().isoformat(),
                    },
                    sort_keys=True,
                )
            )
    finally:
        providers.close()


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_LAYA_EVENT_FRONTIER") != "1",
    reason="explicit opt-in managed CUDA Laya schema-30 event smoke",
)
def test_real_laya_event_turn_runs_inside_ordinary_investigation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile_path = os.environ.get("SYSTEMSENSE_LIVE_LAYA_PROFILE")
    if profile_path is None:
        pytest.skip("explicit SYSTEMSENSE_LIVE_LAYA_PROFILE is required")
    profile = load_inference_profile(Path(profile_path))
    initial_gate, initial_resource_wait_ms = _await_gpu_capacity(
        profile.laya.cuda_device_index, allow_ambient_gpu=True
    )
    if initial_gate is not None:
        _emit_report(
            {
                "kind": "real_laya_schema30_ordinary_run_serial_v1",
                "attempts_requested": 8,
                "focused_deliveries": 0,
                "misses": 8,
                "all_attempt_p95_ms": None,
                "status": "blocked_before_prewarm",
                "gpu_gate_reason": initial_gate,
                "initial_resource_wait_ms": initial_resource_wait_ms,
                "gpu_isolation": "unverified_ambient",
                "engineering_target_admissible": False,
                "diagnostic_utility_claim": False,
                "measurement_admission_claim": False,
            }
        )
        pytest.skip(f"GPU resource gate blocked before prewarm: {initial_gate}")
    providers, admission = _managed_providers(profile)
    try:
        prewarm_started = time.perf_counter_ns()
        providers.prewarm_laya(timeout_seconds=90)
        prewarm_ms = (time.perf_counter_ns() - prewarm_started) / 1_000_000
        assert providers.frontier_ranker is not None
        details: list[dict[str, object]] = []
        failures: list[str] = []
        for index in range(8):
            gate_reason, resource_wait_ms = _await_gpu_capacity(
                profile.laya.cuda_device_index,
                owned_laya_pid=admission.status.worker_pid,
                allow_ambient_gpu=True,
            )
            if gate_reason is not None:
                details.append(
                    {
                        "trial": index + 1,
                        "outcome": "resource_miss",
                        "gate_reason": gate_reason,
                        "resource_wait_ms": resource_wait_ms,
                    }
                )
                continue
            with SQLiteStore(tmp_path / f"real-laya-ordinary-{index}.db") as store:
                base = investigator(store)
                app = Investigator(
                    store=store,
                    runtime=base.runtime,
                    capabilities=base.capabilities,
                    decision=base.decision,
                    reasoning=base.reasoning,
                    knowledge=providers.knowledge,
                    frontier_ranker=providers.frontier_ranker,
                )
                state = app.create(
                    objective="Investigate a recent disk observation",
                    budget_ms=120_000,
                    max_rounds=1,
                )
                target = _fill_case(store, str(state.case_id), count=1, target_index=1)
                generation = store.connection.execute(
                    "SELECT generation FROM evidence_case_generations WHERE case_id=?",
                    (str(state.case_id),),
                ).fetchone()
                assert generation is not None
                frontier = SearchFrontierRepository(store)
                with store.transaction():
                    event = frontier.append_result_event(
                        state.case_id,
                        source_evidence_id=target,
                        source_execution_id=None,
                        versions=RelevantVersionsV1(objective=1, evidence=int(generation[0])),
                    )
                assert isinstance(event, FrontierEventV1)
                persisted_ns = time.perf_counter_ns()
                _omit_until_selected(app, str(state.case_id), target, monkeypatch)
                marks: dict[str, int] = {}
                monkeypatch.setattr(
                    app, "_event_frontier_turn", _capture_focused_turn(app, target, marks)
                )
                try:
                    finished = app.run(str(state.case_id))
                    turns = frontier.investigator_turns(state.case_id, event.event_id)
                    assert len(turns) == 1
                    outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
                    assert outcome is not None and outcome.outcome == "focused_delivery"
                    assert outcome.resulting_checkpoint_version is not None
                    assert frontier.read_investigator_turn_closure(event.event_id) is not None
                    assert any(
                        call.detail == "event_frontier_retrieval" and not call.degraded
                        for call in finished.provider_calls
                    )
                    assert "turn_completed_ns" in marks
                    details.append(
                        {
                            "trial": index + 1,
                            "outcome": "focused_delivery",
                            "event_persisted_to_outcome_ms": (
                                marks["turn_completed_ns"] - persisted_ns
                            )
                            / 1_000_000,
                            "event_id": event.event_id,
                            "turn_id": turns[0].turn_id,
                            "event_persisted_at_utc": event.persisted_at.isoformat(),
                            "outcome_completed_at_utc": outcome.completed_at.isoformat(),
                            "resource_wait_ms": resource_wait_ms,
                        }
                    )
                except (AssertionError, RuntimeError, ValueError) as error:
                    failures.append(f"trial {index + 1}: {type(error).__name__}")
                    details.append(
                        {
                            "trial": index + 1,
                            "outcome": "harness_failure",
                            "error": type(error).__name__,
                            "resource_wait_ms": resource_wait_ms,
                        }
                    )
        timings = [
            value
            for item in details
            if isinstance(value := item.get("event_persisted_to_outcome_ms"), float)
        ]
        host = read_host_telemetry(gpu_device_index=profile.laya.cuda_device_index)
        _emit_report(
            {
                "kind": "real_laya_schema30_ordinary_run_serial_v1",
                "status": "failed" if failures else "complete" if len(timings) == 8 else "partial",
                "attempts_requested": 8,
                "focused_deliveries": len(timings),
                "misses": 8 - len(timings),
                "all_attempt_p95_ms": _percentile(timings, 0.95) if len(timings) == 8 else None,
                "focused_only_p95_ms": _percentile(timings, 0.95),
                "prewarm_ms": prewarm_ms,
                "initial_resource_wait_ms": initial_resource_wait_ms,
                "gpu_isolation": "unverified_ambient",
                "gpu_device_index": host.gpu_device_index,
                "gpu_uuid": host.gpu_uuid,
                "host_sample_started_at_utc": host.source_window_started_at.isoformat(),
                "timing_clock": "time.perf_counter_ns",
                "model_weight_sha256": profile.laya.runtime_config()
                .validate_install()
                .weight_sha256,
                "profile_sha256": hashlib.sha256(Path(profile_path).read_bytes()).hexdigest(),
                "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                "base_revision": _base_revision(),
                "provider": providers.frontier_ranker.provider.model_dump(mode="json"),
                "engineering_target_admissible": False,
                "diagnostic_utility_claim": False,
                "measurement_admission_claim": False,
                "details": details,
            }
        )
        assert not failures
        assert timings
    finally:
        providers.close()
