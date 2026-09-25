"""Opt-in actual-model trial over a synthetic four-kind read-only frontier."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from typing import cast

import pytest

from benchmarks.host_diagnostic_trace import HostDiagnosticTrace
from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.cli import _v4_providers  # pyright: ignore[reportPrivateUsage]
from systemsense.decision.contracts import ProbeCapability
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.evidence import EvidenceFact, EvidenceRecord
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import utc_now
from systemsense.evidence.projection import ExplicitRelationProjector
from systemsense.evidence.retrieval import EvidenceRelationRepository
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.inference.profile import load_inference_profile
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import default_probe_definitions
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.synthetic_pilot_oracle import (
    PILOT_SCENARIOS,
    SyntheticScenario,
    selected_action_receipt,
    synthetic_probe_facts,
    write_synthetic_recipe_binding,
)
from tests.integration.test_catalog_attention_loop import (
    _fill_case,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.evidence.test_retrieval import _insert_record  # pyright: ignore[reportPrivateUsage]

_FOUR_KINDS = {"retrieve_evidence", "review_branch", "measure", "consult_deep"}

_CPU_PARITY_CODE = r"""
import contextlib, hashlib, io, json, os, sqlite3, sys
from dataclasses import asdict
from pathlib import Path
os.environ['CUDA_VISIBLE_DEVICES'] = ''
os.environ['HF_HUB_OFFLINE'] = '1'
os.environ['TRANSFORMERS_OFFLINE'] = '1'
sys.path.insert(0, sys.argv[3])
from benchmarks.laya_exact_batch_parity import _local_qualification, reconstruct_exact_worker_call
report = {
    'status': 'fail', 'drafts': 0, 'batches': 0, 'digest_valid': False,
    'coverage_valid': False, 'tensor_parity': False, 'builder_differences': 0,
}
try:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        tokenizer, cfg, qualification = _local_qualification(Path(sys.argv[2]))
        con = sqlite3.connect(Path(sys.argv[1]).as_uri() + '?mode=ro', uri=True)
        rows = con.execute(
            'SELECT d.snapshot_id,d.capture_bytes,d.capture_sha256,s.response_json '
            'FROM frontier_worker_capture_drafts d '
            'JOIN candidate_decision_snapshots s ON s.snapshot_id=d.snapshot_id '
            'ORDER BY d.snapshot_id'
        ).fetchall()
        report['drafts'] = len(rows)
        digests = coverage = tensors = True
        differences = 0
        for snapshot_id, raw, digest, response_json in rows:
            digests &= hashlib.sha256(raw).hexdigest() == digest
            draft = json.loads(raw)
            response = json.loads(response_json)
            trace = response.get('presentation_trace')
            if (
                not isinstance(trace, dict)
                or response.get('ranking_source') != 'laya'
                or response.get('cache_hit')
            ):
                coverage = False
                continue
            captured = {(b['phase'], b['batch_index']): b['call'] for b in draft['batches']}
            expected = {(b['phase'], b['batch_index']): b for b in trace['microbatches']}
            coverage &= draft['snapshot_id'] == snapshot_id and set(captured) == set(expected)
            for key, batch in expected.items():
                proof = batch.get('worker_presentation')
                if proof is None or key not in captured:
                    coverage = False
                    continue
                call = captured[key]
                built, issues, _ = reconstruct_exact_worker_call(
                    call, proof, tokenizer=tokenizer, cfg=cfg,
                    qualification=qualification,
                )
                differences += len(issues)
                predicted = asdict(built)
                for field in ('input_ids', 'attention_mask', 'marker_pos', 'marker_mask', 'qtype'):
                    tensors &= (
                        json.dumps(call['model_input'][field], separators=(',', ':'))
                        == json.dumps(predicted[field], separators=(',', ':'))
                    )
                report['batches'] += 1
        con.close()
        report.update(
            digest_valid=digests, coverage_valid=coverage,
            tensor_parity=tensors, builder_differences=differences,
        )
        report['status'] = (
            'pass'
            if rows and report['batches'] and digests and coverage
            and tensors and not differences
            else 'fail'
        )
except BaseException as error:
    report = {'status': 'error', 'error_type': type(error).__name__, 'trainable': False}
print(json.dumps(report, sort_keys=True))
"""


def _installed_builder_parity(
    *, database: Path, model_path: Path, interpreter: Path
) -> dict[str, object]:
    """Read only fixture drafts in a CPU-only pinned Laya interpreter."""

    env = {
        **os.environ,
        "CUDA_VISIBLE_DEVICES": "",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
    }
    command = (
        str(interpreter),
        "-c",
        _CPU_PARITY_CODE,
        str(database),
        str(model_path),
        str(Path(__file__).resolve().parents[2]),
    )
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=45, check=False, env=env
    )
    try:
        report = json.loads(completed.stdout)
    except ValueError:
        return {"status": "error", "error_type": "invalid_checker_output", "trainable": False}
    if not isinstance(report, dict):
        return {"status": "error", "error_type": "invalid_checker_output", "trainable": False}
    return cast(dict[str, object], report)


def summarize_trace(
    menus: Sequence[Mapping[str, object]],
    calls: Sequence[Mapping[str, object]],
    *,
    deep_provider_id: str,
) -> dict[str, int | bool]:
    """Summarize observed calls only; a synthetic fixture is not a quality score."""

    deep_intervals: list[tuple[datetime, datetime]] = []
    for call in calls:
        if (
            call.get("role") != "reasoning"
            or call.get("provider_id") != deep_provider_id
            or call.get("degraded") is not False
        ):
            continue
        started = datetime.fromisoformat(str(call["started_at"]))
        ended = started + timedelta(milliseconds=float(str(call["elapsed_ms"])))
        deep_intervals.append((started, ended))
    laya_menus = tuple(
        menu
        for menu in menus
        if menu.get("ranking_source") == "laya" and menu.get("cache_hit") is not True
    )
    timed_overlap = any(
        datetime.fromisoformat(str(menu["started_at"])) < deep_end
        and datetime.fromisoformat(str(menu["ended_at"])) > deep_start
        for menu in laya_menus
        for deep_start, deep_end in deep_intervals
    )
    return {
        "four_kind_menus": sum(
            _FOUR_KINDS <= set(cast(list[str], menu["kinds"])) for menu in menus
        ),
        "laya_ranks": len(laya_menus),
        "deep_successes": len(deep_intervals),
        "laya_deep_time_overlap": timed_overlap,
        "deep_active_at_laya_rank": any(
            menu.get("deep_active_before") is True for menu in laya_menus
        ),
    }


def summarize_event_order(
    probe_events: Sequence[Mapping[str, object]],
    menus: Sequence[Mapping[str, object]],
    calls: Sequence[Mapping[str, object]],
    *,
    deep_provider_id: str,
) -> dict[str, bool]:
    """Check temporal causality of the synthetic probe/deep/rerank sequence."""

    def parsed(value: object) -> datetime:
        return datetime.fromisoformat(str(value))

    pressure = tuple(
        event
        for event in probe_events
        if event.get("probe_id") == "pressure.sample" and event.get("status") == "ok"
    )
    core = tuple(
        event
        for event in probe_events
        if event.get("probe_id") == "core.system" and event.get("status") == "ok"
    )
    deep = tuple(
        (
            parsed(call["started_at"]),
            parsed(call["started_at"]) + timedelta(milliseconds=float(str(call["elapsed_ms"]))),
        )
        for call in calls
        if call.get("role") == "reasoning"
        and call.get("provider_id") == deep_provider_id
        and call.get("degraded") is False
    )
    laya = tuple(
        (parsed(menu["started_at"]), parsed(menu["ended_at"]))
        for menu in menus
        if menu.get("ranking_source") == "laya" and menu.get("cache_hit") is not True
    )
    pressure_while_core = any(
        parsed(c["started_at"]) <= parsed(p["started_at"]) < parsed(c["finished_at"])
        for p in pressure
        for c in core
    )
    deep_after_pressure = any(
        parsed(p["finished_at"]) <= deep_start for p in pressure for deep_start, _ in deep
    )
    late_core = any(
        deep_start < parsed(c["finished_at"]) < deep_end
        for c in core
        for deep_start, deep_end in deep
    )
    rerank_after_core = any(
        rank_start >= parsed(c["finished_at"]) for c in core for rank_start, _ in laya
    )
    rerank_overlap = any(
        rank_start >= parsed(c["finished_at"]) and rank_start < deep_end and rank_end > deep_start
        for c in core
        for rank_start, rank_end in laya
        for deep_start, deep_end in deep
    )
    generation_advanced = any(
        int(str(later["evidence_generation"])) > int(str(earlier["evidence_generation"]))
        for c in core
        for earlier in menus
        for later in menus
        if earlier.get("ranking_source") == "laya"
        and later.get("ranking_source") == "laya"
        and earlier.get("evidence_generation") is not None
        and later.get("evidence_generation") is not None
        and parsed(earlier["started_at"]) < parsed(c["finished_at"])
        and parsed(later["started_at"]) >= parsed(c["finished_at"])
    )
    return {
        "pressure_measured_while_core_running": pressure_while_core,
        "deep_started_after_pressure": deep_after_pressure,
        "late_core_arrived_during_deep": late_core,
        "laya_reranked_after_late_core": rerank_after_core,
        "laya_rerank_overlap_deep": rerank_overlap,
        "late_evidence_generation_advanced": generation_advanced,
    }


class RecordingRealRanker(MixedFrontierRanker):
    """Observe the actual adapter output without changing its rank or authority."""

    def __init__(
        self, delegate: MixedFrontierRanker, status: Callable[[], dict[str, object]]
    ) -> None:
        super().__init__(
            ranker=None,
            provider=delegate.provider,
            model_weight_sha256=delegate.model_weight_sha256,
        )
        self.delegate = delegate
        self.status = status
        self.menus: list[dict[str, object]] = []
        self._lock = threading.Lock()

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        status = self.status()
        started = utc_now()
        started_monotonic = time.monotonic()
        response: FrontierRankResponseV1 | None = None
        captured_keys: list[tuple[str, int]] = []

        def observed_capture(
            phase: str,
            index: int,
            call: dict[str, object],
            presentation: LayaWorkerPresentation,
        ) -> None:
            captured_keys.append((phase, index))
            assert capture_worker_batch is not None
            capture_worker_batch(phase, index, call, presentation)

        try:
            response = self.delegate.rank(
                request,
                capture_worker_batch=(
                    observed_capture if capture_worker_batch is not None else None
                ),
            )
            return response
        finally:
            ended = utc_now()
            items = {item.item_id: item.reference.kind for item in request.items}
            record: dict[str, object] = {
                "started_at": started.isoformat(),
                "ended_at": ended.isoformat(),
                "elapsed_ms": round((time.monotonic() - started_monotonic) * 1000, 3),
                "evidence_generation": request.items[0].versions.evidence,
                "kinds": [item.reference.kind for item in request.items],
                "item_ids": [item.item_id for item in request.items],
                "packet_count": len(request.evidence_packets),
                "ranking_source": None if response is None else response.ranking_source,
                "cache_hit": None if response is None else response.cache_hit,
                "selected_kind": (
                    None
                    if response is None or not response.ranked_item_ids
                    else items[response.ranked_item_ids[0]]
                ),
                "coverage_complete": None if response is None else response.coverage_complete,
                "degraded_reason": None if response is None else response.degraded_reason,
                "attention_notes": [] if response is None else list(response.attention_notes),
                "worker_callback_count": len(captured_keys),
                "worker_microbatch_count": (
                    0
                    if response is None or response.presentation_trace is None
                    else len(response.presentation_trace.microbatches)
                ),
                "worker_cache_hit_count": (
                    0
                    if response is None or response.presentation_trace is None
                    else sum(
                        len(batch.cache_hit_ids)
                        for batch in response.presentation_trace.microbatches
                    )
                ),
                "deep_active_before": status.get("deep_active_calls", 0) != 0,
            }
            with self._lock:
                self.menus.append(record)


def _run_controlled_case(
    scenario: SyntheticScenario | None = None, *, require_four_kind_acceptance: bool
) -> dict[str, object]:
    """Run one isolated synthetic case through both real model providers."""

    profile_path = (
        Path(__file__).resolve().parents[2] / "examples" / "warm-local-development.profile.json"
    )
    profile = load_inference_profile(profile_path)
    assert profile.schema_version == 4 and profile.runtime_strategy == "warm-independent"
    assert profile.laya.enabled and profile.managed_reasoning is not None
    assert profile.laya.model_path is not None and profile.laya.interpreter_path is not None
    pressure_percent = 97 if scenario is None else scenario.pressure_percent
    slow_threshold = 90
    recipe: dict[str, str | int] = (
        {
            "fixture": "pressure-v1",
            "pressure_percent": pressure_percent,
            "slow_threshold": slow_threshold,
        }
        if scenario is None
        else {
            "fixture": "controlled-synthetic-pilot-v1",
            "scenario_kind": scenario.kind,
            "pressure_percent": pressure_percent,
            "external_service_status": scenario.external_service_status,
            "slow_threshold": slow_threshold,
        }
    )
    oracle_bad = (
        pressure_percent >= slow_threshold
        if scenario is None
        else scenario.kind != "healthy_control"
    )
    oracle_receipt = hashlib.sha256(
        json.dumps(recipe, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if scenario is None:
        assert oracle_bad

    def observe(_parameters: dict[str, JsonValue], *, name: str) -> ProbeObservation:
        if name == "core.system":
            threading.Event().wait(8.0)
        observed = utc_now()
        return ProbeObservation(
            summary=(
                f"Synthetic {name} pressure fixture"
                if scenario is None
                else f"Synthetic {name} bounded fixture"
            ),
            facts=(
                {"fixture": "pressure-v1", "pressure_percent": pressure_percent}
                if scenario is None
                else synthetic_probe_facts(scenario, name)
            ),
            observed_at=observed,
            captured_at=observed,
        )

    allowed = {"core.system", "core.resources", "pressure.sample"}
    if scenario is not None:
        allowed.add("network.connectivity")
    definitions: tuple[ProbeDefinition, ...] = tuple(
        replace(
            original,
            isolated=False,
            handler=partial(observe, name=original.manifest.probe_id),
        )
        for original in default_probe_definitions()
        if original.manifest.probe_id in allowed
    )
    assert {item.manifest.probe_id for item in definitions} == allowed
    providers = _v4_providers(profile)
    assert providers.frontier_ranker is not None
    recorder = RecordingRealRanker(providers.frontier_ranker, providers.runtime_status)
    assert profile.managed_resources is not None
    host_trace = HostDiagnosticTrace(gpu_device_index=profile.managed_resources.gpu_device_index)
    work_dir = Path(
        tempfile.mkdtemp(
            prefix=(
                "SystemSenseControlledFourKind-"
                if scenario is None
                else f"SystemSenseSyntheticPilot-{scenario.kind}-"
            )
        )
    )
    output_path = work_dir / "controlled-four-kind-result.json"
    started = time.monotonic()
    failure: str | None = None
    report: dict[str, object] = {}
    host_trace.start()
    try:
        with SQLiteStore(work_dir / "controlled-four-kind.db") as store:
            runtime = DiagnosticRuntime(
                store=store,
                case_service=CaseService(store, DeterministicPlanner(candidates=())),
                probe_runner=ProbeRunner(definitions=definitions),
            )
            app = Investigator(
                store=store,
                runtime=runtime,
                capabilities=tuple(
                    ProbeCapability(
                        probe_id=item.manifest.probe_id,
                        description=item.manifest.question,
                        common=item.manifest.probe_id in {"core.system", "core.resources"},
                        cost_ms=1,
                        resource_class=ResourceClass.CPU,
                    )
                    for item in definitions
                    if item.manifest.probe_id
                    in (
                        {"core.system", "core.resources"}
                        if scenario is None
                        else {"core.system", "core.resources", "network.connectivity"}
                    )
                ),
                decision=providers.decision,
                reasoning=providers.reasoning,
                knowledge=providers.knowledge,
                frontier_ranker=recorder,
                capture_frontier_worker_inputs=True,
            )
            case = app.create(
                objective=(
                    "Investigate synthetic intermittent slow resource pressure"
                    if scenario is None
                    else scenario.objective
                ),
                budget_ms=60_000,
                max_probes=5,
                max_rounds=4,
            )
            binding_path = work_dir / "hidden-recipe-binding.json"
            if scenario is not None:
                write_synthetic_recipe_binding(binding_path, str(case.case_id), scenario)
            _fill_case(store, str(case.case_id), count=80, target_index=70)
            service_facts = (
                EvidenceFact(
                    name="processes",
                    value=[{"pid": 42, "creation_time": "2026-09-24T12:00:00+00:00"}],
                ),
                EvidenceFact(name="services", value=[{"name": "AudioSrv", "process_id": 42}]),
            )
            relations = EvidenceRelationRepository(store)
            for number, age in ((81, 1), (82, 120)):
                evidence_id = f"ev_{number:032x}"
                _insert_record(
                    store,
                    case_id=str(case.case_id),
                    evidence_id=evidence_id,
                    collector_id="services.snapshot",
                    summary="Synthetic exact service process identity",
                    observed_at=utc_now() - timedelta(seconds=age),
                    facts=service_facts,
                )
                row = store.evidence(case_id=str(case.case_id), evidence_id=evidence_id)
                assert row is not None
                record = EvidenceRecord.model_validate_json(row.record_json)
                if number == 81:
                    with store.transaction() as transaction:
                        transaction.record_probe_execution(
                            execution_id=str(record.collector.execution_id),
                            case_id=str(case.case_id),
                            probe_id="services.snapshot",
                            probe_version=1,
                            status="ok",
                            parameters_json="{}",
                            started_at=(record.observed_at - timedelta(milliseconds=1)).isoformat(),
                            finished_at=record.captured_at.isoformat(),
                            state_version=case.state_version,
                        )
                        store.connection.execute(
                            "UPDATE evidence SET execution_id=?,time_basis='collector_observed',"
                            "time_quality='exact' WHERE evidence_id=?",
                            (str(record.collector.execution_id), evidence_id),
                        )
                for relation in ExplicitRelationProjector().project(record).relations:
                    relations.append(relation)
            completed = None
            try:
                completed = app.run(str(case.case_id))
            except Exception as error:
                failure = type(error).__name__
            calls = (
                ()
                if completed is None
                else tuple(call.model_dump(mode="json") for call in completed.provider_calls)
            )
            summary = summarize_trace(
                recorder.menus, calls, deep_provider_id=providers.reasoning.identity.provider_id
            )
            measured = store.connection.execute(
                "SELECT count(*) FROM probe_executions WHERE case_id=? "
                "AND probe_id='pressure.sample' AND status='ok'",
                (str(case.case_id),),
            ).fetchone()
            probe_events = tuple(
                {
                    "probe_id": str(row[0]),
                    "status": str(row[1]),
                    "started_at": str(row[2]),
                    "finished_at": str(row[3]),
                }
                for row in store.connection.execute(
                    "SELECT probe_id,status,started_at,finished_at FROM probe_executions "
                    "WHERE case_id=? AND probe_id IN ('core.system','pressure.sample') "
                    "ORDER BY started_at",
                    (str(case.case_id),),
                ).fetchall()
            )
            event_order = summarize_event_order(
                probe_events,
                recorder.menus,
                calls,
                deep_provider_id=providers.reasoning.identity.provider_id,
            )
            draft_rows = store.connection.execute(
                "SELECT snapshot_id FROM frontier_worker_capture_drafts WHERE case_id=? "
                "ORDER BY snapshot_id",
                (str(case.case_id),),
            ).fetchall()
            snapshots = CandidateDecisionSnapshotRepository(store)
            drafts = tuple(
                snapshots.readback_frontier_worker_draft(str(row[0])) for row in draft_rows
            )
            action_receipts = (
                ()
                if scenario is None
                else tuple(
                    selected_action_receipt(
                        store, draft.snapshot_id, scenario, binding_path=binding_path
                    )
                    for draft in drafts
                )
            )
            report = {
                "schema_version": 1,
                "classification": "synthetic_fixture_runtime_only",
                "training_admissible": False,
                "diagnostic_performance_admissible": False,
                "case_id": str(case.case_id),
                "artifact_dir": str(work_dir),
                "fixture_oracle": {
                    "affected_task_degraded": oracle_bad,
                    "recipe_sha256": oracle_receipt,
                    "source": "authored_synthetic_recipe_not_model_output",
                },
                "model_pins": {
                    "laya_weight_sha256": recorder.model_weight_sha256,
                    "deep_model": profile.managed_reasoning.model,
                    "deep_digest": profile.managed_reasoning.model_digest,
                },
                "failure_type": failure,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                "outcome": None if completed is None else completed.outcome.value,
                "summary": summary,
                "event_order": event_order,
                "probe_events": probe_events,
                "synthetic_pressure_probe_ok_count": 0 if measured is None else measured[0],
                "worker_drafts": [
                    {
                        "snapshot_id": draft.snapshot_id,
                        "capture_sha256": draft.capture_sha256,
                        "batch_count": len(draft.captured_calls),
                        "training_admissible": False,
                    }
                    for draft in drafts
                ],
                "selected_action_receipts": [receipt.__dict__ for receipt in action_receipts],
                "synthetic_source_attestation": (
                    None
                    if scenario is None
                    else {
                        "scope": "isolated temporary SQLite and literal investigation handlers",
                        "host_trace_excluded_from_worker_input": True,
                        "exact_worker_payload_privacy_reviewed": False,
                        "attestation_status": "harness_declared_unreviewed",
                    }
                ),
                "menus": recorder.menus,
                "provider_calls": calls,
            }
    finally:
        try:
            providers.close()
        finally:
            report["host_diagnostic_trace"] = host_trace.finish()
    if report.get("worker_drafts"):
        report["installed_builder_parity"] = _installed_builder_parity(
            database=work_dir / "controlled-four-kind.db",
            model_path=profile.laya.model_path,
            interpreter=profile.laya.interpreter_path,
        )
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "case_id",
                    "artifact_dir",
                    "failure_type",
                    "summary",
                    "model_pins",
                    "elapsed_ms",
                )
            },
            sort_keys=True,
        )
    )
    assert output_path.exists(), "the exact offered-menu metadata was not persisted"
    if require_four_kind_acceptance:
        assert failure is None
        summary = cast(dict[str, int | bool], report["summary"])
        assert summary["four_kind_menus"] >= 1
        assert summary["laya_ranks"] >= 1
        assert summary["deep_successes"] >= 1
        assert summary["laya_deep_time_overlap"] is True
        event_order = cast(dict[str, bool], report["event_order"])
        assert all(event_order.values()), (
            "the synthetic evidence/deep/rerank sequence did not occur"
        )
        assert report["worker_drafts"], (
            "no selected uncached Laya decision retained exact worker input"
        )
        parity = cast(dict[str, object], report["installed_builder_parity"])
        assert parity["status"] == "pass", "controlled worker draft differs from installed builder"
    return report


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_RUN_LIVE_FOUR_KIND") != "1",
    reason="opt-in actual Laya and Qwen trial requires shared v4 host lease",
)
def test_actual_warm_models_see_four_kind_synthetic_menu() -> None:
    """Preserve the original integrated warm-model acceptance contract."""

    _run_controlled_case(require_four_kind_acceptance=True)


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_RUN_SYNTHETIC_PILOT") != "1",
    reason="opt-in three-case synthetic pilot requires actual Laya and Qwen",
)
@pytest.mark.parametrize("scenario", PILOT_SCENARIOS, ids=lambda scenario: scenario.kind)
def test_actual_models_capture_synthetic_pilot_case(scenario: SyntheticScenario) -> None:
    """Record exact inputs and independent outcomes without training admission."""

    report = _run_controlled_case(scenario, require_four_kind_acceptance=False)
    assert report["failure_type"] is None
    assert report["worker_drafts"]
    assert report["selected_action_receipts"]
    parity = cast(dict[str, object], report["installed_builder_parity"])
    assert parity["status"] == "pass"


def test_trace_summary_requires_real_model_calls_and_overlap() -> None:
    menus = (
        {
            "kinds": ["retrieve_evidence", "review_branch", "measure", "consult_deep"],
            "ranking_source": "laya",
            "started_at": "2026-09-24T12:00:00+00:00",
            "ended_at": "2026-09-24T12:00:00.200000+00:00",
            "deep_active_before": True,
        },
    )
    calls = (
        {
            "role": "reasoning",
            "provider_id": "ollama-local-reasoning",
            "degraded": False,
            "started_at": "2026-09-24T11:59:59.900000+00:00",
            "elapsed_ms": 600,
        },
    )
    summary = summarize_trace(menus, calls, deep_provider_id="ollama-local-reasoning")
    assert summary == {
        "four_kind_menus": 1,
        "laya_ranks": 1,
        "deep_successes": 1,
        "laya_deep_time_overlap": True,
        "deep_active_at_laya_rank": True,
    }
    cached = {**menus[0], "cache_hit": True}
    assert (
        summarize_trace((cached,), calls, deep_provider_id="ollama-local-reasoning")["laya_ranks"]
        == 0
    )
    assert (
        summarize_trace(menus, calls, deep_provider_id="some-other-provider")["deep_successes"] == 0
    )


def test_event_order_requires_measured_change_then_rerank_during_deep() -> None:
    events = (
        {
            "probe_id": "pressure.sample",
            "status": "ok",
            "started_at": "2026-09-24T12:00:01+00:00",
            "finished_at": "2026-09-24T12:00:01.100000+00:00",
        },
        {
            "probe_id": "core.system",
            "status": "ok",
            "started_at": "2026-09-24T12:00:00+00:00",
            "finished_at": "2026-09-24T12:00:03+00:00",
        },
    )
    menus = (
        {
            "ranking_source": "laya",
            "started_at": "2026-09-24T12:00:01.200000+00:00",
            "ended_at": "2026-09-24T12:00:01.400000+00:00",
            "evidence_generation": 85,
        },
        {
            "ranking_source": "laya",
            "started_at": "2026-09-24T12:00:03.100000+00:00",
            "ended_at": "2026-09-24T12:00:03.300000+00:00",
            "evidence_generation": 86,
        },
    )
    calls = (
        {
            "role": "reasoning",
            "provider_id": "local-deep",
            "degraded": False,
            "started_at": "2026-09-24T12:00:02+00:00",
            "elapsed_ms": 2500,
        },
    )
    assert summarize_event_order(events, menus, calls, deep_provider_id="local-deep") == {
        "pressure_measured_while_core_running": True,
        "deep_started_after_pressure": True,
        "late_core_arrived_during_deep": True,
        "laya_reranked_after_late_core": True,
        "laya_rerank_overlap_deep": True,
        "late_evidence_generation_advanced": True,
    }
