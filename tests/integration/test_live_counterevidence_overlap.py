"""Opt-in capture-off Laya/Qwen check after contradictory synthetic evidence.

This is an actual-model scheduling and input-custody trial, not a diagnosis
oracle. The selected action is reported, never forced or graded as correct.
All probe handlers are synthetic and read-only; no host fault is created.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from typing import cast

import pytest

from benchmarks.real_mixed_trace import trace_case
from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.cli import _v4_providers  # pyright: ignore[reportPrivateUsage]
from systemsense.decision.contracts import ProbeCapability
from systemsense.domain.evidence import EvidenceFact, EvidenceRecord
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.laya_runtime import LayaSubprocessRuntime
from systemsense.inference.profile import load_inference_profile
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import default_probe_definitions
from systemsense.storage.search_frontier import FrontierStatus, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_conflicting_frontier_redirection import (
    ContradictionOracleRanker,
    _high_pressure_source,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_event_frontier_loop import (
    _bind_fixture_execution,  # pyright: ignore[reportPrivateUsage]
    _omit_until_selected,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator
from tests.integration.test_opt_in_live_four_kind import RecordingRealRanker
from tests.unit.application.test_general_candidate_catalog import (
    _gpu_source,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.evidence.test_retrieval import _insert_record  # pyright: ignore[reportPrivateUsage]


def _observe(_parameters: dict[str, JsonValue], *, name: str) -> ProbeObservation:
    facts = cast(
        dict[str, JsonValue],
        {
            "core.system": {"os": "Windows", "fixture": "synthetic"},
            "core.resources": {"pressure_percent": 97},
            "pressure.sample": {"pressure_percent": 3},
            "gpu.telemetry.sample": {
                "temperature_c": 92,
                "clock_mhz": 300,
                "throttle_state": "thermal",
            },
        }[name],
    )
    observed = datetime.now(UTC)
    return ProbeObservation(
        summary=f"Synthetic {name} observation",
        facts=facts,
        observed_at=observed,
        captured_at=observed,
    )


def _synthetic_definitions() -> tuple[ProbeDefinition, ...]:
    registered = {"core.system", "core.resources", "pressure.sample", "gpu.telemetry.sample"}
    definitions = tuple(
        replace(
            original,
            isolated=False,
            handler=partial(_observe, name=original.manifest.probe_id),
        )
        for original in default_probe_definitions()
        if original.manifest.probe_id in registered
    )
    assert {item.manifest.probe_id for item in definitions} == registered
    return definitions


def _seed_deferred_related_evidence(store: SQLiteStore, case_id: CaseId) -> tuple[EvidenceId, ...]:
    """One small, pre-existing process/power/driver menu, not invented later facts."""

    now = datetime.now(UTC)
    observations = (
        (
            "power.snapshot",
            "Active power plan limits the processor to 50 percent",
            (EvidenceFact(name="processor_max_percent", value=50),),
        ),
        (
            "application.snapshot",
            "Game overlay capture process uses substantial resources",
            (
                EvidenceFact(name="process_name", value="GameOverlay.exe"),
                EvidenceFact(name="cpu_percent", value=38),
            ),
        ),
        (
            "devices.snapshot",
            "Display driver reports one recent reset event",
            (
                EvidenceFact(name="device", value="NVIDIA display adapter"),
                EvidenceFact(name="recent_reset_count", value=1),
            ),
        ),
        (
            "application.snapshot",
            "Background update process consumed disk and CPU during game launch",
            (
                EvidenceFact(name="process_name", value="WindowsUpdate.exe"),
                EvidenceFact(name="cpu_percent", value=29),
                EvidenceFact(name="disk_busy_percent", value=80),
            ),
        ),
    )
    ids: list[EvidenceId] = []
    for index, (collector, summary, facts) in enumerate(observations):
        evidence_id = EvidenceId.new()
        _insert_record(
            store,
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            collector_id=collector,
            summary=summary,
            observed_at=now - timedelta(seconds=10 + index),
            captured_at=now,
            facts=facts,
        )
        _bind_fixture_execution(store, case_id, evidence_id)
        ids.append(evidence_id)
    return tuple(ids)


def _hide_until_focused(
    app: Investigator,
    case_id: CaseId,
    ids: tuple[EvidenceId, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Simulate a four-row packet omission; original source bytes stay stored."""

    for evidence_id in ids:
        _omit_until_selected(app, str(case_id), evidence_id, monkeypatch)
    visible = {str(item.evidence_id) for item in app.context(str(case_id))}
    assert not visible.intersection(str(item) for item in ids)


def test_deferred_related_evidence_competes_with_measurement_after_counterevidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fake oracle proves menu custody, not actual untrained Laya quality."""

    definitions = _synthetic_definitions()
    with SQLiteStore(tmp_path / "deferred-counter-menu.db") as store:
        base = investigator(store)
        oracle = ContradictionOracleRanker()
        app = Investigator(
            store=store,
            runtime=DiagnosticRuntime(
                store=store,
                case_service=CaseService(store, DeterministicPlanner(candidates=())),
                probe_runner=ProbeRunner(definitions=definitions),
            ),
            capabilities=tuple(
                ProbeCapability(
                    probe_id=definition.manifest.probe_id,
                    description=definition.manifest.question,
                    common=True,
                    cost_ms=1,
                    resource_class=ResourceClass.CPU,
                )
                for definition in definitions
                if definition.manifest.probe_id in {"core.system", "core.resources"}
            ),
            decision=base.decision,
            reasoning=base.reasoning,
            knowledge=ReferenceKnowledgeGraph.load_default(),
            frontier_ranker=oracle,
        )
        case = app.create(
            objective="Game runs slowly despite a capable GPU",
            budget_ms=20_000,
            max_probes=8,
            max_rounds=6,
        )
        _gpu_source(store, case.case_id, age_seconds=0.5, epoch=case.state_version)
        _high_pressure_source(store, case.case_id, case.state_version)
        deferred_ids = _seed_deferred_related_evidence(store, case.case_id)
        _hide_until_focused(app, case.case_id, deferred_ids, monkeypatch)
        final = app.run(str(case.case_id))

        post_counter = [
            (request, response)
            for request, response in oracle.trace
            if any(
                (semantic := json.loads(packet.description)).get("probe_id") == "pressure.sample"
                and semantic.get("metric") == "pressure_percent"
                and semantic.get("value") == 3
                for packet in request.evidence_packets
            )
        ]
        assert post_counter, "no later mixed menu saw the contradictory sample"
        assert any(
            len(request.items) >= 2
            and any(
                item.reference.kind == "measure"
                and semantic.measurement is not None
                and semantic.measurement.probe_id == "gpu.telemetry.sample"
                for item, semantic in zip(request.items, request.item_semantics, strict=True)
            )
            and any(
                item.reference.kind == "retrieve_evidence"
                and item.reference.evidence_id in deferred_ids
                for item in request.items
            )
            for request, _ in post_counter
        ), "no meaningful GPU-vs-stored-evidence comparison survived after counterevidence"
        pressure_row = store.connection.execute(
            "SELECT e.evidence_id FROM evidence AS e JOIN probe_executions AS x "
            "ON x.execution_id=e.execution_id WHERE e.case_id=? "
            "AND x.probe_id='pressure.sample' LIMIT 1",
            (str(case.case_id),),
        ).fetchone()
        assert pressure_row is not None
        event_row = store.connection.execute(
            "SELECT event_id FROM search_frontier_events WHERE case_id=? AND source_evidence_id=?",
            (str(case.case_id), str(pressure_row[0])),
        ).fetchone()
        assert event_row is not None
        frontier = SearchFrontierRepository(store)
        counter_turns = frontier.investigator_turns(case.case_id, str(event_row[0]))
        assert counter_turns, (
            "the changed observation remained durable but was never given its own fast turn"
        )
        assert all(frontier.read_investigator_turn_outcome(turn.turn_id) for turn in counter_turns)
        assert all(
            event.event_id != str(event_row[0])
            for event in frontier.pending_investigator_events(case.case_id)
        )
        assert final.round_count < final.max_rounds


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_RUN_LIVE_COUNTEREVIDENCE") != "1",
    reason="explicit opt-in actual Laya/Qwen synthetic counterevidence trial",
)
def test_actual_laya_reranks_after_counterevidence_while_qwen_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_path = (
        Path(__file__).resolve().parents[2] / "examples" / "warm-local-development.profile.json"
    )
    profile = load_inference_profile(profile_path)
    assert profile.schema_version == 4 and profile.runtime_strategy == "warm-independent"
    assert profile.managed_reasoning is not None

    definitions = _synthetic_definitions()
    setup_started = time.monotonic()
    try:
        providers = _v4_providers(profile)
    except Exception as error:
        print(
            json.dumps(
                {
                    "kind": "actual_model_prewarm_failure",
                    "stage": "setup_and_laya_cold",
                    "elapsed_ms": round((time.monotonic() - setup_started) * 1000, 3),
                    "error_type": type(error).__name__,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        raise
    setup_and_laya_cold_ms = round((time.monotonic() - setup_started) * 1000, 3)
    assert providers.frontier_ranker is not None
    recorder = RecordingRealRanker(providers.frontier_ranker, providers.runtime_status)
    database = Path(tempfile.mkdtemp(prefix="systemsense-live-counter-")) / "case.db"
    try:
        laya_rewarm_started = time.monotonic()
        try:
            providers.prewarm_laya(timeout_seconds=profile.laya.timeout_seconds)
        except Exception as error:
            print(
                json.dumps(
                    {
                        "kind": "actual_model_prewarm_failure",
                        "stage": "laya_rewarm",
                        "elapsed_ms": round((time.monotonic() - laya_rewarm_started) * 1000, 3),
                        "error_type": type(error).__name__,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            raise
        laya_rewarm_ms = round((time.monotonic() - laya_rewarm_started) * 1000, 3)
        prewarm = {
            "setup_and_laya_cold_ms": setup_and_laya_cold_ms,
            "laya_rewarm_ms": laya_rewarm_ms,
            "deep_first_owned_call": "cold; standalone managed preload is unsupported",
        }
        print(json.dumps({"kind": "actual_model_prewarm", **prewarm}, sort_keys=True), flush=True)
        independent = getattr(providers, "_independent_runtime", None)
        coordinator = getattr(independent, "coordinator", None)
        fast_roles = getattr(coordinator, "_roles", {})
        fast_session = getattr(fast_roles.get("fast"), "session", None)
        fast_runtime = getattr(fast_session, "runtime", None)
        pre_case_timing_count = (
            len(fast_runtime.timing_samples())
            if isinstance(fast_runtime, LayaSubprocessRuntime)
            else 0
        )
        with SQLiteStore(database) as store:
            app = Investigator(
                store=store,
                runtime=DiagnosticRuntime(
                    store=store,
                    case_service=CaseService(store, DeterministicPlanner(candidates=())),
                    probe_runner=ProbeRunner(definitions=definitions),
                ),
                capabilities=tuple(
                    ProbeCapability(
                        probe_id=definition.manifest.probe_id,
                        description=definition.manifest.question,
                        common=True,
                        cost_ms=1,
                        resource_class=ResourceClass.CPU,
                    )
                    for definition in definitions
                    if definition.manifest.probe_id in {"core.system", "core.resources"}
                ),
                decision=providers.decision,
                reasoning=providers.reasoning,
                knowledge=providers.knowledge,
                frontier_ranker=recorder,
                capture_frontier_worker_inputs=False,
            )
            case = app.create(
                objective="Game runs slowly despite a capable GPU",
                budget_ms=45_000,
                max_probes=8,
                max_rounds=6,
            )
            _gpu_source(store, case.case_id, age_seconds=0.5, epoch=case.state_version)
            high_id = _high_pressure_source(store, case.case_id, case.state_version)
            deferred_ids = _seed_deferred_related_evidence(store, case.case_id)
            _hide_until_focused(app, case.case_id, deferred_ids, monkeypatch)
            started = time.monotonic()
            final = app.run(str(case.case_id))
            elapsed_ms = round((time.monotonic() - started) * 1000, 3)

            high_row = store.evidence(case_id=str(case.case_id), evidence_id=str(high_id))
            assert high_row is not None
            high = EvidenceRecord.model_validate_json(high_row.record_json)
            assert {fact.name: fact.value for fact in high.facts}["pressure_percent"] == 97
            counter_rows = store.connection.execute(
                "SELECT e.evidence_id,e.record_json,t.persisted_at "
                "FROM evidence AS e JOIN coordinator_events AS t "
                "ON t.source_record_id=e.evidence_id AND t.kind='evidence' "
                "JOIN probe_executions AS x ON x.execution_id=e.execution_id "
                "WHERE e.case_id=? AND x.probe_id='pressure.sample' "
                "ORDER BY t.persisted_at",
                (str(case.case_id),),
            ).fetchall()
            counter = [
                (str(row[0]), str(row[2]))
                for row in counter_rows
                if {
                    fact.name: fact.value
                    for fact in EvidenceRecord.model_validate_json(str(row[1])).facts
                }.get("pressure_percent")
                == 3
            ]
            trace = trace_case(database, str(case.case_id))
            laya_before = False
            pre_counter_generations: list[int] = []
            laya_after_with_input_and_deep = False
            selected_after: list[dict[str, object]] = []
            counter_opportunity: dict[str, object] | None = None
            if counter:
                counter_at = datetime.fromisoformat(counter[0][1])
                counter_opportunity = next(
                    (
                        cast(dict[str, object], item)
                        for item in trace["fast_turn_opportunities"]
                        if item["source_evidence_id"] == counter[0][0]
                    ),
                    None,
                )
                frontier = SearchFrontierRepository(store)
                # Mixed event turns commit custody-checked outcomes, not the
                # streaming focus-delivery receipt used by the other route.
                completed_action_ids = {
                    item_id
                    for (turn_id,) in store.connection.execute(
                        "SELECT turn_id FROM search_frontier_investigator_turn_outcomes "
                        "WHERE case_id=?",
                        (str(case.case_id),),
                    )
                    if (outcome := frontier.read_investigator_turn_outcome(str(turn_id)))
                    is not None
                    and outcome.outcome in {"focused_delivery", "measurement_admitted"}
                    for item_id in outcome.frontier_item_ids
                    if frontier.readback(item_id).status is FrontierStatus.SATISFIED
                }
                for menu in recorder.menus:
                    started = datetime.fromisoformat(str(menu["started_at"]))
                    if menu["ranking_source"] != "laya" or menu["degraded_reason"]:
                        continue
                    if started < counter_at:
                        laya_before = True
                        pre_counter_generations.append(cast(int, menu["evidence_generation"]))
                        continue
                    selected_id = str(menu["selected_item_id"])
                    offered_ids = cast(list[str], menu["item_ids"])
                    pressure_packets = cast(list[dict[str, object]], menu["pressure_packets"])
                    attention_notes = cast(list[str], menu["attention_notes"])
                    fragment_note = next(
                        (
                            note
                            for note in attention_notes
                            if note.startswith("fragments_considered=")
                        ),
                        "",
                    )
                    fragment_counts = fragment_note.removeprefix("fragments_considered=").split(
                        "_of_"
                    )
                    complete_worker_evidence = (
                        menu["coverage_complete"] is True
                        and "state_omissions_max=0_fields_0_items" in attention_notes
                        and len(fragment_counts) == 2
                        and fragment_counts[0] == fragment_counts[1]
                    )
                    saw_counter = any(
                        packet["evidence_id"] == counter[0][0]
                        and packet["value"] == 3
                        and packet["quality"] == "exact"
                        for packet in pressure_packets
                    )
                    deep_overlap = any(
                        isinstance(task["worker_started_at"], str)
                        and isinstance(task["worker_finished_at"], str)
                        and datetime.fromisoformat(str(task["worker_started_at"]))
                        <= started
                        < datetime.fromisoformat(str(task["worker_finished_at"]))
                        for task in trace["deep"]
                    )
                    admitted = selected_id in completed_action_ids
                    selected_after.append(
                        {
                            "started_at": menu["started_at"],
                            "rank_elapsed_ms": menu["elapsed_ms"],
                            "offered_kinds": menu["kinds"],
                            "offered_count": len(offered_ids),
                            "attention_notes": menu["attention_notes"],
                            "coverage_complete": menu["coverage_complete"],
                            "selected_item_id": selected_id,
                            "selected_kind": menu["selected_kind"],
                            "evidence_generation": menu["evidence_generation"],
                            "saw_counter": saw_counter,
                            "complete_worker_evidence": complete_worker_evidence,
                            "deep_worker_overlap": deep_overlap,
                            "action_completed": admitted,
                        }
                    )
                    laya_after_with_input_and_deep |= (
                        saw_counter
                        and complete_worker_evidence
                        and deep_overlap
                        and len(offered_ids) >= 2
                        and admitted
                        and bool(pre_counter_generations)
                        and cast(int, menu["evidence_generation"]) > max(pre_counter_generations)
                    )
            deep_applied = any(
                task["status"] == "applied" and task["response_degraded"] is False
                for task in trace["deep"]
            )
            admitted_probes = [
                str(row[0])
                for row in store.connection.execute(
                    "SELECT c.probe_id FROM candidate_dispatch_admissions AS a "
                    "JOIN case_measurement_candidates AS c ON c.candidate_id=a.candidate_id "
                    "WHERE a.case_id=? ORDER BY a.admitted_at",
                    (str(case.case_id),),
                )
            ]
            laya_menus = [
                menu
                for menu in recorder.menus
                if menu["ranking_source"] == "laya" and not menu["degraded_reason"]
            ]
            distinct_ids: set[str] = set()
            active_rank_ms = 0.0
            microbatch_count = 0
            for menu in laya_menus:
                distinct_ids.update(cast(list[str], menu["item_ids"]))
                active_rank_ms += cast(float, menu["elapsed_ms"])
                microbatch_count += cast(int, menu["worker_microbatch_count"])
            worker_samples = (
                fast_runtime.timing_samples()[pre_case_timing_count:]
                if isinstance(fast_runtime, LayaSubprocessRuntime)
                else ()
            )
            stage_names = (
                "queue_wait_ns",
                "worker_admission_ns",
                "request_write_ns",
                "tokenization_input_ns",
                "model_forward_ns",
                "response_presentation_ns",
                "response_validation_ns",
                "total_ns",
            )
            print(
                json.dumps(
                    {
                        "kind": "actual_model_counterevidence_overlap_capture_off",
                        "database": str(database.resolve()),
                        "case_id": str(case.case_id),
                        "elapsed_ms": elapsed_ms,
                        "prewarm": prewarm,
                        "deep_first_owned_worker_elapsed_ms": (
                            None if not trace["deep"] else trace["deep"][0]["worker_elapsed_ms"]
                        ),
                        "profile_id": profile.profile_id,
                        "provider_status": providers.runtime_status(),
                        "counterevidence": counter,
                        "counter_event_opportunity": counter_opportunity,
                        "admitted_probes": admitted_probes,
                        "simulated_packet_omission_ids": [str(item) for item in deferred_ids],
                        "laya_before_counter": laya_before,
                        "laya_after_counter_with_input_and_deep": laya_after_with_input_and_deep,
                        "post_counter_rankings": selected_after,
                        "deep_applied": deep_applied,
                        "final_status": final.status.value,
                        "final_stop_reason": final.stop_reason,
                        "small_menu_responsiveness": trace["small_menu_responsiveness"],
                        "distinct_candidate_throughput": trace["distinct_candidate_throughput"],
                        "all_observed_laya_menu_throughput": {
                            "menus": len(laya_menus),
                            "distinct_offered_item_ids": len(distinct_ids),
                            "active_rank_ms": round(active_rank_ms, 3),
                            "distinct_per_active_second": (
                                None
                                if not active_rank_ms
                                else round(len(distinct_ids) * 1000 / active_rank_ms, 3)
                            ),
                            "worker_microbatches": microbatch_count,
                        },
                        "laya_worker_stage_totals_ms": {
                            "samples": len(worker_samples),
                            **{
                                name.removesuffix("_ns"): round(
                                    sum(int(sample[name]) for sample in worker_samples) / 1e6,
                                    3,
                                )
                                for name in stage_names
                                if worker_samples
                                and all(name in sample for sample in worker_samples)
                            },
                        },
                    },
                    sort_keys=True,
                    default=str,
                ),
                flush=True,
            )
            assert counter, "the planned contradictory baseline did not persist"
            assert counter_opportunity is not None
            assert counter_opportunity["queued_at"] is not None
            assert counter_opportunity["turns"]
            assert laya_before, "no actual Laya decision preceded counterevidence"
            assert laya_after_with_input_and_deep, (
                "no actual Laya decision saw later low pressure while Qwen was active"
            )
            assert deep_applied, "the actual deep result was not applied"
    finally:
        providers.close()
