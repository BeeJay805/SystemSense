"""Version 2 synthetic source comparison through the public Investigator.run path.

This checks custody and a matched visible choice, not model or Windows diagnosis.
Each arm starts from a byte-identical closed postbaseline SQLite checkpoint.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import inspect
import json
import shutil
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from benchmarks.source_backed_frontier_pilot import (
    _CASES,  # pyright: ignore[reportPrivateUsage]
    ScriptedSourceRanker,
    SourceCaseV1,
    _canonical,  # pyright: ignore[reportPrivateUsage]
    _evidence_id,  # pyright: ignore[reportPrivateUsage]
    _git_head,  # pyright: ignore[reportPrivateUsage]
    _sha,  # pyright: ignore[reportPrivateUsage]
    _source_sha,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import DiagnosticPurpose, ProbeCapability, ProbeProposal
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
    _candidate_description,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.decision.semantic_packets import compact_worker_packet
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeOutputFieldV1,
    ProbeSafety,
    ProbeToolMetadataV1,
    SafetyClass,
    SelfWrite,
)
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class WorldV2:
    world_key: str
    case: SourceCaseV1
    diagnostic_facts: dict[str, JsonValue]


_WORLDS = (
    WorldV2("network-world-a", _CASES[0], _CASES[0].source_facts[0]),
    WorldV2(
        "network-world-b",
        _CASES[0],
        {
            "affected_browser_task": "open synthetic site item in this browser profile",
            "browser_route_result": "timeout",
            "direct_same_origin_result": "unreachable",
            "proxy_enabled": False,
            "proxy_endpoint": None,
        },
    ),
    WorldV2("application-world-a", _CASES[1], _CASES[1].source_facts[0]),
    WorldV2(
        "application-world-b",
        _CASES[1],
        {
            "affected_viewer_task": "open synthetic document item in the viewer",
            "open_to_interactive_ms": 480,
            "viewer_render_p95_ms": 40,
            "external_fetch_p95_ms": 430,
        },
    ),
)

_SOURCE_IDS = tuple(str(_evidence_id(index)) for index in range(49, 53))
_BASELINE_PROBE_ID = "fixture.task_baseline"


class FrozenMenuRanker(ScriptedSourceRanker):
    """Script one choice only when all four source IDs share a legal menu."""

    def __init__(self, source_ordinal: Literal[0, 1]) -> None:
        super().__init__(source_ordinal)
        self.target_request: FrontierRankRequestV1 | None = None
        self.target_response: FrontierRankResponseV1 | None = None

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Any = None,
    ) -> FrontierRankResponseV1:
        sources = {
            str(item.reference.evidence_id)
            for item in request.items
            if item.reference.kind == "retrieve_evidence"
        }
        if self.target_request is None and set(_SOURCE_IDS) <= sources:
            self.requests.append(request)
            selected_source = _SOURCE_IDS[self.source_ordinal]
            selected = next(
                item.item_id
                for item in request.items
                if str(item.reference.evidence_id) == selected_source
            )
            offered = tuple(item.item_id for item in request.items)
            fallback = MixedFrontierRanker.rank(
                self, request, capture_worker_batch=capture_worker_batch
            )
            response = fallback.model_copy(
                update={
                    "ranked_item_ids": (selected, *(item for item in offered if item != selected)),
                    "considered_item_ids": offered,
                    "ranking_source": "laya",  # Runtime response shape; provider is scripted.
                    "model_abstained": False,
                    "coverage_complete": True,
                    "degraded_reason": None,
                }
            ).validate_against(request)
            self.responses.append(response)
            self.target_request, self.target_response = request, response
            return response
        self.requests.append(request)
        response = MixedFrontierRanker.rank(
            self, request, capture_worker_batch=capture_worker_batch
        )
        self.responses.append(response)
        return response


def _task_facts(domain: str) -> dict[str, JsonValue]:
    if domain == "network_browser":
        return {
            "target_handle": "synthetic:browser-profile:one",
            "action": "open synthetic site item",
            "expected": "page_loaded",
            "observed": "timeout",
            "sample_window_ms": 500,
        }
    return {
        "target_handle": "synthetic:document-viewer:one",
        "action": "open synthetic document item",
        "expected": "interactive_within_100ms",
        "observed": "interactive_after_480ms",
        "sample_window_ms": 500,
    }


def _app(store: SQLiteStore, spec: SourceCaseV1, ranker: FrozenMenuRanker | None) -> Investigator:
    facts = _task_facts(spec.domain)

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = datetime.now(UTC)
        observed = {
            **facts,
            "synthetic_window_start_utc": (now - timedelta(milliseconds=500)).isoformat(),
            "synthetic_window_end_utc": now.isoformat(),
        }
        return ProbeObservation(
            summary="Scripted fixture affected-task observation",
            facts=observed,
            limitations=("Synthetic fixture only; no Windows browser or document was opened.",),
            observed_at=now,
            captured_at=now,
        )

    manifest = ProbeManifest(
        probe_id=_BASELINE_PROBE_ID,
        version=1,
        implementation_id="builtin.fixture.synthetic.task_baseline.v1",
        question="Observe the synthetic affected task",
        safety=ProbeSafety(
            safety_class=SafetyClass.R1,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
            self_writes=(SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
        ),
        input_model="NoParametersV1",
        limits=ProbeLimits(timeout_ms=1_000, max_output_bytes=32_768, max_records=64),
        category="fixture",
    )
    discovery = ProbeToolMetadataV1(
        probe_id=_BASELINE_PROBE_ID,
        probe_version=1,
        observable_ids=(_BASELINE_PROBE_ID,),
        parameter_fields=(),
        supports_window=False,
        outputs=(ProbeOutputFieldV1(name="observed"),),
        estimated_cost_ms=25,
        resource_class="cpu",
        sensitivity=Sensitivity.SYSTEM_METADATA,
        network_effect="none",
        io_intensity="light",
        target_state_effect="none",
        self_writes=(SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
        purpose="Observe the synthetic affected task",
    )
    runtime = DiagnosticRuntime(
        store=store,
        case_service=CaseService(
            store,
            DeterministicPlanner(
                candidates=(
                    ProbeCandidate(probe_id=_BASELINE_PROBE_ID, cost_ms=25, value=1, common=True),
                )
            ),
        ),
        probe_runner=ProbeRunner(
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=_NoParameters,
                    handler=collect,
                    isolated=False,
                    discovery=discovery,
                ),
            )
        ),
    )
    return Investigator(
        store=store,
        runtime=runtime,
        capabilities=(
            ProbeCapability(
                probe_id=_BASELINE_PROBE_ID,
                description="Observe synthetic affected task",
                keywords=frozenset({"task"}),
                common=True,
                cost_ms=25,
                resource_class=ResourceClass.CPU,
            ),
        ),
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
        knowledge=ReferenceKnowledgeGraph.load_default(),
        frontier_ranker=ranker,
        enable_scout_prefetch=False,
    )


def _checkpoint(path: Path, spec: SourceCaseV1) -> dict[str, Any]:
    with SQLiteStore(path) as store:
        app = _app(store, spec, None)
        state = app.create(
            objective=spec.objective,
            budget_ms=60_000,
            max_rounds=12,
            max_probes=16,
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "started",
            "Synthetic baseline setup started.",
        )
        proposal = ProbeProposal(
            probe_id=_BASELINE_PROBE_ID,
            purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
            priority=1,
            estimated_cost_ms=25,
            resource_class=ResourceClass.CPU,
            dedupe_key="baseline:fixture.task_baseline",
        )
        state = app._collect(state, (proposal,), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        if state.completed_probe_ids != (_BASELINE_PROBE_ID,):
            raise ValueError("synthetic baseline did not complete")
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.QUEUED}),
            "setup_checkpoint",
            "Closed synthetic postbaseline checkpoint.",
        )
        task_rows = store.connection.execute(
            "SELECT evidence_id,record_json FROM evidence WHERE case_id=? AND "
            "json_extract(record_json, '$.collector.id')=?",
            (str(state.case_id), _BASELINE_PROBE_ID),
        ).fetchall()
        if len(task_rows) != 1:
            raise ValueError("synthetic affected-task observation is not uniquely bound")
        task_record = EvidenceRecord.model_validate_json(str(task_rows[0][1]))
        task_values = {fact.name: fact.value for fact in task_record.facts}
        if any(task_values.get(key) != value for key, value in _task_facts(spec.domain).items()):
            raise ValueError("affected-task observation does not match frozen task scope")
        if task_values.get("synthetic_window_end_utc") != task_record.observed_at.isoformat():
            raise ValueError("affected-task window does not match observation time")
        return {
            "case_id": str(state.case_id),
            "state_version": state.state_version,
            "completed_probe_ids": list(state.completed_probe_ids),
            "task_observation": {
                "evidence_id": str(task_record.evidence_id),
                "case_id": str(task_record.case_id),
                "collector_id": task_record.collector.id,
                "execution_id": str(task_record.collector.execution_id),
                "source_id": task_record.source.source_id,
                "observed_at": task_record.observed_at.isoformat(),
                "captured_at": task_record.captured_at.isoformat(),
                "facts": task_values,
                "classification": "fixture_simulated_task_observation",
            },
        }


def _seed_world_sources(
    store: SQLiteStore, case_id: CaseId, world: WorldV2, observed_at: datetime
) -> None:
    """Append source observations once, with the same clock and IDs per reset arm."""

    for index in range(1, 53):
        summary = (
            f"Background source record {index}"
            if index <= 48
            else world.case.source_summaries[index - 49]
        )
        facts: dict[str, JsonValue] = (
            {"background_index": index}
            if index <= 48
            else world.diagnostic_facts
            if index == 49
            else world.case.source_facts[index - 49]
        )
        evidence_id = _evidence_id(index)
        execution_id = ExecutionId(root=f"exec_{index:032x}")
        source_id = stable_source_id(
            "fixture.scripted.source", {"domain": world.case.domain, "source_index": index}
        )
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=observed_at,
            captured_at=observed_at,
            source=EvidenceSource(
                type="fixture.scripted.source",
                source_id=source_id,
                locator={"domain": world.case.domain, "source_index": index},
            ),
            collector=CollectorReference(
                id=f"fixture.{world.case.domain}", version=1, execution_id=execution_id
            ),
            summary=summary,
            facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
            extraction=Extraction(confidence=1.0, parser="fixture.scripted", parser_version=1),
            sensitivity=Sensitivity.SYSTEM_METADATA,
            limitations=("Preexisting synthetic fixture source; no on-case probe execution.",),
        )
        with store.transaction() as transaction:
            inserted = transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=source_id,
                record_json=record.model_dump_json(),
                observed_at=observed_at.isoformat(),
                captured_at=observed_at.isoformat(),
                execution_id=str(execution_id),
                time_basis="fixture_observed",
                time_quality="exact",
            )
        if not inserted:
            raise ValueError("synthetic source row was not append-only")


def _cell(
    database: Path,
    world: WorldV2,
    ordinal: Literal[0, 1],
    checkpoint_case_id: str,
    source_observed_at: datetime,
) -> dict[str, Any]:
    started = time.perf_counter()
    with SQLiteStore(database) as store:
        ranker = FrozenMenuRanker(ordinal)
        app = _app(store, world.case, ranker)
        case_id = CaseId(root=checkpoint_case_id)
        _seed_world_sources(store, case_id, world, source_observed_at)
        generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=case_id, limit=1))
            .case_evidence_generation
        )
        frontier = SearchFrontierRepository(store)
        with store.transaction():
            event = frontier.append_result_event(
                case_id,
                source_evidence_id=_evidence_id(49),
                source_execution_id=None,
                versions=RelevantVersionsV1(objective=1, evidence=generation),
            )
        if not isinstance(event, FrontierEventV1) or event.source_state != "present":
            raise ValueError("source event is not verifiable")
        state = app.run(str(case_id))
        request, response = ranker.target_request, ranker.target_response
        if request is None or response is None:
            raise ValueError("full run did not offer all four frozen source choices")
        source_items = [
            item for item in request.items if item.reference.kind == "retrieve_evidence"
        ]
        menu = [str(item.reference.evidence_id) for item in source_items]
        if not set(_SOURCE_IDS) <= set(menu):
            raise ValueError(f"full-run source menu drifted: {menu}")
        selected_id = _SOURCE_IDS[ordinal]
        if _evidence_id(49 + ordinal) not in state.fast_catalog_selected_ids:
            raise ValueError("scripted source selection is absent from durable state")
        selected = store.evidence(case_id=str(case_id), evidence_id=selected_id)
        if selected is None:
            raise ValueError("selected source readback missing")
        selected_record = EvidenceRecord.model_validate_json(selected.record_json)
        turns = tuple(
            turn
            for row in store.connection.execute(
                "SELECT DISTINCT event_id FROM search_frontier_investigator_turns WHERE case_id=?",
                (str(case_id),),
            )
            for turn in frontier.investigator_turns(case_id, str(row[0]))
        )
        calls = [
            call
            for call in InvestigationRepository(store).load(str(case_id)).provider_calls
            if call.role == "catalog_attention"
            and call.provider_id == "scripted-source-frontier-v1"
            and call.detail == "event_frontier_retrieval"
            and not call.degraded
        ]
        target_turn = next(
            (
                turn
                for turn in turns
                if set(item.item_id for item in source_items)
                <= set((*turn.pending_item_ids, *turn.offered_item_ids))
            ),
            None,
        )
        if target_turn is None or not any(
            call.state_version == target_turn.expected_checkpoint_version for call in calls
        ):
            raise ValueError("frozen offer lacks durable turn/provider custody")
        source_row_count = int(
            store.connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id=? AND "
                "json_extract(record_json, '$.source.type')='fixture.scripted.source'",
                (str(case_id),),
            ).fetchone()[0]
        )
        source_probe_links = int(
            store.connection.execute(
                "SELECT COUNT(*) FROM evidence AS e JOIN probe_executions AS x "
                "ON x.case_id=e.case_id AND x.execution_id=e.execution_id "
                "WHERE e.case_id=? AND "
                "json_extract(e.record_json, '$.source.type')='fixture.scripted.source'",
                (str(case_id),),
            ).fetchone()[0]
        )
        if source_row_count != 52 or source_probe_links:
            raise ValueError("synthetic source rows were misclassified as case probe attempts")
        request_json = request.model_dump(mode="json")
        if any(
            str(value) in json.dumps(request_json)
            for value in ("127.0.0.1:9", "viewer_render_p95_ms", "storage_warning_count")
        ):
            raise ValueError("unopened source result leaked to scripted provider")
        return {
            "world_key": world.world_key,
            "case_key": world.case.case_key,
            "domain": world.case.domain,
            "choice": f"scripted_ordinal_{ordinal}",
            "case_id": str(case_id),
            "status": state.status.value,
            "outcome": state.outcome.value,
            "stop_reason": state.stop_reason,
            "source_event_id": event.event_id,
            "target_event_id": target_turn.event_id,
            "target_turn_id": target_turn.turn_id,
            "target_state_version": target_turn.expected_checkpoint_version,
            "source_menu_evidence_ids": menu,
            "target_source_evidence_ids": list(_SOURCE_IDS),
            "source_menu_item_ids": [item.item_id for item in source_items],
            "rank_request": request_json,
            "rank_response": response.model_dump(mode="json"),
            "rank_request_sha256": _sha(request_json),
            "selected_evidence_id": selected_id,
            "selected_facts": {fact.name: fact.value for fact in selected_record.facts},
            "provider_call": next(
                call.model_dump(mode="json")
                for call in calls
                if call.state_version == target_turn.expected_checkpoint_version
            ),
            "all_rank_call_count": len(ranker.requests),
            "probe_attempt_count": int(
                store.connection.execute(
                    "SELECT COUNT(*) FROM probe_executions WHERE case_id=?", (str(case_id),)
                ).fetchone()[0]
            ),
            "preexisting_synthetic_source_count": source_row_count,
            "preexisting_source_probe_execution_links": source_probe_links,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        }


def _prechoice_request_digest(request: dict[str, Any]) -> str:
    """Remove wall-clock offer times, retaining every source commitment."""

    normalized = copy.deepcopy(request)
    normalized.pop("deadline_at", None)
    for item in normalized["items"]:
        item.pop("created_at", None)
    return _sha(normalized)


def _model_facing_projection_digests(request: dict[str, Any]) -> dict[str, str]:
    """Hash the actual fields sent by current Laya and local-deep adapters."""

    typed = FrontierRankRequestV1.model_validate(request)
    descriptions = [
        {"item_id": item.item_id, "description": _candidate_description(item, semantic)}
        for item, semantic in zip(typed.items, typed.item_semantics, strict=True)
    ]
    shared = {
        "symptom": typed.symptom,
        "hypothesis_briefs": typed.hypothesis_briefs,
    }
    laya = {
        **shared,
        "attention_kind": "mixed_frontier_relevance",
        "evidence": [compact_worker_packet(packet.wire()) for packet in typed.evidence_packets],
        "candidates": [
            {"probe_id": item["item_id"], "description": item["description"]}
            for item in descriptions
        ],
    }
    local_deep = {
        **shared,
        "evidence_packets": [packet.wire() for packet in typed.evidence_packets],
        "offered_items": descriptions,
    }
    return {"laya_payload_sha256": _sha(laya), "local_deep_payload_sha256": _sha(local_deep)}


def run_full_run_pilot(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "checkpoints").mkdir()
    (output_dir / "cases").mkdir()
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    protocol = {
        "schema_version": 2,
        "classification": "synthetic_full_run_mechanics_only",
        "entrypoint": "Investigator.run",
        "baseline": "one_registered_read_only_fixture.task_baseline_probe_before_checkpoint",
        "source_capture_class": "preexisting_synthetic_fixture_records_not_case_probe_executions",
        "source_count_per_cell": 52,
        "policy_provider": "scripted-source-frontier-v1",
        "model_arms": "unrun",
        "source_choices": list(_SOURCE_IDS),
        "target_choice_ordinals": [0, 1],
        "world_groups": [
            {
                "domain": case.domain,
                "case_key": case.case_key,
                "visible_objective": case.objective,
                "world_count": 2,
            }
            for case in _CASES
        ],
        "task_target": {case.case_key: _task_facts(case.domain) for case in _CASES},
        "cause_labels": "evaluator_only",
        "result_scope": "scripted_synthetic_task_and_recipe_compatibility_only",
        "comparison_admissible": False,
        "prechoice_request_parity_contract": (
            "Compare the validated rank request across hidden worlds after excluding "
            "only wall-clock deadline_at and item created_at. Report source content "
            "commitments in the envelope separately from current model payloads."
        ),
        "world_key_scope": "evaluator_metadata_only_not_policy_input",
        "model_payload_projection": (
            "Static reconstruction from current MixedFrontierRanker and "
            "LocalDeepFrontierRanker serialization; no model transport invoked"
        ),
    }
    (output_dir / "protocol.json").write_bytes(_canonical(protocol))
    checkpoints: dict[str, dict[str, Any]] = {}
    for spec in _CASES:
        database = output_dir / "checkpoints" / f"{spec.case_key}.db"
        readback = _checkpoint(database, spec)
        readback["sha256"] = hashlib.sha256(database.read_bytes()).hexdigest()
        checkpoints[spec.case_key] = readback
    cells: list[dict[str, Any]] = []
    for world in _WORLDS:
        base = output_dir / "checkpoints" / f"{world.case.case_key}.db"
        for ordinal in (0, 1):
            database = output_dir / "cases" / f"{world.world_key}-{ordinal}.db"
            shutil.copyfile(base, database)
            if (
                hashlib.sha256(database.read_bytes()).hexdigest()
                != checkpoints[world.case.case_key]["sha256"]
            ):
                raise ValueError("arm did not start from exact checkpoint bytes")
            checkpoint = checkpoints[world.case.case_key]
            cell = _cell(
                database,
                world,
                ordinal,
                str(checkpoint["case_id"]),
                datetime.fromisoformat(str(checkpoint["task_observation"]["captured_at"]))
                + timedelta(microseconds=1),
            )
            cell["initial_checkpoint_sha256"] = checkpoints[world.case.case_key]["sha256"]
            cell["database_sha256"] = hashlib.sha256(database.read_bytes()).hexdigest()
            cell["prechoice_request_normalized_sha256"] = _prechoice_request_digest(
                cell["rank_request"]
            )
            cell["model_facing_projection_sha256"] = _model_facing_projection_digests(
                cell["rank_request"]
            )
            cells.append(cell)
    parity: dict[str, Any] = {}
    for spec in _CASES:
        family = [cell for cell in cells if cell["case_key"] == spec.case_key]
        per_world = {
            key: {
                cell["prechoice_request_normalized_sha256"]
                for cell in family
                if cell["world_key"] == key
            }
            for key in {cell["world_key"] for cell in family}
        }
        if any(len(digests) != 1 for digests in per_world.values()):
            raise ValueError("same-world scripted choices lost prechoice request parity")
        menu_ids = {tuple(cell["source_menu_item_ids"]) for cell in family}
        if len(menu_ids) != 1:
            raise ValueError("same-domain source menu item IDs drifted")
        commitments = {
            cell["world_key"]: next(
                item["source_record_sha256"]
                for item in cell["rank_request"]["item_semantics"]
                if item["reference_id"] == _SOURCE_IDS[0]
            )
            for cell in family
        }
        parity[spec.case_key] = {
            "same_world_choice_parity": True,
            "same_domain_menu_ids": True,
            "hidden_world_prechoice_request_parity": (
                "matched"
                if len({next(iter(value)) for value in per_world.values()}) == 1
                else "mismatched"
            ),
            "current_adapter_laya_payload_parity": (
                "matched"
                if len(
                    {
                        cell["model_facing_projection_sha256"]["laya_payload_sha256"]
                        for cell in family
                    }
                )
                == 1
                else "mismatched"
            ),
            "current_adapter_local_deep_payload_parity": (
                "matched"
                if len(
                    {
                        cell["model_facing_projection_sha256"]["local_deep_payload_sha256"]
                        for cell in family
                    }
                )
                == 1
                else "mismatched"
            ),
            "source_record_sha256_by_world": commitments,
            "reason_if_mismatched": "validated_rank_request_envelope_source_commitment_differs",
        }
    blind = {
        "schema_version": 2,
        "classification": "prechoice_request_review_only",
        "cells": [
            {
                "anonymous_cell_id": f"cell_{index:02d}",
                "case_key": cell["case_key"],
                "rank_request": cell["rank_request"],
                "source_menu_evidence_ids": cell["source_menu_evidence_ids"],
                "source_menu_item_ids": cell["source_menu_item_ids"],
            }
            for index, cell in enumerate(cells)
        ],
    }
    (output_dir / "policy-visible" / "requests.json").write_bytes(_canonical(blind))
    (output_dir / "attempts.json").write_bytes(
        _canonical(
            {"schema_version": 2, "checkpoints": checkpoints, "parity": parity, "cells": cells}
        )
    )
    from benchmarks.source_backed_full_run_oracle import review_cells

    reviews = review_cells(cells)
    (output_dir / "evaluator-only" / "reviews.json").write_bytes(_canonical(reviews))
    files = [
        "protocol.json",
        "policy-visible/requests.json",
        "attempts.json",
        "evaluator-only/reviews.json",
        *(f"checkpoints/{spec.case_key}.db" for spec in _CASES),
        *(f"cases/{world.world_key}-{ordinal}.db" for world in _WORLDS for ordinal in (0, 1)),
    ]
    manifest = {
        "schema_version": 2,
        "runner_git_sha": _git_head(),
        "protocol_digest": _sha(protocol),
        "source_sha256_normalized": {
            "runner": _source_sha(Path(__file__).resolve()),
            "oracle": _source_sha(Path(inspect.getfile(review_cells)).resolve()),
            "runtime_investigator": _source_sha(Path(inspect.getfile(Investigator)).resolve()),
        },
        "files": {
            name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest() for name in files
        },
    }
    (output_dir / "manifest.json").write_bytes(_canonical(manifest))
    return {
        "cells": len(cells),
        "full_run_target_menus": len(cells),
        "hidden_world_prechoice_parity": {
            key: value["hidden_world_prechoice_request_parity"] for key, value in parity.items()
        },
        "comparison_admissible": False,
        "protocol_digest": manifest["protocol_digest"],
    }


def verify_full_run_pilot(output_dir: Path) -> dict[str, Any]:
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    from benchmarks.source_backed_full_run_oracle import review_cells

    if manifest["source_sha256_normalized"] != {
        "runner": _source_sha(Path(__file__).resolve()),
        "oracle": _source_sha(Path(inspect.getfile(review_cells)).resolve()),
        "runtime_investigator": _source_sha(Path(inspect.getfile(Investigator)).resolve()),
    }:
        raise ValueError("artifact source revision mismatch")
    for name, digest in manifest["files"].items():
        if hashlib.sha256((output_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"artifact hash mismatch: {name}")
    cells = json.loads((output_dir / "attempts.json").read_text(encoding="utf-8"))["cells"]
    if len(cells) != 8 or any(
        not set(_SOURCE_IDS) <= set(cell["source_menu_evidence_ids"]) for cell in cells
    ):
        raise ValueError("full-run cells or menus incomplete")
    return {"integrity_verified": True, "cells": len(cells), "comparison_admissible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    result = (
        verify_full_run_pilot(args.output_dir)
        if args.verify
        else run_full_run_pilot(args.output_dir)
    )
    print(json.dumps(result, sort_keys=True))
