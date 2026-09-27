"""Version 1 CPU reachability fixture for source-backed frontier choices.

This drives a real persisted Investigator event frontier with scripted advice.
It is a synthetic mechanics pilot, not a four-arm trajectory or model result.
The source facts are stored before ranking but the rank request sees only source
metadata; private cause labels are evaluated after the selected fact is read.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from benchmarks.trajectory_comparison import (
    _frontier_offer_counts,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.time import utc_now
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeRunner
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True, slots=True)
class SourceCaseV1:
    case_key: str
    domain: str
    objective: str
    source_summaries: tuple[str, str, str, str]
    source_facts: tuple[
        dict[str, JsonValue], dict[str, JsonValue], dict[str, JsonValue], dict[str, JsonValue]
    ]


_CASES = (
    SourceCaseV1(
        case_key="source-network-browser-001",
        domain="network_browser",
        objective=(
            "Investigate why this browser cannot open a site while the host is otherwise usable"
        ),
        source_summaries=(
            "Browser route and settings sample",
            "Host processor sample",
            "Direct external connection sample",
            "Browser resolver sample",
        ),
        source_facts=(
            {
                "affected_browser_task": "open synthetic site item in this browser profile",
                "browser_route_result": "timeout",
                "direct_same_origin_result": "reachable",
                "proxy_enabled": True,
                "proxy_endpoint": "127.0.0.1:9",
            },
            {"cpu_peak_percent": 92, "duration_ms": 50},
            {"direct_external_https": "reachable"},
            {"resolver_mode": "automatic"},
        ),
    ),
    SourceCaseV1(
        case_key="source-application-performance-001",
        domain="application_performance",
        objective="Investigate why a document viewer is slow while other applications respond",
        source_summaries=(
            "Document viewer phase timing sample",
            "Storage status sample",
            "Independent document source sample",
            "Host resource sample",
        ),
        source_facts=(
            {
                "affected_viewer_task": "open synthetic document item in the viewer",
                "open_to_interactive_ms": 480,
                "viewer_render_p95_ms": 430,
                "external_fetch_p95_ms": 40,
            },
            {"storage_warning_count": 1, "current_queue_length": 0},
            {"independent_document_open_ms": 35},
            {"host_cpu_p95_percent": 24},
        ),
    ),
)


def _evidence_id(index: int) -> EvidenceId:
    return EvidenceId(root=f"ev_{index:032x}")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _source_sha(path: Path) -> str:
    """Hash code with normalized line endings for cross-worktree readback."""

    normalized = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _git_head() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=Path(__file__).resolve().parent,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return result.stdout.strip() if result.returncode == 0 else None


class ScriptedSourceRanker(MixedFrontierRanker):
    """Select one ordinal for reachability, without inspecting facts or labels."""

    def __init__(self, source_ordinal: Literal[0, 1]) -> None:
        super().__init__(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="scripted-source-frontier-v1",
                provider_version="1",
                role="fast_decision",
            ),
            model_weight_sha256="a" * 64,
        )
        self.source_ordinal = source_ordinal
        self.requests: list[FrontierRankRequestV1] = []
        self.responses: list[FrontierRankResponseV1] = []

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Any = None,
    ) -> FrontierRankResponseV1:
        self.requests.append(request)
        source_items = [
            item for item in request.items if item.reference.kind == "retrieve_evidence"
        ]
        if len(source_items) < 2:
            raise ValueError("fixture did not reach two source-backed alternatives")
        selected = source_items[self.source_ordinal].item_id
        offered = tuple(item.item_id for item in request.items)
        fallback = super().rank(request, capture_worker_batch=capture_worker_batch)
        response = fallback.model_copy(
            update={
                "ranked_item_ids": (selected, *(item for item in offered if item != selected)),
                "considered_item_ids": offered,
                "ranking_source": "laya",  # The runtime's accepted advisory response shape.
                "model_abstained": False,
                "coverage_complete": True,
                "degraded_reason": None,
            }
        ).validate_against(request)
        self.responses.append(response)
        return response


def _app(store: SQLiteStore, ranker: ScriptedSourceRanker) -> Investigator:
    return Investigator(
        store=store,
        runtime=DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, DeterministicPlanner(candidates=())),
            probe_runner=ProbeRunner(definitions=()),
        ),
        capabilities=(),
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
        knowledge=ReferenceKnowledgeGraph.load_default(),
        frontier_ranker=ranker,
    )


def _seed_sources(store: SQLiteStore, case_id: CaseId, spec: SourceCaseV1) -> None:
    observed = utc_now()
    for index in range(1, 53):
        summary = (
            f"Background source record {index}"
            if index <= 48
            else spec.source_summaries[index - 49]
        )
        facts: dict[str, JsonValue] = (
            {"background_index": index} if index <= 48 else spec.source_facts[index - 49]
        )
        evidence_id = _evidence_id(index)
        execution_id = ExecutionId(root=f"exec_{index:032x}")
        source_id = stable_source_id(
            "fixture.scripted.source", {"domain": spec.domain, "source_index": index}
        )
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=observed,
            captured_at=observed,
            source=EvidenceSource(
                type="fixture.scripted.source",
                source_id=source_id,
                locator={"domain": spec.domain, "source_index": index},
            ),
            collector=CollectorReference(
                id=f"fixture.{spec.domain}", version=1, execution_id=execution_id
            ),
            summary=summary,
            facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
            extraction=Extraction(confidence=1.0, parser="fixture.scripted", parser_version=1),
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=source_id,
                record_json=record.model_dump_json(),
                observed_at=observed.isoformat(),
                captured_at=observed.isoformat(),
                time_basis="source_observed",
                time_quality="exact",
            )


def _run_cell(database: Path, spec: SourceCaseV1, ordinal: Literal[0, 1]) -> dict[str, Any]:
    cell_started = time.perf_counter()
    with SQLiteStore(database) as store:
        ranker = ScriptedSourceRanker(ordinal)
        app = _app(store, ranker)
        state = app.create(objective=spec.objective, budget_ms=30_000, max_rounds=1)
        _seed_sources(store, state.case_id, spec)
        seeded_attempts = int(
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=?", (str(state.case_id),)
            ).fetchone()[0]
        )
        if seeded_attempts:
            raise ValueError("preexisting source fixture consumed investigation probes")
        before = app.context(str(state.case_id))
        if len(before) != 48 or any(
            str(_evidence_id(index)) in {str(item.evidence_id) for item in before}
            for index in range(49, 53)
        ):
            raise ValueError("fixture source visibility changed")
        generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        frontier = SearchFrontierRepository(store)
        with store.transaction():
            event = frontier.append_result_event(
                state.case_id,
                source_evidence_id=_evidence_id(1),
                source_execution_id=None,
                versions=RelevantVersionsV1(objective=1, evidence=generation),
            )
        if not isinstance(event, FrontierEventV1):
            raise ValueError("fixture source event was not admitted")
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "started",
            "Read-only synthetic frontier fixture started.",
        )
        owner_version = state.state_version
        page_durations_ms: list[float] = []
        for _ in range(8):
            page_started = time.perf_counter()
            state, _, _ = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
                state, app.context(str(state.case_id)), owner_version
            )
            page_durations_ms.append(round((time.perf_counter() - page_started) * 1000, 3))
            if ranker.requests:
                break
        time_to_menu_ms = round(sum(page_durations_ms), 3)
        if len(ranker.requests) != 1 or len(ranker.responses) != 1:
            raise ValueError("fixture did not reach one source-backed frontier decision")
        request = ranker.requests[0]
        source_items = [
            item for item in request.items if item.reference.kind == "retrieve_evidence"
        ]
        source_ids = [str(item.reference.evidence_id) for item in source_items]
        if source_ids != [str(_evidence_id(index)) for index in range(49, 53)]:
            raise ValueError("fixture source menu changed")
        if any(
            fact in _canonical(request.model_dump(mode="json")).decode("utf-8")
            for fact in (
                "127.0.0.1:9",
                "viewer_render_p95_ms",
                "cpu_peak_percent",
                "storage_warning_count",
            )
        ):
            raise ValueError("hidden source result leaked into the ranking request")
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        selected_id = _evidence_id(49 + ordinal)
        reloaded = InvestigationRepository(store).load(str(state.case_id))
        calls = [
            call
            for call in reloaded.provider_calls
            if call.provider_id == "scripted-source-frontier-v1"
            and call.role == "catalog_attention"
            and not call.degraded
            and call.detail == "event_frontier_retrieval"
        ]
        offered = set(turns[-1].offered_item_ids)
        if (
            len(offered) != 4
            or not all(item.item_id in offered for item in source_items)
            or len(calls) != 1
            or calls[0].state_version != turns[-1].expected_checkpoint_version
            or selected_id not in reloaded.fast_catalog_selected_ids
        ):
            raise ValueError("source menu, selected item, or durable provider call mismatch")
        selected_row = store.evidence(case_id=str(state.case_id), evidence_id=str(selected_id))
        if selected_row is None:
            raise ValueError("selected source record missing")
        selected_record = EvidenceRecord.model_validate_json(selected_row.record_json)
        return {
            "case_key": spec.case_key,
            "domain": spec.domain,
            "policy": f"scripted_ordinal_{ordinal}",
            "classification": "synthetic_mechanics_only",
            "case_id": str(state.case_id),
            "state_version": calls[0].state_version,
            "event_id": event.event_id,
            "source_menu_evidence_ids": source_ids,
            "source_menu_item_ids": [item.item_id for item in source_items],
            "source_menu_semantics": [
                item.model_dump(mode="json") for item in request.item_semantics
            ],
            "rank_request": request.model_dump(mode="json"),
            "rank_response": ranker.responses[0].model_dump(mode="json"),
            "rank_request_sha256": _sha(request.model_dump(mode="json")),
            "selected_evidence_id": str(selected_id),
            "selected_facts": {fact.name: fact.value for fact in selected_record.facts},
            "provider_call": calls[0].model_dump(mode="json"),
            "frontier_offer_counts": _frontier_offer_counts(store, str(state.case_id)),
            "no_new_fact_pages_before_offer": len(turns) - 1,
            "seeded_probe_attempts": seeded_attempts,
            "no_new_fact_page_ms": round(sum(page_durations_ms[:-1]), 3),
            "time_to_first_menu_ms": time_to_menu_ms,
            "total_cell_ms": round((time.perf_counter() - cell_started) * 1000, 3),
            "database_sha256": "pending_after_close",
        }


def run_cpu_reachability(output_dir: Path) -> dict[str, Any]:
    """Produce four independent, reset synthetic cells and sealed post-run review."""

    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "cases").mkdir()
    (output_dir / "evaluator-only").mkdir()
    protocol = {
        "schema_version": 1,
        "classification": "synthetic_mechanics_only",
        "execution_entrypoint": "direct_investigator_event_frontier_turn_cpu_reachability",
        "ordinary_full_run_reachability": "ranker_reached_in_separate_registered_probe_prototype",
        "ordinary_full_run_target_menu": "not_matched_in_that_prototype",
        "timing_clock": {
            "name": "perf_counter",
            "implementation": time.get_clock_info("perf_counter").implementation,
            "resolution_seconds": time.get_clock_info("perf_counter").resolution,
            "scope": "synthetic_cpu_paging_only",
        },
        "source_count_per_case": 52,
        "source_capture_class": "preexisting_synthetic_source_not_probe_attempts",
        "visible_context_limit_observed": 48,
        "expected_no_new_fact_pages_before_offer": 6,
        "no_new_fact_pages_are_accounted": True,
        "planned_model_arms": "unrun",
        "first_request_parity": "unknown",
        "model_budget_enforced": False,
        "affected_task_bound": False,
        "synthetic_task_scope": "bound_to_scripted_fact_only",
        "representativeness": "catalog_paging_stress_not_ordinary_task_latency",
        "cases": [
            {
                "case_key": spec.case_key,
                "domain": spec.domain,
                "objective": spec.objective,
                "source_summaries": spec.source_summaries,
                "source_observation_digest": _sha(spec.source_facts),
            }
            for spec in _CASES
        ],
    }
    (output_dir / "protocol.json").write_bytes(_canonical(protocol))
    cells: list[dict[str, Any]] = []
    for spec in _CASES:
        for ordinal in (0, 1):
            database = output_dir / "cases" / f"{spec.case_key}-scripted-{ordinal}.db"
            cell = _run_cell(database, spec, ordinal)
            cell["database_sha256"] = hashlib.sha256(database.read_bytes()).hexdigest()
            cells.append(cell)
    (output_dir / "attempts.json").write_bytes(_canonical({"schema_version": 1, "cells": cells}))
    # The oracle is imported only after all scripted provider calls complete.
    from benchmarks.source_backed_frontier_oracle import review_cells

    reviews = review_cells(cells)
    (output_dir / "evaluator-only" / "reviews.json").write_bytes(_canonical(reviews))
    files = [
        "protocol.json",
        "attempts.json",
        "evaluator-only/reviews.json",
        *(f"cases/{spec.case_key}-scripted-{ordinal}.db" for spec in _CASES for ordinal in (0, 1)),
    ]
    manifest = {
        "schema_version": 1,
        "classification": "synthetic_mechanics_only",
        "protocol_digest": _sha(protocol),
        "runner_git_sha": _git_head(),
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
        "source_menus": sum(len(cell["source_menu_evidence_ids"]) == 4 for cell in cells),
        "comparison_admissible": False,
        "protocol_digest": manifest["protocol_digest"],
    }


def verify_cpu_reachability(output_dir: Path) -> dict[str, Any]:
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    from benchmarks.source_backed_frontier_oracle import review_cells

    current_source = {
        "runner": _source_sha(Path(__file__).resolve()),
        "oracle": _source_sha(Path(inspect.getfile(review_cells)).resolve()),
        "runtime_investigator": _source_sha(Path(inspect.getfile(Investigator)).resolve()),
    }
    if current_source != manifest["source_sha256_normalized"]:
        raise ValueError("artifact source revision mismatch")
    for name, digest in manifest["files"].items():
        if hashlib.sha256((output_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"artifact hash mismatch: {name}")
    attempts = json.loads((output_dir / "attempts.json").read_text(encoding="utf-8"))
    cells = attempts["cells"]
    if len(cells) != 4 or any(len(cell["source_menu_evidence_ids"]) != 4 for cell in cells):
        raise ValueError("source-backed pilot cells or menus are incomplete")
    return {"integrity_verified": True, "cells": len(cells), "comparison_admissible": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    result = (
        verify_cpu_reachability(args.output_dir)
        if args.verify
        else run_cpu_reachability(args.output_dir)
    )
    print(json.dumps(result, sort_keys=True))
