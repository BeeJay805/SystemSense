"""One owned Laya/Qwen run on the existing source-bound synthetic fixture.

This records actual model choices and their durable execution links. It is not
a matched policy comparison, Windows observation, or causal accuracy score.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from benchmarks.actual_model_full_loop import (
    _BUDGET_MS,  # pyright: ignore[reportPrivateUsage]
    _FOLLOWUP,  # pyright: ignore[reportPrivateUsage]
    _error_category,  # pyright: ignore[reportPrivateUsage]
    _sha,  # pyright: ignore[reportPrivateUsage]
    _TracedReasoner,  # pyright: ignore[reportPrivateUsage]
    _write,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_frontier_pilot import (
    _CASES,  # pyright: ignore[reportPrivateUsage]
    _evidence_id,  # pyright: ignore[reportPrivateUsage]
    _git_head,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_full_run import (
    _app,  # pyright: ignore[reportPrivateUsage]
    _checkpoint,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_task_relation_red import (
    _WORLD_FACTS,  # pyright: ignore[reportPrivateUsage]
    _seed,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRanker,
    FrontierRankRequestV1,
    FrontierRankResponseV1,
)
from systemsense.domain.ids import CaseId
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.inference.factory import AdvisoryProviders, load_warm_v4_providers
from systemsense.inference.host_lease import LeaseBudget
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.inference.profile import load_inference_profile
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger
from systemsense.storage.search_frontier import RelevantVersionsV1, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore


class _CaptureRanker:
    """Record only bounded ranking outcomes; preserve the production policy."""

    def __init__(self, inner: FrontierRanker) -> None:
        self.inner = inner
        self.outcomes: list[dict[str, Any]] = []

    @property
    def provider(self) -> ProviderIdentity:
        return self.inner.provider

    @property
    def model_weight_sha256(self) -> str:
        return self.inner.model_weight_sha256

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        response = self.inner.rank(request, capture_worker_batch=capture_worker_batch)
        self.outcomes.append(
            {
                "offered_kinds": [item.reference.kind for item in request.items],
                "ranking_source": response.ranking_source,
                "degraded_reason": response.degraded_reason,
                "attention_notes": response.attention_notes,
                "selected_kind": next(
                    (
                        item.reference.kind
                        for item in request.items
                        if item.item_id == response.ranked_item_ids[0]
                    ),
                    None,
                ),
            }
        )
        return response


def run(output_dir: Path, *, profile_path: Path, outcome_file: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    if outcome_file.stat().st_size > 32:
        raise ValueError("synthetic outcome file exceeds bounded value length")
    followup_value = outcome_file.read_text(encoding="ascii").strip()
    if followup_value not in {"online", "offline"}:
        raise ValueError("synthetic outcome must be one registered categorical value")
    profile = load_inference_profile(profile_path.resolve())
    resources, pin = profile.managed_resources, profile.managed_reasoning
    if resources is None or pin is None or profile.investigation_budget_ms != _BUDGET_MS:
        raise ValueError("expected pinned warm profile with 180-second case budget")
    ledger = TreeHostInferenceLeaseLedger(
        (Path(os.environ["LOCALAPPDATA"]) / "SystemSense" / "host-gpu-lease-v3.sqlite3").resolve(),
        LeaseBudget(
            cpu_slots=2,
            ram_bytes=resources.peak_ram_bytes + pin.peak_ram_bytes,
            vram_bytes=resources.peak_vram_bytes + pin.peak_vram_bytes,
            gpu_device_index=resources.gpu_device_index,
        ),
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "code_head": _git_head(),
        "started_at": datetime.now(UTC).isoformat(),
        "profile_sha256": _sha(profile_path),
        "runner_sha256": _sha(Path(__file__)),
        "fixture_sha256": {
            "source_backed_full_run": _sha(Path(__file__).with_name("source_backed_full_run.py")),
            "source_task_relation_red": _sha(
                Path(__file__).with_name("source_task_relation_red.py")
            ),
            "advisory_validation_boundary": _sha(
                Path(__file__).with_name("advisory_validation_boundary.py")
            ),
        },
        "fast_model_weight_sha256": None,
        "deep_model": pin.model,
        "deep_model_digest": pin.model_digest,
        "case_budget_ms": _BUDGET_MS,
        "fixture_scope": "synthetic_network_browser_one_cell",
        "policy": "owned_warm_laya_plus_qwen",
        "scout_prefetch": False,
        "hidden_followup_value": "evaluator_only",
    }
    providers: AdvisoryProviders | None = None
    tracer: _TracedReasoner | None = None
    try:
        if ledger.migrate_from_v3() != "migrated":
            raise RuntimeError("host lease migration unavailable")
        providers = load_warm_v4_providers(profile, ledger)
        warm_started = time.perf_counter()
        providers.prewarm_laya(timeout_seconds=profile.laya.timeout_seconds)
        manifest["fast_prewarm_elapsed_ms"] = round((time.perf_counter() - warm_started) * 1000, 3)
        assert providers.frontier_ranker is not None
        manifest["fast_model_weight_sha256"] = providers.frontier_ranker.model_weight_sha256
        manifest["fast_provider"] = providers.decision.identity.model_dump(mode="json")
        manifest["deep_provider"] = providers.reasoning.identity.model_dump(mode="json")
        tracer = _TracedReasoner(
            providers, initial_request_path=output_dir / "policy-visible" / "initial-request.json"
        )
        spec = next(item for item in _CASES if item.domain == "network_browser")
        checkpoint_path = output_dir / "checkpoint.db"
        checkpoint = _checkpoint(checkpoint_path, spec, case_budget_ms=_BUDGET_MS)
        case_id = CaseId(root=str(checkpoint["case_id"]))
        database = output_dir / "case.db"
        shutil.copyfile(checkpoint_path, database)
        with SQLiteStore(database) as store:
            _seed(
                store,
                case_id,
                spec.domain,
                checkpoint["task_observation"],
                _evidence_id(49),
                _WORLD_FACTS["network_browser"][0][1],
            )
            catalog = EvidenceRetriever(store).discover(
                EvidenceCatalogQuery(case_id=case_id, limit=64)
            )
            app = _app(store, spec, None, followup_direct_status=followup_value)
            app.decision = providers.decision
            app.reasoning = tracer
            app.knowledge = providers.knowledge
            app.catalog_attention = providers.catalog_attention
            capture_ranker = _CaptureRanker(providers.frontier_ranker)
            app.frontier_ranker = capture_ranker
            app.enable_scout_prefetch = False
            with store.transaction():
                SearchFrontierRepository(store).append_result_event(
                    case_id,
                    source_evidence_id=_evidence_id(48),
                    source_execution_id=None,
                    versions=RelevantVersionsV1(
                        objective=1, evidence=catalog.case_evidence_generation
                    ),
                )
            started = time.perf_counter()
            state = app.run(str(case_id))
            manifest["app_run_elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
            candidate_snapshots = [
                {
                    "snapshot_id": row[0],
                    "request": json.loads(str(row[1])),
                    "response": json.loads(str(row[2])),
                }
                for row in store.connection.execute(
                    "SELECT snapshot_id,request_json,response_json "
                    "FROM candidate_decision_snapshots "
                    "WHERE case_id=? ORDER BY request_frozen_at LIMIT 128",
                    (str(case_id),),
                )
            ]
            execution_links = [
                {
                    "snapshot_id": row[0],
                    "candidate_id": row[1],
                    "execution_id": row[2],
                    "epoch_state_version": row[3],
                }
                for row in store.connection.execute(
                    "SELECT snapshot_id,candidate_id,execution_id,epoch_state_version "
                    "FROM candidate_decision_execution_links WHERE case_id=?",
                    (str(case_id),),
                )
            ]
            followup_executions = [
                {
                    "execution_id": row[0],
                    "probe_version": row[1],
                    "status": row[2],
                    "started_at": row[3],
                    "finished_at": row[4],
                    "followup_admission_id": row[5],
                }
                for row in store.connection.execute(
                    "SELECT execution_id,probe_version,status,started_at,finished_at,"
                    "followup_admission_id FROM probe_executions "
                    "WHERE case_id=? AND probe_id=?",
                    (str(case_id), _FOLLOWUP),
                )
            ]
            followup_records = [
                json.loads(str(row[0]))
                for row in store.connection.execute(
                    "SELECT record_json FROM evidence WHERE case_id=? AND "
                    "json_extract(record_json,'$.collector.id')=?",
                    (str(case_id), _FOLLOWUP),
                )
            ]
            deep_mailbox = [
                {"request_sha256": row[0], "status": row[1], "created_at": row[2]}
                for row in store.connection.execute(
                    "SELECT request_sha256,status,created_at FROM deep_mailbox WHERE case_id=? "
                    "ORDER BY created_at",
                    (str(case_id),),
                )
            ]
            private = {
                "candidate_snapshots": candidate_snapshots,
                "candidate_execution_links": execution_links,
                "followup_executions": followup_executions,
                "followup_records": followup_records,
                "deep_mailbox": deep_mailbox,
                "provider_exchanges": [
                    {
                        "request": request.model_dump(mode="json"),
                        "response": response.model_dump(mode="json"),
                    }
                    for request, response in tracer.exchanges
                ],
                "provider_calls": [call.model_dump(mode="json") for call in state.provider_calls],
                "frontier_rank_outcomes": capture_ranker.outcomes,
                "terminal_status": state.status.value,
                "terminal_outcome": state.outcome.value,
                "terminal_assessment": (
                    state.assessment.model_dump(mode="json")
                    if state.assessment is not None
                    else None
                ),
                "terminal_summary": state.summary,
            }
            manifest.update(
                {
                    "status": "completed",
                    "case_database_sha256": _sha(database),
                    "checkpoint_sha256": _sha(checkpoint_path),
                    "evaluator_only_sha256": _write(
                        output_dir / "evaluator-only" / "readback.json", private
                    ),
                    "fast_candidate_snapshots": len(candidate_snapshots),
                    "candidate_execution_links": len(execution_links),
                    "followup_executions": len(followup_executions),
                    "deep_requests": len(tracer.exchanges),
                    "deep_model_returns_or_failures": len(tracer.receipts),
                    "terminal_outcome": state.outcome.value,
                }
            )
    except Exception as error:
        manifest.update({"status": "failed", "error_category": _error_category(error)})
    finally:
        if providers is not None:
            try:
                providers.close()
                manifest["provider_close"] = "returned"
            except Exception as error:
                manifest["provider_close"] = _error_category(error)
                manifest["status"] = "failed"
        if tracer is not None:
            manifest["deep_model_call_receipts"] = tracer.receipts
            manifest["deep_requests"] = len(tracer.exchanges)
        initial = output_dir / "policy-visible" / "initial-request.json"
        if initial.exists():
            manifest["initial_request_sha256"] = _sha(initial)
        manifest["finished_at"] = datetime.now(UTC).isoformat()
        _write(output_dir / "manifest.json", manifest)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--profile", type=Path, default=Path("examples/warm-local-development.profile.json")
    )
    parser.add_argument("--outcome-file", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output_dir, profile_path=args.profile, outcome_file=args.outcome_file)
    print(json.dumps(result, sort_keys=True))
    if result["status"] != "completed":
        raise SystemExit(2)
