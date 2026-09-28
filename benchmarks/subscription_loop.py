"""Explicit synthetic Laya/Codex trial; custody checks are not semantic grading."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from benchmarks.real_mixed_trace import trace_case
from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.cli import _v4_providers  # pyright: ignore[reportPrivateUsage]
from systemsense.decision.contracts import ProbeCapability
from systemsense.inference.codex import CodexInferenceConfig, CodexJsonClient
from systemsense.inference.profile import load_inference_profile
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.orchestration.probes import ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.codex import CodexReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_conflicting_frontier_redirection import (
    _high_pressure_source,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_live_counterevidence_overlap import (
    _hide_until_focused,  # pyright: ignore[reportPrivateUsage]
    _seed_deferred_related_evidence,  # pyright: ignore[reportPrivateUsage]
    _synthetic_definitions,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.application import test_general_candidate_catalog as catalog_fixtures
from tests.unit.application.test_general_candidate_catalog import (
    _gpu_source,  # pyright: ignore[reportPrivateUsage]
)


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str), encoding="utf-8")


class CapturingCodexClient(CodexJsonClient):
    """Retain exact adapter input and returned JSON before provider validation."""

    def __init__(self, config: CodexInferenceConfig, directory: Path) -> None:
        super().__init__(config)
        self.directory = directory
        self.calls = 0

    def complete(
        self, *, model: str, prompt: str, schema: Mapping[str, object], timeout_seconds: float
    ) -> dict[str, object]:
        self.calls += 1
        prefix = self.directory / f"codex-{self.calls:03d}"
        prefix.with_suffix(".prompt.txt").write_text(prompt, encoding="utf-8")
        _write(prefix.with_suffix(".schema.json"), schema)
        _write(
            prefix.with_suffix(".request.json"),
            {
                "model": model,
                "timeout_seconds": timeout_seconds,
                "started_at": datetime.now(UTC).isoformat(),
            },
        )
        try:
            result = super().complete(
                model=model, prompt=prompt, schema=schema, timeout_seconds=timeout_seconds
            )
        except Exception as error:
            _write(prefix.with_suffix(".failure.json"), {"error": str(error)})
            _write(prefix.with_suffix(".runtime.json"), self.last_runtime)
            raise
        _write(prefix.with_suffix(".raw-return.json"), result)
        _write(prefix.with_suffix(".runtime.json"), self.last_runtime)
        return result


def score_custody(artifact: dict[str, Any]) -> dict[str, Any]:
    """Require a real model selection -> execution -> later accepted citation.

    A missing-evidence citation is ID-bound, but interpreting its explanation
    remains a separate human/independent-model review. Mere considered IDs fail.
    """
    links: list[dict[str, Any]] = []
    for snapshot in artifact["snapshots"]:
        request, response = snapshot["request"], snapshot["response"]
        ranked = response.get("ranked_item_ids", [])
        if (
            response.get("ranking_source") != "laya"
            or response.get("degraded_reason")
            or not ranked
        ):
            continue
        selected = next((item for item in request["items"] if item["item_id"] == ranked[0]), None)
        if selected is None or selected["reference"]["kind"] != "measure":
            continue
        for execution in artifact["executions"]:
            if (
                execution["snapshot_id"] != snapshot["snapshot_id"]
                or execution["candidate_id"] != selected["reference"]["candidate_id"]
                or execution["finished_at"] is None
                or execution.get("status") != "ok"
            ):
                continue
            observation_ids = set(execution["evidence_ids"])
            if not observation_ids:
                continue
            for mailbox in artifact["mailbox"]:
                result = cast(dict[str, Any], mailbox.get("result") or {})
                response = cast(dict[str, Any], result.get("response") or {})
                if (
                    mailbox["status"] != "applied"
                    or response.get("degraded", True)
                    or response.get("provider", {}).get("provider_id")
                    != "codex-subscription-reasoning"
                    or datetime.fromisoformat(mailbox["created_at"])
                    <= datetime.fromisoformat(execution["finished_at"])
                ):
                    continue
                deep_request = mailbox["task"]["request"]
                shown_observations = {
                    item["evidence_id"]
                    for item in deep_request.get("evidence_context", [])
                    if item.get("status") == "observed"
                }
                supplied = (
                    set(deep_request["evidence_ids"])
                    & shown_observations
                    & set(response.get("considered_evidence_ids", []))
                )
                summary = str(response.get("summary", ""))
                summary_lower = summary.casefold()
                explicit_missing = any(
                    word in summary_lower
                    for word in (
                        "missing",
                        "unobserved",
                        "insufficient",
                        "unknown",
                        "not establish",
                        "not confirm",
                    )
                ) and any(word in summary_lower for word in ("target", "time", "window", "task"))
                if explicit_missing:
                    bound_ids = sorted(
                        item
                        for item in observation_ids & supplied
                        if re.search(r"(?<![\w-])" + re.escape(item) + r"(?![\w-])", summary)
                    )
                    if bound_ids:
                        links.append(
                            {
                                "selected_item_id": selected["item_id"],
                                "snapshot_id": snapshot["snapshot_id"],
                                "admission_id": execution["admission_id"],
                                "execution_id": execution["execution_id"],
                                "request_sha256": mailbox["request_sha256"],
                                "citation_field": "summary_missing_target_or_time_lexical_match",
                                "evidence_ids": bound_ids,
                            }
                        )
                for hypothesis in response.get("hypotheses", []):
                    for field in (
                        "supporting_evidence_ids",
                        "contradicting_evidence_ids",
                        "missing_evidence_ids",
                    ):
                        cited = observation_ids & supplied & set(hypothesis.get(field, []))
                        if cited:
                            links.append(
                                {
                                    "selected_item_id": selected["item_id"],
                                    "snapshot_id": snapshot["snapshot_id"],
                                    "admission_id": execution["admission_id"],
                                    "execution_id": execution["execution_id"],
                                    "request_sha256": mailbox["request_sha256"],
                                    "hypothesis_id": hypothesis["hypothesis_id"],
                                    "citation_field": field,
                                    "evidence_ids": sorted(cited),
                                }
                            )
    return {
        "mechanical_pass": bool(links),
        "semantic_correctness": "not_evaluated",
        "selection_execution_later_response_links": links,
        "scope": "measurement selection only; retrieval-only runs do not pass this gate",
    }


def collect_artifact(store: SQLiteStore, case_id: str) -> dict[str, Any]:
    connection = store.connection
    snapshots = [
        {"snapshot_id": row[0], "request": json.loads(row[1]), "response": json.loads(row[2])}
        for row in connection.execute(
            "SELECT snapshot_id,request_json,response_json FROM candidate_decision_snapshots "
            "WHERE case_id=? ORDER BY captured_at",
            (case_id,),
        )
    ]
    mailbox = [
        {
            "request_sha256": row[0],
            "status": row[1],
            "created_at": row[2],
            "updated_at": row[3],
            "reason": row[4],
            "task": json.loads(row[5]),
            "result": None if row[6] is None else json.loads(row[6]),
        }
        for row in connection.execute(
            "SELECT request_sha256,status,created_at,updated_at,reason,task_json,result_json "
            "FROM deep_mailbox WHERE case_id=? ORDER BY created_at",
            (case_id,),
        )
    ]
    executions = [
        {
            "admission_id": row[0],
            "snapshot_id": row[1],
            "candidate_id": row[2],
            "execution_id": row[3],
            "finished_at": row[4],
            "status": row[5],
            "evidence_ids": [
                item[0]
                for item in connection.execute(
                    "SELECT evidence_id FROM evidence WHERE case_id=? AND execution_id=?",
                    (case_id, row[3]),
                )
            ],
        }
        for row in connection.execute(
            "SELECT a.admission_id,a.snapshot_id,a.candidate_id,l.execution_id,"
            "x.finished_at,x.status FROM candidate_dispatch_admissions a "
            "JOIN candidate_decision_execution_links l ON l.snapshot_id=a.snapshot_id "
            "AND l.candidate_id=a.candidate_id "
            "JOIN probe_executions x ON x.execution_id=l.execution_id WHERE a.case_id=?",
            (case_id,),
        )
    ]
    return {
        "case_id": case_id,
        "snapshots": snapshots,
        "mailbox": mailbox,
        "executions": executions,
    }


def run_trial(
    *, executable: Path, artifact_directory: Path, budget_seconds: int = 180
) -> dict[str, Any]:
    """Explicit operator entrypoint. Does not start managed Qwen or host probes."""
    if not 1 <= budget_seconds <= 180:
        raise ValueError("case budget must be between 1 and 180 seconds")
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("an explicit existing absolute Codex executable path is required")
    artifact_directory.mkdir(parents=True, exist_ok=False)
    config = CodexInferenceConfig(
        enabled=True, executable=executable, timeout_seconds=budget_seconds
    )
    client = CapturingCodexClient(config, artifact_directory)
    profile = load_inference_profile(
        Path(__file__).resolve().parents[1] / "examples/warm-local-development.profile.json"
    )
    if profile.schema_version != 4 or profile.runtime_strategy != "warm-independent":
        raise ValueError("trial requires the pinned warm-independent v4 Laya profile")
    providers = _v4_providers(profile)  # Warm only Laya; Qwen role reservation is not execution.
    database = artifact_directory / "case.db"
    try:
        with SQLiteStore(database) as store, pytest.MonkeyPatch.context() as patch:
            patch.setattr(catalog_fixtures, "NOW", datetime.now(UTC))
            definitions = _synthetic_definitions()
            app = Investigator(
                store=store,
                runtime=DiagnosticRuntime(
                    store=store,
                    case_service=CaseService(store, DeterministicPlanner(candidates=())),
                    probe_runner=ProbeRunner(definitions=definitions),
                ),
                capabilities=tuple(
                    ProbeCapability(
                        probe_id=item.manifest.probe_id,
                        description=item.manifest.question,
                        common=True,
                        cost_ms=1,
                        resource_class=ResourceClass.CPU,
                    )
                    for item in definitions
                    if item.manifest.probe_id in {"core.system", "core.resources"}
                ),
                decision=providers.decision,
                reasoning=CodexReasoningProvider(config, client=client),
                knowledge=providers.knowledge,
                frontier_ranker=providers.frontier_ranker,
                capture_frontier_worker_inputs=False,
            )
            case = app.create(
                objective="Game runs slowly despite a capable GPU",
                budget_ms=budget_seconds * 1000,
                max_probes=8,
                max_rounds=6,
            )
            _gpu_source(store, case.case_id, age_seconds=0.5, epoch=case.state_version)
            _high_pressure_source(store, case.case_id, case.state_version)
            deferred = _seed_deferred_related_evidence(store, case.case_id)
            _hide_until_focused(app, case.case_id, deferred, patch)
            try:
                final = app.run(str(case.case_id))
                _write(artifact_directory / "final.json", final.model_dump(mode="json"))
            finally:
                artifact = collect_artifact(store, str(case.case_id))
                artifact["runtime"] = {
                    "codex": client.last_runtime,
                    "codex_calls": client.calls,
                    "reasoning_route": "codex-subscription-reasoning",
                    "profile_id": profile.profile_id,
                }
                _write(artifact_directory / "custody.json", artifact)
                _write(artifact_directory / "trace.json", trace_case(database, str(case.case_id)))
                score = score_custody(artifact)
                _write(artifact_directory / "score.json", score)
            return score
    finally:
        providers.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-executable", type=Path, required=True)
    parser.add_argument("--artifact-directory", type=Path, required=True)
    parser.add_argument("--budget-seconds", type=int, default=180)
    args = parser.parse_args()
    score = run_trial(
        executable=args.codex_executable,
        artifact_directory=args.artifact_directory,
        budget_seconds=args.budget_seconds,
    )
    print(json.dumps(score, sort_keys=True))
    raise SystemExit(0 if score["mechanical_pass"] else 1)


if __name__ == "__main__":
    main()
