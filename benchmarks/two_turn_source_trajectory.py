"""One CPU-only source -> prediction -> new probe -> counterevidence trajectory.

This is a scripted provider and synthetic observation, not model or Windows evidence.
The provider sees ReasoningRequest only; the later fixture value is supplied to
the registered probe handler and is absent from its first request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from benchmarks.postretrieval_advisory_pilot import (
    ScriptedPostretrievalReasoner,
    _family,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_frontier_pilot import (
    _git_head,  # pyright: ignore[reportPrivateUsage]
    _source_sha,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_task_relation_red import run_balanced_relation_probe
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal, ProviderIdentity
from systemsense.domain.ids import EvidenceId
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import (
    ExpectedFact,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.sqlite_store import SQLiteStore

_FOLLOWUP = "fixture.direct_origin_after_source"


class TwoTurnReasoner(ScriptedPostretrievalReasoner):
    """Predict opposing outcomes before a registered follow-up is executed."""

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="scripted-two-turn-advisory",
            provider_version="1",
            role="reasoning",
        )

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        response = super().investigate(request)
        if _family(request) != "network_browser":
            return response
        followup = next(
            (item for item in request.evidence_context if item.probe_id == _FOLLOWUP), None
        )
        if (
            followup is not None
            and followup.facts.get("direct_origin_status") in {"online", "offline"}
            and any(hypothesis.expected_facts for hypothesis in request.previous_hypotheses)
        ):
            observed = followup.facts["direct_origin_status"]
            revised: list[Hypothesis] = []
            for hypothesis in request.previous_hypotheses:
                expected = next(
                    (
                        fact.expected_value
                        for fact in hypothesis.expected_facts
                        if fact.probe_id == _FOLLOWUP and fact.fact_name == "direct_origin_status"
                    ),
                    None,
                )
                if expected is None:
                    continue
                contradicted = observed != expected
                revised.append(
                    hypothesis.model_copy(
                        update={
                            "status": HypothesisStatus.CONTESTED
                            if contradicted
                            else HypothesisStatus.UNRESOLVED,
                            "supporting_evidence_ids": ()
                            if contradicted
                            else (followup.evidence_id,),
                            "contradicting_evidence_ids": (followup.evidence_id,)
                            if contradicted
                            else (),
                            "missing_evidence_ids": (),
                            "expected_facts": (),
                            "expected_facts_observed_after": None,
                        }
                    )
                )
            response = response.model_copy(
                update={
                    "summary": (
                        "The later direct-origin observation contests one prospective "
                        "prediction; the rivals remain unresolved."
                    ),
                    "status": ReasoningStatus.UNRESOLVED,
                    "hypotheses": tuple(revised),
                    "considered_evidence_ids": (followup.evidence_id,),
                }
            )
        elif (
            followup is None
            and _FOLLOWUP not in request.completed_probe_ids
            and response.considered_evidence_ids
        ):
            if _FOLLOWUP not in {probe.probe_id for probe in request.available_probes}:
                return response
            rivals = tuple(
                hypothesis.model_copy(
                    update={
                        "distinguishing_probe_ids": (_FOLLOWUP,),
                        "expected_facts": (
                            ExpectedFact(
                                probe_id=_FOLLOWUP,
                                fact_name="direct_origin_status",
                                expected_value="online" if index == 0 else "offline",
                            ),
                        ),
                    }
                )
                for index, hypothesis in enumerate(response.hypotheses)
            )
            response = response.model_copy(
                update={
                    "summary": (
                        "The cited task-window source suggests rivals; a fresh direct-origin "
                        "measurement will discriminate them, and neither is proven."
                    ),
                    "hypotheses": rivals,
                    "distinguishing_probes": (
                        ProbeProposal(
                            probe_id=_FOLLOWUP,
                            purpose=DiagnosticPurpose.CHECK_COVERAGE,
                            priority=0.9,
                            estimated_cost_ms=25,
                            resource_class=ResourceClass.CPU,
                            dedupe_key="source:direct-origin-after-source",
                        ),
                    ),
                }
            )
        response = response.validate_against(request)
        self.exchanges[-1] = (request, response)
        return response


def _write_json(path: Path, value: Any) -> str:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "policy-visible").mkdir()
    (output_dir / "evaluator-only").mkdir()
    providers: list[TwoTurnReasoner] = []

    def provider_factory() -> TwoTurnReasoner:
        provider = TwoTurnReasoner()
        providers.append(provider)
        return provider

    cells = run_balanced_relation_probe(
        output_dir / "cases",
        domain_filter="network_browser",
        matched_indices=(49,),
        chosen_indices=(49,),
        reasoning_factory=provider_factory,
        followup_direct_status="offline",
        allow_evicted_choice=True,
    )
    if len(cells) != len(providers) or len(cells) != 1:
        raise ValueError("the frozen one-cell trajectory changed")
    cell, provider = cells[0], providers[0]
    chosen_id = EvidenceId(root=cell["chosen_evidence_id"])
    first = next(
        (
            (request, response)
            for request, response in provider.exchanges
            if chosen_id in response.considered_evidence_ids
            and any(hypothesis.expected_facts for hypothesis in response.hypotheses)
        ),
        None,
    )
    second = next(
        (
            (request, response)
            for request, response in provider.exchanges
            if any(item.probe_id == _FOLLOWUP for item in request.evidence_context)
            and any(item.expected_facts for item in request.previous_hypotheses)
            and any(
                item.probe_id == _FOLLOWUP
                for item in request.evidence_context
                if item.evidence_id in response.considered_evidence_ids
            )
        ),
        None,
    )
    visible = {
        "schema_version": 1,
        "first": None
        if first is None
        else {
            "request": first[0].model_dump(mode="json"),
            "response": first[1].model_dump(mode="json"),
        },
        "second": None
        if second is None
        else {
            "request": second[0].model_dump(mode="json"),
            "response": second[1].model_dump(mode="json"),
        },
    }
    visible_sha = _write_json(output_dir / "policy-visible" / "trajectory.json", visible)
    with SQLiteStore(Path(cell["database"])) as store:
        rows = store.connection.execute(
            "SELECT evidence_id,record_json,observed_at FROM evidence WHERE case_id=? "
            "AND json_extract(record_json,'$.collector.id')=?",
            (cell["task_observation"]["case_id"], _FOLLOWUP),
        ).fetchall()
        executions = [
            dict(zip(("execution_id", "status", "started_at", "finished_at"), row, strict=True))
            for row in store.connection.execute(
                "SELECT execution_id,status,started_at,finished_at FROM probe_executions "
                "WHERE case_id=? AND probe_id=?",
                (cell["task_observation"]["case_id"], _FOLLOWUP),
            )
        ]
        events = [
            {
                "event": event["event"],
                "occurred_at": event["occurred_at"],
                "hypotheses": event["hypotheses"],
            }
            for (record_json,) in store.connection.execute(
                "SELECT record_json FROM investigation_steps WHERE case_id=? "
                "ORDER BY state_version",
                (cell["task_observation"]["case_id"],),
            )
            if (event := json.loads(record_json))["event"]
            in {"deep_applied", "prediction_contested"}
        ]
    private = {
        "world_key": cell["world_key"],
        "chosen_evidence_id": cell["chosen_evidence_id"],
        "alternative_evidence_id": cell["alternative_evidence_id"],
        "selected_readback": cell["selected_readback"],
        "alternative_readback": cell["alternative_readback"],
        "followup_record": [json.loads(row[1]) for row in rows],
        "followup_executions": executions,
        "events": events,
        "terminal_status": cell["status"],
        "terminal_outcome": cell["outcome"],
        "terminal_assessment": cell["assessment"],
        "terminal_hypotheses": cell["terminal_hypotheses"],
        "terminal_stop_reason": cell["terminal_stop_reason"],
        "all_deep_calls": len(provider.exchanges),
        "provider_exchanges": [
            {
                "request": request.model_dump(mode="json"),
                "response": response.model_dump(mode="json"),
            }
            for request, response in provider.exchanges
        ],
        "provider_trace": [
            {
                "state_version": request.state_version,
                "selected_source_ids": [str(item.evidence_id) for item in request.selected_sources],
                "followup_context_ids": [
                    str(item.evidence_id)
                    for item in request.evidence_context
                    if item.probe_id == _FOLLOWUP
                ],
                "previous_prediction_count": sum(
                    bool(item.expected_facts) for item in request.previous_hypotheses
                ),
                "considered_ids": [str(item) for item in response.considered_evidence_ids],
                "summary": response.summary,
            }
            for request, response in provider.exchanges
        ],
    }
    private_sha = _write_json(output_dir / "evaluator-only" / "readback.json", private)
    manifest = {
        "schema_version": 1,
        "code_head": _git_head(),
        "scripted_provider": provider.identity.model_dump(mode="json"),
        "source_sha256": {
            item.name: _source_sha(item)
            for item in (
                Path(__file__),
                Path(__file__).with_name("source_task_relation_red.py"),
                Path(__file__).with_name("source_backed_full_run.py"),
                Path(__file__).with_name("postretrieval_advisory_pilot.py"),
            )
        },
        "policy_visible_sha256": visible_sha,
        "evaluator_only_sha256": private_sha,
        "database_sha256": hashlib.sha256(Path(cell["database"]).read_bytes()).hexdigest(),
        "first_present": first is not None,
        "second_present": second is not None,
        "followup_executions": len(executions),
        "prediction_contested_events": sum(
            item["event"] == "prediction_contested" for item in events
        ),
    }
    _write_json(output_dir / "manifest.json", manifest)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    print(json.dumps(run(parser.parse_args().output_dir), indent=2))
