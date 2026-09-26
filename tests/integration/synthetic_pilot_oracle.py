"""Hidden, deterministic oracle for opt-in synthetic search-policy captures.

The worker sees probe observations, never these recipes or the oracle result.
This only checks information yield from a linked selected action. It cannot
establish Windows diagnostic accuracy, privacy review, or training admission.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from systemsense.decision.frontier_ranker import FrontierRankRequestV1
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import JsonValue
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.case_candidates import CaseCandidateRegistry
from systemsense.storage.sqlite_store import SQLiteStore

ScenarioKind = Literal["pressure_fault", "healthy_control", "external_outage", "pdf_process_pair"]
ActionStatus = Literal["useful", "uninformative", "failed", "unknown", "unrun"]


@dataclass(frozen=True)
class SyntheticScenario:
    kind: ScenarioKind
    pressure_percent: int
    external_service_status: Literal["available", "unavailable"]
    objective: str


PILOT_SCENARIOS = (
    SyntheticScenario("pressure_fault", 97, "available", "Investigate synthetic slow computer"),
    SyntheticScenario("healthy_control", 12, "available", "Check synthetic slow-computer report"),
    SyntheticScenario("external_outage", 12, "unavailable", "Investigate synthetic slow service"),
)

PDF_PROCESS_PAIR_SCENARIO = SyntheticScenario(
    "pdf_process_pair",
    97,
    "available",
    "PDF viewer and related indexing service both run slowly",
)


@dataclass(frozen=True)
class VisibleReferenceChoice:
    """A test-only selection from the exact menu supplied to Laya."""

    selected_item_id: str
    selected_kind: str
    considered_item_ids: tuple[str, ...]
    rule: str


_OBSERVABLE_FACT = {
    "pressure.sample": "pressure_percent",
    "network.connectivity": "external_service_status",
}
_STOPWORDS = {
    "a",
    "and",
    "bounded",
    "case",
    "check",
    "does",
    "for",
    "in",
    "of",
    "read",
    "registered",
    "reveal",
    "synthetic",
    "the",
    "this",
    "to",
    "what",
    "would",
}


def _tokens(value: str) -> set[str]:
    return set(re.findall(r"[a-z]+", value.casefold())) - _STOPWORDS


def _visible_exact_metrics(
    request: FrontierRankRequestV1,
) -> dict[tuple[str, str], list[datetime]]:
    metrics: dict[tuple[str, str], list[datetime]] = {}
    for packet in request.evidence_packets:
        visible = json.loads(packet.description)
        if (
            visible.get("packet_kind") == "fact"
            and visible.get("value_quality") == "exact"
            and isinstance(visible.get("metric"), str)
            and isinstance(visible.get("probe_id"), str)
        ):
            metrics.setdefault((visible["probe_id"], visible["metric"]), []).append(
                datetime.fromisoformat(visible["observed_at"])
            )
    return metrics


def reference_next_step(request: FrontierRankRequestV1) -> VisibleReferenceChoice:
    """Apply a preregistered visible-input rubric, without recipe or outcome access.

    Prefer a new registered measurement relevant to the symptom. Existing
    exact facts only satisfy the same or an older observation window. If no
    new measurement is offered, inspect relevant stored evidence, then a
    sourced branch, and finally ask the deep adviser. All choices remain
    within the frozen requested menu and its existing budget/authority checks.
    This rubric is a controlled comparator, not a qualified expert policy.
    """

    exact_metrics = _visible_exact_metrics(request)
    symptom = _tokens(request.symptom)
    scored: list[tuple[tuple[int, int, int, int], str, str, str]] = []
    for index, (item, semantic) in enumerate(
        zip(request.items, request.item_semantics, strict=True)
    ):
        kind = item.reference.kind
        relevance = len(symptom & _tokens(semantic.information_goal))
        if semantic.measurement is not None:
            observable = semantic.measurement.observable
            if observable == "pressure.sample" and {"computer", "resource", "pressure"} & symptom:
                relevance += 3
            if observable == "network.connectivity" and {"service", "network", "outage"} & symptom:
                relevance += 3
            metric = _OBSERVABLE_FACT.get(semantic.measurement.probe_id)
            observed = (
                ()
                if metric is None or semantic.target_scope != "host"
                else exact_metrics.get((semantic.measurement.probe_id, metric), ())
            )
            window = semantic.measurement_window
            fresh_fact = any(window is None or at >= window.start for at in observed)
            tier = 4 if not fresh_fact else 0
            rule = "new_registered_measurement" if not fresh_fact else "already_visible_measurement"
        elif kind == "retrieve_evidence":
            tier, rule = 3, "stored_evidence"
        elif kind == "review_branch":
            tier, rule = 2, "sourced_branch"
        else:
            tier, rule = 1, "deep_review"
        scored.append(((tier, relevance, -item.cost_ms, -index), item.item_id, kind, rule))
    _, selected_id, selected_kind, rule = max(scored)
    return VisibleReferenceChoice(
        selected_item_id=selected_id,
        selected_kind=selected_kind,
        considered_item_ids=tuple(item.item_id for item in request.items),
        rule=rule,
    )


@dataclass(frozen=True)
class SyntheticReferenceComparison:
    """Research comparison; a counterfactual fixture result is not a runtime label."""

    snapshot_id: str
    case_id: str
    actual_item_id: str
    actual_status: ActionStatus
    reference_item_id: str
    reference_kind: str
    reference_rule: str
    reference_status: ActionStatus
    reference_evaluation: Literal[
        "same_recorded_action", "counterfactual_synthetic_probe", "unknown"
    ]
    actual_item_outcomes: tuple[tuple[str, ActionStatus], ...]
    learning_candidate: bool
    training_admissible: Literal[False] = False


def compare_visible_reference(
    store: SQLiteStore,
    snapshot_id: str,
    scenario: SyntheticScenario,
    *,
    binding_path: Path,
) -> SyntheticReferenceComparison:
    """Choose first from visible input, then evaluate with the hidden fixture.

    A different selected measurement is run through the same literal fixture
    handler as the pilot, but only as a synthetic counterfactual. The original
    Laya item's unrun alternatives retain their unknown statuses.
    """

    with store.read_snapshot():
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_id)
        reference = reference_next_step(snapshot.request)
        actual = selected_action_receipt(store, snapshot_id, scenario, binding_path=binding_path)
        status: ActionStatus = "unknown"
        evaluation: Literal["same_recorded_action", "counterfactual_synthetic_probe", "unknown"] = (
            "unknown"
        )
        if reference.selected_item_id == snapshot.selected_item_id:
            status, evaluation = actual.selected_status, "same_recorded_action"
        elif reference.selected_kind == "measure":
            selected_index = reference.considered_item_ids.index(reference.selected_item_id)
            semantic = snapshot.request.item_semantics[selected_index]
            if semantic.measurement is not None:
                prior = _prior_case_facts(
                    store,
                    case_id=str(snapshot.case_id),
                    frozen_at=snapshot.request_frozen_at,
                )
                if prior is not None:
                    status = evaluate_reference_measurement(
                        snapshot.request, reference, scenario, prior
                    )
                    if status != "unknown":
                        evaluation = "counterfactual_synthetic_probe"
        return SyntheticReferenceComparison(
            snapshot_id=snapshot_id,
            case_id=str(snapshot.case_id),
            actual_item_id=snapshot.selected_item_id,
            actual_status=actual.selected_status,
            reference_item_id=reference.selected_item_id,
            reference_kind=reference.selected_kind,
            reference_rule=reference.rule,
            reference_status=status,
            reference_evaluation=evaluation,
            actual_item_outcomes=actual.item_outcomes,
            learning_candidate=(
                status == "useful" and actual.selected_status in {"failed", "uninformative"}
            ),
        )


def evaluate_reference_measurement(
    request: FrontierRankRequestV1,
    choice: VisibleReferenceChoice,
    scenario: SyntheticScenario,
    prior_facts: tuple[tuple[str, JsonValue], ...],
) -> ActionStatus:
    """Independently execute only the chosen registered synthetic probe.

    This evaluates a simulator counterfactual after selection. It does not
    retroactively convert other unrun menu items into observed outcomes.
    """

    if choice.considered_item_ids != tuple(item.item_id for item in request.items):
        raise ValueError("reference choice escapes frozen menu")
    selected = next(
        (
            index
            for index, item in enumerate(request.items)
            if item.item_id == choice.selected_item_id
        ),
        None,
    )
    if (
        selected is None
        or choice.selected_kind != "measure"
        or request.items[selected].reference.kind != "measure"
    ):
        return "unknown"
    semantic = request.item_semantics[selected]
    if semantic.measurement is None:
        return "unknown"
    probe_id = semantic.measurement.probe_id
    return assess_selected_fact(
        scenario, probe_id, synthetic_probe_facts(scenario, probe_id), prior_facts
    )


def _recipe_sha256(scenario: SyntheticScenario) -> str:
    return hashlib.sha256(
        json.dumps(asdict(scenario), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def write_synthetic_recipe_binding(path: Path, case_id: str, scenario: SyntheticScenario) -> None:
    """Write once before model work; the sidecar is never supplied to providers."""

    if not case_id:
        raise ValueError("hidden recipe binding requires a case")
    binding = {
        "schema_version": 1,
        "case_id": case_id,
        "scenario_sha256": _recipe_sha256(scenario),
        "bound_at": datetime.now(UTC).isoformat(),
    }
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(binding, sort_keys=True, separators=(",", ":")))


def _verify_synthetic_recipe_binding(
    path: Path, *, case_id: str, frozen_at: datetime, scenario: SyntheticScenario
) -> str:
    raw = path.read_bytes()
    if len(raw) > 2048:
        raise ValueError("hidden recipe binding is oversized")
    try:
        binding: object = json.loads(raw)
        if not isinstance(binding, dict):
            raise ValueError("hidden recipe binding shape differs")
        typed = cast(dict[str, object], binding)
        if set(typed) != {
            "schema_version",
            "case_id",
            "scenario_sha256",
            "bound_at",
        }:
            raise ValueError("hidden recipe binding shape differs")
        bound_at = datetime.fromisoformat(str(typed["bound_at"]))
        if (
            typed["schema_version"] != 1
            or typed["case_id"] != case_id
            or typed["scenario_sha256"] != _recipe_sha256(scenario)
            or bound_at.utcoffset() != UTC.utcoffset(None)
            or bound_at > frozen_at
        ):
            raise ValueError("hidden recipe binding differs from case or decision")
    except (TypeError, ValueError) as error:
        raise ValueError("hidden recipe binding is invalid") from error
    return hashlib.sha256(raw).hexdigest()


def synthetic_probe_facts(scenario: SyntheticScenario, probe_id: str) -> dict[str, JsonValue]:
    """Emit only literal synthetic data; the hidden case kind is not an output fact."""

    facts: dict[str, JsonValue] = {"fixture": "controlled-synthetic-pilot-v1"}
    if probe_id == "pressure.sample":
        facts["pressure_percent"] = scenario.pressure_percent
    elif probe_id == "network.connectivity":
        facts["external_service_status"] = scenario.external_service_status
    return facts


def synthetic_process_pressure_facts(scenario: SyntheticScenario, pid: int) -> dict[str, JsonValue]:
    """Literal fixture handler shared by runtime execution and offline replay."""

    if scenario.kind != "pdf_process_pair" or pid not in {4201, 4202}:
        raise ValueError("fixture target is unavailable")
    return {
        "target_pressure": {
            "target_pid": pid,
            "status": "available",
            "samples": [{"cpu_percent": 94 if pid == 4201 else 4}],
        }
    }


@dataclass(frozen=True)
class SyntheticProcessCounterfactualReceipt:
    snapshot_id: str
    item_id: str
    candidate_id: str
    target_handle: str
    source_evidence_id: str
    source_evidence_sha256: str
    invocation_sha256: str
    result_sha256: str
    observed_cpu_percent: int
    original_selected_item_id: str
    original_item_status: Literal["unrun"]
    utility: Literal["unknown"]
    provenance_class: Literal["validated_simulator"]
    training_admissible: Literal[False]
    receipt_sha256: str


def process_pair_counterfactual_receipts(
    store: SQLiteStore,
    snapshot_id: str,
    scenario: SyntheticScenario,
    *,
    binding_path: Path,
) -> tuple[SyntheticProcessCounterfactualReceipt, ...]:
    """Replay only unselected, source-bound fixture alternatives outside Laya's run."""

    if scenario.kind != "pdf_process_pair":
        raise ValueError("process pair requires its hidden simulator recipe")
    with store.read_snapshot():
        repo = CandidateDecisionSnapshotRepository(store)
        snapshot = repo.readback_frontier(snapshot_id)
        repo.readback_frontier_worker_draft(snapshot_id)
        _verify_synthetic_recipe_binding(
            binding_path,
            case_id=str(snapshot.case_id),
            frozen_at=snapshot.request_frozen_at,
            scenario=scenario,
        )
        if snapshot.response.ranking_source != "laya" or snapshot.response.cache_hit:
            raise ValueError("process pair requires uncached exact Laya input")
        registry = CaseCandidateRegistry(
            store, registrations=(), manifest_lookup=lambda _probe_id: None, revalidate_target=None
        )
        candidate_records = {
            record.candidate_id: record
            for record in registry.readback(snapshot.case_id, snapshot.epoch_state_version)
        }
        pairs = tuple(
            (item, semantic)
            for item, semantic in zip(
                snapshot.request.items, snapshot.request.item_semantics, strict=True
            )
            if semantic.measurement is not None
            and semantic.measurement.probe_id == "application.target_pressure"
        )
        if len(pairs) != 2:
            raise ValueError("process pair is not two frozen alternatives")
        receipts: list[SyntheticProcessCounterfactualReceipt] = []
        for item, semantic in pairs:
            if item.item_id == snapshot.selected_item_id:
                continue
            candidate_id = item.reference.candidate_id
            record = candidate_records.get(candidate_id or "")
            if record is None or semantic.measurement is None:
                raise ValueError("process pair candidate readback is missing")
            record_sha = hashlib.sha256(
                json.dumps(
                    record.model_dump(mode="json"),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            row = store.connection.execute(
                "SELECT target_handle,source_evidence_id,source_evidence_sha256,"
                "invocation_json,invocation_sha256 FROM case_measurement_candidates "
                "WHERE candidate_id=? AND case_id=? AND epoch_state_version=?",
                (candidate_id, str(snapshot.case_id), snapshot.epoch_state_version),
            ).fetchone()
            if row is None:
                raise ValueError("process pair candidate source is missing")
            target_handle, source_id, source_sha, invocation_json, invocation_sha = map(str, row)
            source = store.evidence(case_id=str(snapshot.case_id), evidence_id=source_id)
            if source is None:
                raise ValueError("process pair source evidence is missing")
            source_record = EvidenceRecord.model_validate_json(source.record_json)
            invocation = json.loads(invocation_json)
            parameters = invocation.get("parameters", {})
            pid = parameters.get("pid")
            process_facts = {fact.name: fact.value for fact in source_record.facts}
            processes = process_facts.get("processes")
            if (
                record_sha != semantic.source_record_sha256
                or record.invocation_sha256 != invocation_sha
                or semantic.measurement.invocation_sha256 != invocation_sha
                or hashlib.sha256(invocation_json.encode("utf-8")).hexdigest() != invocation_sha
                or hashlib.sha256(source.record_json.encode("utf-8")).hexdigest() != source_sha
                or source_record.collector.id != "application.snapshot"
                or source_record.captured_at > snapshot.request_frozen_at
                or not isinstance(processes, list)
                or type(pid) is not int
                or not any(
                    isinstance(process, dict)
                    and process.get("pid") == pid
                    and datetime.fromisoformat(str(process.get("creation_time")))
                    == datetime.fromisoformat(str(parameters.get("creation_time")))
                    for process in processes
                )
                or invocation.get("target_handle") != target_handle
            ):
                raise ValueError("process pair source or target binding differs")
            observed = synthetic_process_pressure_facts(scenario, pid)
            pressure = cast(dict[str, JsonValue], observed["target_pressure"])
            samples = cast(list[dict[str, JsonValue]], pressure["samples"])
            cpu = samples[0]["cpu_percent"]
            assert isinstance(cpu, int)
            result_sha = hashlib.sha256(
                json.dumps(observed, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            content = {
                "snapshot_id": snapshot_id,
                "item_id": item.item_id,
                "candidate_id": candidate_id,
                "target_handle": target_handle,
                "source_evidence_id": source_id,
                "source_evidence_sha256": source_sha,
                "invocation_sha256": invocation_sha,
                "result_sha256": result_sha,
                "observed_cpu_percent": cpu,
                "original_selected_item_id": snapshot.selected_item_id,
                "original_item_status": "unrun",
                "utility": "unknown",
                "provenance_class": "validated_simulator",
                "training_admissible": False,
            }
            receipts.append(
                SyntheticProcessCounterfactualReceipt(
                    **content,  # type: ignore[arg-type]
                    receipt_sha256=hashlib.sha256(
                        json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    ).hexdigest(),
                )
            )
        if (
            not 1 <= len(receipts) <= 2
            or len({receipt.source_evidence_id for receipt in receipts}) != 1
            or len({receipt.target_handle for receipt in receipts}) != len(receipts)
        ):
            raise ValueError("process pair must share one source and have distinct targets")
        return tuple(receipts)


def assess_selected_fact(
    scenario: SyntheticScenario,
    probe_id: str,
    observed_facts: dict[str, JsonValue],
    prior_facts: tuple[tuple[str, JsonValue], ...],
) -> ActionStatus:
    """Score new distinguishing information, not the fast brain's preference."""

    if probe_id == "pressure.sample":
        metric, expected = "pressure_percent", scenario.pressure_percent
    elif probe_id == "network.connectivity":
        metric, expected = "external_service_status", scenario.external_service_status
    else:
        return "unknown"
    if metric not in observed_facts:
        return "unknown"
    if observed_facts[metric] != expected:
        raise ValueError("selected observation contradicts the hidden recipe")
    if (metric, expected) in prior_facts:
        return "uninformative"
    return "useful"


def _prior_case_facts(
    store: SQLiteStore, *, case_id: str, frozen_at: datetime
) -> tuple[tuple[str, JsonValue], ...] | None:
    """Read the case ledger, including evidence omitted from a worker packet."""

    rows = store.connection.execute(
        "SELECT record_json FROM evidence WHERE case_id=? ORDER BY captured_at LIMIT 513",
        (case_id,),
    ).fetchall()
    if len(rows) > 512:
        return None
    facts: list[tuple[str, JsonValue]] = []
    for row in rows:
        record = EvidenceRecord.model_validate_json(str(row[0]))
        if record.captured_at <= frozen_at:
            facts.extend((fact.name, fact.value) for fact in record.facts)
    return tuple(facts)


@dataclass(frozen=True)
class SyntheticActionReceipt:
    schema_version: Literal[1]
    scenario_sha256: str
    hidden_recipe_binding_sha256: str
    snapshot_id: str
    case_id: str
    selected_item_id: str
    selected_kind: str
    execution_id: str | None
    evidence_ids: tuple[str, ...]
    selected_status: ActionStatus
    item_outcomes: tuple[tuple[str, ActionStatus], ...]
    worker_draft_sha256: str
    source_attestation: Literal["harness_declared_synthetic_unreviewed"]
    training_admissible: Literal[False]
    diagnostic_performance_admissible: Literal[False]
    receipt_sha256: str


def selected_action_receipt(
    store: SQLiteStore,
    snapshot_id: str,
    scenario: SyntheticScenario,
    *,
    binding_path: Path,
) -> SyntheticActionReceipt:
    """Read immutable worker and execution custody before assigning an outcome.

    Unlinked, unsupported, or unobserved selections stay unknown. All unrun
    alternatives remain unknown rather than becoming negative examples.
    """

    with store.read_snapshot():
        snapshots = CandidateDecisionSnapshotRepository(store)
        snapshot = snapshots.readback_frontier(snapshot_id)
        binding_sha = _verify_synthetic_recipe_binding(
            binding_path,
            case_id=str(snapshot.case_id),
            frozen_at=snapshot.request_frozen_at,
            scenario=scenario,
        )
        draft = snapshots.readback_frontier_worker_draft(snapshot_id)
        if snapshot.response.ranking_source != "laya" or snapshot.response.cache_hit:
            raise ValueError("selected-action oracle needs uncached Laya worker input")
        selected = next(
            item for item in snapshot.request.items if item.item_id == snapshot.selected_item_id
        )
        status: ActionStatus = "unknown"
        execution_id: str | None = None
        evidence_ids: tuple[str, ...] = ()
        if selected.reference.kind == "measure" and snapshot.candidate_id is not None:
            links = snapshots.execution_links(snapshot_id)
            if len(links) > 1:
                raise ValueError("selected action has multiple execution links")
            if links:
                link = links[0]
                if link.candidate_id != snapshot.candidate_id:
                    raise ValueError("selected action execution differs from snapshot")
                execution_id = link.execution_id
                execution = store.probe_execution(execution_id)
                if execution is None:
                    raise ValueError("selected action has no recorded execution")
                if execution.status != "ok":
                    status = "failed"
                else:
                    rows = store.connection.execute(
                        "SELECT evidence_id,record_json FROM evidence "
                        "WHERE case_id=? AND execution_id=? ORDER BY evidence_id",
                        (str(snapshot.case_id), execution_id),
                    ).fetchall()
                    facts: dict[str, JsonValue] = {}
                    ids: list[str] = []
                    for evidence_id, record_json in rows:
                        record = EvidenceRecord.model_validate_json(str(record_json))
                        if (
                            record.collector.id != execution.probe_id
                            or str(record.collector.execution_id) != execution_id
                        ):
                            raise ValueError("selected action evidence provenance differs")
                        ids.append(str(evidence_id))
                        for fact in record.facts:
                            if fact.name in facts and facts[fact.name] != fact.value:
                                raise ValueError("selected action has conflicting facts")
                            facts[fact.name] = fact.value
                    evidence_ids = tuple(ids)
                    prior = _prior_case_facts(
                        store,
                        case_id=str(snapshot.case_id),
                        frozen_at=snapshot.request_frozen_at,
                    )
                    if prior is not None:
                        status = assess_selected_fact(scenario, execution.probe_id, facts, prior)
        outcomes = tuple(
            (item.item_id, status if item.item_id == snapshot.selected_item_id else "unrun")
            for item in snapshot.request.items
        )
        content = {
            "schema_version": 1,
            "scenario_sha256": _recipe_sha256(scenario),
            "hidden_recipe_binding_sha256": binding_sha,
            "snapshot_id": snapshot_id,
            "case_id": str(snapshot.case_id),
            "selected_item_id": snapshot.selected_item_id,
            "selected_kind": selected.reference.kind,
            "execution_id": execution_id,
            "evidence_ids": evidence_ids,
            "selected_status": status,
            "item_outcomes": outcomes,
            "worker_draft_sha256": draft.capture_sha256,
            "source_attestation": "harness_declared_synthetic_unreviewed",
            "training_admissible": False,
            "diagnostic_performance_admissible": False,
        }
        digest = hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return SyntheticActionReceipt(**content, receipt_sha256=digest)  # type: ignore[arg-type]
