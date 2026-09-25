"""Hidden, deterministic oracle for opt-in synthetic search-policy captures.

The worker sees probe observations, never these recipes or the oracle result.
This only checks information yield from a linked selected action. It cannot
establish Windows diagnostic accuracy, privacy review, or training admission.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import JsonValue
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore

ScenarioKind = Literal["pressure_fault", "healthy_control", "external_outage"]
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
