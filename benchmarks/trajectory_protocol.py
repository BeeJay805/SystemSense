"""CPU-only accounting for planned, matched investigation trajectories.

These records complement the externally reviewed Windows scorecard. They do not
authenticate captures, reconstruct exact worker inputs, or grade a cause against
a hidden recipe. A real arm must pass the existing lab/reset and independent
oracle gates before its results support diagnostic claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Literal, Self, TypedDict, cast

from pydantic import Field, model_validator

from benchmarks.lab_episodes import LabModel


class Arm(StrEnum):
    DETERMINISTIC = "deterministic"
    DEEP_ONLY = "deep_only"
    FAST_DEEP_SCOUT_OFF = "fast_deep_scout_off"
    FAST_DEEP_SCOUT_ON = "fast_deep_scout_on"


REQUIRED_ARMS = tuple(Arm)


@dataclass(frozen=True, slots=True)
class ScenarioSlot:
    role: str
    domain: Literal["network_browser", "application_performance"]
    split: Literal["development", "holdout"]
    family_group: str


# Reservation only. These are roles for future controlled episodes, not fault
# recipes, observed outcomes, or runnable Windows scenarios.
SCENARIO_MATRIX = (
    ScenarioSlot("network_proxy_fault", "network_browser", "development", "wininet_proxy"),
    ScenarioSlot("network_external_control", "network_browser", "development", "remote_outage"),
    ScenarioSlot("network_healthy_control", "network_browser", "development", "network_healthy"),
    ScenarioSlot(
        "network_misleading_abnormality", "network_browser", "development", "irrelevant_health"
    ),
    ScenarioSlot("network_same_symptom_other_cause", "network_browser", "holdout", "dns_fault"),
    ScenarioSlot("network_counterevidence", "network_browser", "holdout", "changing_network_state"),
    ScenarioSlot(
        "application_performance_fault", "application_performance", "development", "process_load"
    ),
    ScenarioSlot(
        "application_healthy_control", "application_performance", "development", "app_healthy"
    ),
    ScenarioSlot(
        "application_misleading_abnormality",
        "application_performance",
        "holdout",
        "irrelevant_app_health",
    ),
    ScenarioSlot(
        "application_counterevidence", "application_performance", "holdout", "app_state_change"
    ),
)


class CasePlan(LabModel):
    """Reviewer-side plan; the caller must keep hidden fields from policies."""

    schema_version: Literal[1] = 1
    case_id: str = Field(pattern=r"^[a-z][a-z0-9-]{3,79}$")
    source: Literal["synthetic", "windows_vm", "real_user"]
    split: Literal["development", "holdout"]
    family_group: str = Field(min_length=3, max_length=80)
    scenario_role: str = Field(min_length=3, max_length=80)
    objective: str = Field(min_length=1, max_length=2000)
    visible_input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    initial_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ordered_tools_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget_ms: int = Field(ge=100, le=600_000)
    max_probes: int = Field(ge=1, le=64)
    max_model_calls: int = Field(ge=0, le=100)


class FrozenProtocol(LabModel):
    schema_version: Literal[1] = 1
    cases: tuple[CasePlan, ...] = Field(min_length=1, max_length=100)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def freeze_protocol(cases: tuple[CasePlan, ...]) -> FrozenProtocol:
    """Pin case order and group assignment before outcomes or tuning are seen."""

    if not cases or len(cases) > 100:
        raise ValueError("protocol requires 1 to 100 cases")
    ids: set[str] = set()
    groups: dict[str, str] = {}
    for case in cases:
        if case.case_id in ids:
            raise ValueError("duplicate case ID")
        ids.add(case.case_id)
        previous = groups.setdefault(case.family_group, case.split)
        if previous != case.split:
            raise ValueError("family group crosses development and holdout")
    slots = {slot.role: slot for slot in SCENARIO_MATRIX}
    for case in cases:
        slot = slots.get(case.scenario_role)
        if slot is None or (case.split, case.family_group) != (
            slot.split,
            slot.family_group,
        ):
            raise ValueError("case does not match reserved role, split, and family group")
    encoded = json.dumps(
        [case.model_dump(mode="json") for case in cases],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return FrozenProtocol(cases=cases, digest=hashlib.sha256(encoded).hexdigest())


def visible_case_input(case: CasePlan) -> dict[str, str | int]:
    """Project predecision metadata; exact observations live in external captures."""

    return {
        "objective": case.objective,
        "visible_input_sha256": case.visible_input_sha256,
        "initial_evidence_sha256": case.initial_evidence_sha256,
        "ordered_tools_sha256": case.ordered_tools_sha256,
        "budget_ms": case.budget_ms,
        "max_probes": case.max_probes,
        "max_model_calls": case.max_model_calls,
    }


class Choice(LabModel):
    kind: Literal["probe", "retrieve", "branch", "deep"]
    item_id: str = Field(min_length=1, max_length=120)
    outcome: Literal["useful", "uninformative", "failed", "unknown", "unrun"]
    elapsed_ms: int | None = Field(default=None, ge=0)
    prefetch: bool = False
    used: bool | None = None

    @model_validator(mode="after")
    def no_future_result_for_unrun(self) -> Self:
        if self.prefetch and self.kind != "probe":
            raise ValueError("only a probe can be prefetched")
        if self.outcome == "unrun" and (self.elapsed_ms is not None or self.used is not None):
            raise ValueError("unrun choice cannot have observed utility or use")
        if self.outcome != "unrun" and self.elapsed_ms is None:
            raise ValueError("observed choice requires elapsed time")
        if not self.prefetch and self.used is not None:
            raise ValueError("only prefetch can have a used flag")
        return self


class Claim(LabModel):
    code: str = Field(min_length=1, max_length=120)
    supported: bool | None = None  # Independent review; None remains unknown.
    alternatives_discriminated: bool | None = None
    cited_evidence_ids: tuple[str, ...] = Field(default=(), max_length=16)
    elapsed_ms: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def reviewed_support_needs_evidence(self) -> Self:
        if self.supported is True and (not self.cited_evidence_ids or self.elapsed_ms is None):
            raise ValueError("supported cause requires cited evidence and answer time")
        if self.alternatives_discriminated is True and self.supported is not True:
            raise ValueError("discrimination requires a supported cause")
        return self


class ProviderCall(LabModel):
    role: Literal["fast", "deep", "scout"]
    attempted_provider_id: str = Field(min_length=1, max_length=80)
    effective_provider_id: str | None = Field(default=None, min_length=1, max_length=80)
    model_id: str | None = Field(default=None, min_length=1, max_length=120)
    failed: bool
    invalid_advice: bool
    cost_usd: float | None = Field(default=None, ge=0, allow_inf_nan=False)


class Trajectory(LabModel):
    schema_version: Literal[1] = 1
    case_id: str
    arm: Arm
    status: Literal["completed", "failed", "timeout", "unrun"]
    visible_input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    initial_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ordered_tools_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget_ms: int = Field(ge=100, le=600_000)
    max_probes: int = Field(ge=1, le=64)
    max_model_calls: int = Field(ge=0, le=100)
    started_at_ms: int = Field(ge=0)
    finished_at_ms: int = Field(ge=0)
    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    review_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    choices: tuple[Choice, ...] = Field(max_length=128)
    claims: tuple[Claim, ...] = Field(max_length=12)
    provider_calls: tuple[ProviderCall, ...] = Field(max_length=100)
    host_impact_ms: int | None = Field(default=None, ge=0)
    eligible_opportunities: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def coherent_trace(self) -> Self:
        if self.finished_at_ms < self.started_at_ms:
            raise ValueError("trajectory clock order invalid")
        if self.status == "unrun" and (self.choices or self.claims or self.provider_calls):
            raise ValueError("unrun trajectory cannot contain events")
        times = [choice.elapsed_ms for choice in self.choices if choice.elapsed_ms is not None]
        if times != sorted(times) or any(
            elapsed > self.finished_at_ms - self.started_at_ms for elapsed in times
        ):
            raise ValueError("choice order or time invalid")
        if len(self.choices) > self.max_probes + self.max_model_calls:
            raise ValueError("choice count exceeds common opportunity budget")
        if len(self.provider_calls) > self.max_model_calls:
            raise ValueError("provider calls exceed common budget")
        claim_times = [claim.elapsed_ms for claim in self.claims if claim.elapsed_ms is not None]
        if claim_times != sorted(claim_times) or any(
            elapsed > self.finished_at_ms - self.started_at_ms for elapsed in claim_times
        ):
            raise ValueError("claim order or time invalid")
        if self.eligible_opportunities is not None and self.eligible_opportunities < sum(
            choice.outcome != "unrun" for choice in self.choices
        ):
            raise ValueError("eligible opportunities cannot be fewer than observed choices")
        return self


class ArmAccounting(TypedDict):
    eligible: int
    completed: int
    failed: int
    timeout: int
    unrun: int
    useful_evidence: int
    wasted_probes: int
    failed_choices: int
    unknown_choices: int
    eligible_opportunities: int | None
    missed_opportunities: int | None
    missing_opportunity_accounting: int
    wrong_claims: int
    supported_claims: int
    supported_discrimination: int
    unreviewed_claims: int
    first_useful_ms: list[int]
    first_supported_answer_ms: list[int]
    wall_ms: list[int]
    prefetch_used: int
    prefetch_wasted: int
    prefetch_unknown: int
    provider_failures: int
    invalid_advice: int
    provider_identities: list[tuple[str, str, str | None, str | None]]
    model_cost_usd: float | None
    host_impact_ms: int | None


class TrajectoryReport(TypedDict):
    schema_version: int
    classification: str
    protocol_digest: str
    planned_cases: int
    complete_paired_cases: int
    arms: dict[str, ArmAccounting]
    diagnostic_performance_admissible: bool
    training_admissible: bool


def score_trajectories(
    protocol: FrozenProtocol, records: tuple[Trajectory, ...]
) -> TrajectoryReport:
    """Count every planned cell; supplied reviews are not authenticated here."""

    if freeze_protocol(protocol.cases).digest != protocol.digest:
        raise ValueError("frozen protocol digest mismatch")
    if len({case.source for case in protocol.cases}) != 1:
        raise ValueError("source classes must be scored separately")
    plans = {case.case_id: case for case in protocol.cases}
    observed: dict[tuple[str, Arm], Trajectory] = {}
    for record in records:
        plan = plans.get(record.case_id)
        if plan is None:
            raise ValueError("trajectory case is outside frozen protocol")
        key = (record.case_id, record.arm)
        if key in observed:
            raise ValueError("duplicate trajectory arm")
        if any(
            getattr(record, name) != getattr(plan, name)
            for name in (
                "visible_input_sha256",
                "initial_evidence_sha256",
                "ordered_tools_sha256",
                "budget_ms",
                "max_probes",
                "max_model_calls",
            )
        ):
            raise ValueError("trajectory parity mismatch")
        observed[key] = record

    arms: dict[str, ArmAccounting] = {}
    for arm in REQUIRED_ARMS:
        cells = [observed.get((case.case_id, arm)) for case in protocol.cases]
        runs = [cell for cell in cells if cell is not None and cell.status != "unrun"]
        choices = [choice for run in runs for choice in run.choices]
        calls = [call for run in runs for call in run.provider_calls]
        prefetches = [choice for choice in choices if choice.prefetch]
        costs = [call.cost_usd for call in calls]
        impacts = [run.host_impact_ms for run in runs]
        opportunity_counts = [run.eligible_opportunities for run in runs]
        arms[arm.value] = {
            "eligible": len(cells),
            "completed": sum(cell is not None and cell.status == "completed" for cell in cells),
            "failed": sum(cell is not None and cell.status == "failed" for cell in cells),
            "timeout": sum(cell is not None and cell.status == "timeout" for cell in cells),
            "unrun": sum(cell is None or cell.status == "unrun" for cell in cells),
            "useful_evidence": sum(choice.outcome == "useful" for choice in choices),
            "wasted_probes": sum(
                choice.kind == "probe" and choice.outcome == "uninformative" for choice in choices
            ),
            "failed_choices": sum(choice.outcome == "failed" for choice in choices),
            "unknown_choices": sum(choice.outcome in {"unknown", "unrun"} for choice in choices),
            "eligible_opportunities": (
                sum(count for count in opportunity_counts if count is not None)
                if len(runs) == len(cells)
                and all(count is not None for count in opportunity_counts)
                else None
            ),
            "missed_opportunities": (
                sum(count for count in opportunity_counts if count is not None)
                - sum(choice.outcome != "unrun" for choice in choices)
                if len(runs) == len(cells)
                and all(count is not None for count in opportunity_counts)
                else None
            ),
            "missing_opportunity_accounting": sum(
                run.eligible_opportunities is None for run in runs
            )
            + len(cells)
            - len(runs),
            "wrong_claims": sum(claim.supported is False for run in runs for claim in run.claims),
            "supported_claims": sum(
                claim.supported is True for run in runs for claim in run.claims
            ),
            "supported_discrimination": sum(
                claim.supported is True and claim.alternatives_discriminated is True
                for run in runs
                for claim in run.claims
            ),
            "unreviewed_claims": sum(
                claim.supported is None for run in runs for claim in run.claims
            ),
            "first_useful_ms": [
                min(
                    choice.elapsed_ms
                    for choice in run.choices
                    if choice.outcome == "useful" and choice.elapsed_ms is not None
                )
                for run in runs
                if any(choice.outcome == "useful" for choice in run.choices)
            ],
            "first_supported_answer_ms": [
                min(
                    claim.elapsed_ms
                    for claim in run.claims
                    if claim.supported is True and claim.elapsed_ms is not None
                )
                for run in runs
                if any(claim.supported is True for claim in run.claims)
            ],
            "wall_ms": [run.finished_at_ms - run.started_at_ms for run in runs],
            "prefetch_used": sum(choice.used is True for choice in prefetches),
            "prefetch_wasted": sum(choice.used is False for choice in prefetches),
            "prefetch_unknown": sum(choice.used is None for choice in prefetches),
            "provider_failures": sum(call.failed for call in calls),
            "invalid_advice": sum(call.invalid_advice for call in calls),
            "provider_identities": sorted(
                {
                    (
                        call.role,
                        call.attempted_provider_id,
                        call.effective_provider_id,
                        call.model_id,
                    )
                    for call in calls
                },
                key=str,
            ),
            "model_cost_usd": round(sum(cost for cost in costs if cost is not None), 8)
            if len(runs) == len(cells) and all(cost is not None for cost in costs)
            else None,
            "host_impact_ms": sum(impact for impact in impacts if impact is not None)
            if len(runs) == len(cells) and all(impact is not None for impact in impacts)
            else None,
        }
    complete = sum(
        all(
            (record := observed.get((case.case_id, arm))) is not None
            and record.status == "completed"
            for arm in REQUIRED_ARMS
        )
        for case in protocol.cases
    )
    return {
        "schema_version": 1,
        "classification": "reviewed_input_accounting_only",
        "protocol_digest": protocol.digest,
        "planned_cases": len(protocol.cases),
        "complete_paired_cases": complete,
        "arms": arms,
        "diagnostic_performance_admissible": False,
        "training_admissible": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Freeze private case plans once, or score supplied records read-only."""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freezer = commands.add_parser("freeze", help="write an immutable planned-case manifest")
    freezer.add_argument("--cases", type=Path, required=True)
    freezer.add_argument("--output", type=Path, required=True)
    scorer = commands.add_parser("score", help="account for every planned arm")
    scorer.add_argument("--protocol", type=Path, required=True)
    scorer.add_argument("--trajectories", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "freeze":
        raw_cases = json.loads(args.cases.read_text(encoding="utf-8"))
        if not isinstance(raw_cases, list):
            raise ValueError("case file must be an array")
        protocol = freeze_protocol(
            tuple(CasePlan.model_validate(item) for item in cast(list[object], raw_cases))
        )
        with args.output.open("x", encoding="utf-8") as output:
            output.write(protocol.model_dump_json(indent=2))
        print(
            json.dumps({"protocol_digest": protocol.digest, "planned_cases": len(protocol.cases)})
        )
        return 0
    protocol = FrozenProtocol.model_validate_json(args.protocol.read_text(encoding="utf-8"))
    raw_records = json.loads(args.trajectories.read_text(encoding="utf-8"))
    if not isinstance(raw_records, list):
        raise ValueError("trajectory file must be an array")
    report = score_trajectories(
        protocol, tuple(Trajectory.model_validate(item) for item in cast(list[object], raw_records))
    )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
