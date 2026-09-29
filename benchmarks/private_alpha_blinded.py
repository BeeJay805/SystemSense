"""Offline, evaluator-only development comparison; never opens a recipe or runs a case.

The custodian freezes per-case rubrics and contracts before execution, exports
arm-neutral packets, obtains independent semantic reviews, then joins reviews
back to receipts. A review is a judgment, not machine proof of a causal claim.
Receipt fields must come from independently verified execution artifacts; this
module checks consistency, not whether a supplied runtime identity is truthful.

Basic, deep-led, and Laya/deep have the same evidence access, typed registry and
resource ceilings. Different actual probe choices are the treatment. Deep-led
must be a real route with actual provider receipts; it is currently unavailable.
Missing arms remain missing, and no synthetic route or percentage qualifies it.
The original attempts and artifacts remain immutable outside this scorer.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from typing import Any

ARMS = ("basic", "deep_led", "laya_deep")
_USEFUL = {"bounded_distinction", "supported_cause", "observed_resolution"}
_CLASSIFICATIONS = _USEFUL | {"observation_only", "unresolved", "incorrect"}


def digest(value: dict[str, Any]) -> str:
    """Canonical JSON hash binds the review to the exact exported packet."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def blind_packet(product: dict[str, Any], review_token: str) -> dict[str, Any]:
    """Remove arm/runner labels; product wording can still reveal its origin.

    The input must be the saved product-case artifact, never an evaluator file.
    Evidence is retained intact so reviewers can assess identity, time, citations
    and omissions. Blinding does not redact misleading claims from the summary.
    A custodian stores token-to-arm mapping privately and hashes this packet.
    """
    if not review_token:
        raise ValueError("an opaque review token is required")
    return {
        "schema_version": 1,
        "review_token": review_token,
        "summary": product.get("summary"),
        "status": product.get("status"),
        "outcome": product.get("outcome"),
        "evidence": product.get("evidence", []),
    }


@dataclass(frozen=True)
class Contract:
    """Frozen pre-run per-case contract, identical across all three arms.

    Access includes input evidence, consent scope, initial state recipe digest,
    and collector permissions. The registry digest includes probe parameters.
    Advisory token ceiling is shared even though Basic consumes no model tokens.
    """

    source_revision: str
    source_tree_sha256: str
    manifest_sha256: str
    rubric_sha256: str
    objective_sha256: str
    access_sha256: str
    registry_sha256: str
    budget_ms: int
    max_rounds: int
    max_probe_calls: int
    max_advisory_tokens: int


@dataclass(frozen=True)
class Trial:
    case_id: str
    arm: str
    contract: Contract
    packet_sha256: str
    evidence_ids: tuple[str, ...]
    execution_receipt_sha256: str
    runtime_identity: str
    completed: bool
    control_verified: bool
    independent_target_verified: bool
    restoration_verified: bool
    cleanup_verified: bool
    elapsed_ms: float
    probe_calls: int
    advisory_tokens: int
    rounds: int


@dataclass(frozen=True)
class Review:
    """Custodian joins blinded review to case/arm only after review is locked.

    A rubric must define a useful distinction for this particular task before
    execution. Repeating a symptom or saying unknown alone earns no diagnostic
    credit. A true lack of recurrence may earn observed-resolution credit only
    when the rubric calls for that bounded task and preserves the earlier gap.
    """

    case_id: str
    arm: str
    packet_sha256: str
    rubric_sha256: str
    reviewer_id: str
    classification: str
    rubric_satisfied: bool
    citations: tuple[str, ...]
    target_and_time_supported: bool
    rivals_and_limits_preserved: bool
    unsupported_cause: bool
    false_healthy_claim: bool
    rationale: str


def _hex(value: str, size: int) -> bool:
    return len(value) == size and all(c in "0123456789abcdef" for c in value)


def _valid_contract(contract: Contract) -> bool:
    return (
        _hex(contract.source_revision, 40)
        and all(
            _hex(value, 64)
            for value in (
                contract.manifest_sha256,
                contract.source_tree_sha256,
                contract.rubric_sha256,
                contract.objective_sha256,
                contract.access_sha256,
                contract.registry_sha256,
            )
        )
        and all(
            type(value) is int and value > 0
            for value in (
                contract.budget_ms,
                contract.max_rounds,
                contract.max_probe_calls,
                contract.max_advisory_tokens,
            )
        )
    )


def _eligible(trial: Trial) -> bool:
    return (
        trial.completed
        and trial.control_verified
        and trial.independent_target_verified
        and trial.restoration_verified
        and trial.cleanup_verified
        and bool(trial.runtime_identity.strip())
        and _hex(trial.execution_receipt_sha256, 64)
        and _hex(trial.packet_sha256, 64)
        and math.isfinite(trial.elapsed_ms)
        and 0 <= trial.elapsed_ms <= trial.contract.budget_ms
        and 0 <= trial.probe_calls <= trial.contract.max_probe_calls
        and 0 <= trial.rounds <= trial.contract.max_rounds
        and 0 <= trial.advisory_tokens <= trial.contract.max_advisory_tokens
        and (trial.arm != "basic" or trial.advisory_tokens == 0)
    )


def compare(
    frozen_case_ids: tuple[str, ...],
    trials: list[Trial],
    reviews: list[Review],
    *,
    split: str = "development",
) -> dict[str, Any]:
    """Score every planned slot once, retaining missing/failed arms as failures.

    This development tool intentionally refuses holdouts. A future holdout
    executor needs a separately frozen consumption ledger and authorization.
    No omitted-case denominator, best-attempt selection, or causal automation.
    """
    if split != "development":
        raise ValueError("only development comparison is enabled; holdouts remain sealed")
    if not frozen_case_ids or len(set(frozen_case_ids)) != len(frozen_case_ids):
        raise ValueError("nonempty unique frozen case IDs required")
    indexed: dict[tuple[str, str], Trial] = {}
    contracts: dict[str, Contract] = {}
    for trial in trials:
        slot = (trial.case_id, trial.arm)
        if trial.case_id not in frozen_case_ids or trial.arm not in ARMS:
            raise ValueError("unplanned case or arm")
        if slot in indexed:
            raise ValueError("duplicate attempt; preserve and score attempts separately")
        if not _valid_contract(trial.contract):
            raise ValueError("invalid frozen contract")
        if trial.case_id in contracts and trial.contract != contracts[trial.case_id]:
            raise ValueError("matched contract differs across arms")
        contracts[trial.case_id] = trial.contract
        indexed[slot] = trial
    judged: dict[tuple[str, str], Review] = {}
    for review in reviews:
        slot = (review.case_id, review.arm)
        trial = indexed.get(slot)
        if slot in judged:
            raise ValueError("duplicate review")
        if (
            trial is None
            or review.packet_sha256 != trial.packet_sha256
            or review.rubric_sha256 != trial.contract.rubric_sha256
            or not review.reviewer_id.strip()
            or not review.rationale.strip()
            or review.classification not in _CLASSIFICATIONS
        ):
            raise ValueError("invalid review binding or incomplete semantic judgment")
        judged[slot] = review
    rows: list[dict[str, Any]] = []
    for case_id in frozen_case_ids:
        for arm in ARMS:
            trial, review = indexed.get((case_id, arm)), judged.get((case_id, arm))
            eligible = trial is not None and _eligible(trial)
            useful = bool(
                eligible
                and trial is not None
                and review is not None
                and review.classification in _USEFUL
                and review.rubric_satisfied
                and review.citations
                and set(review.citations).issubset(trial.evidence_ids)
                and review.target_and_time_supported
                and review.rivals_and_limits_preserved
                and not review.unsupported_cause
                and not review.false_healthy_claim
            )
            rows.append(
                {
                    "case_id": case_id,
                    "arm": arm,
                    "executed": trial is not None,
                    "eligible": eligible,
                    "reviewed": review is not None,
                    "useful": useful,
                    "classification": None if review is None else review.classification,
                    "unsupported_cause": None if review is None else review.unsupported_cause,
                    "false_healthy_claim": None if review is None else review.false_healthy_claim,
                    "elapsed_ms": None if trial is None else trial.elapsed_ms,
                    "packet_sha256": None if trial is None else trial.packet_sha256,
                    "execution_receipt_sha256": (
                        None if trial is None else trial.execution_receipt_sha256
                    ),
                    "contract": None if trial is None else asdict(trial.contract),
                    "runtime_identity": None if trial is None else trial.runtime_identity,
                    "review": None if review is None else asdict(review),
                }
            )
    return {
        "schema_version": 1,
        "split": split,
        "qualification": "development_only; semantic judgments and receipt custody required",
        "count_per_arm": len(frozen_case_ids),
        "cases": rows,
        "matched_complete_cases": sum(
            all(row["eligible"] and row["reviewed"] for row in rows if row["case_id"] == cid)
            for cid in frozen_case_ids
        ),
        "useful_by_arm": {
            arm: sum(row["useful"] for row in rows if row["arm"] == arm) for arm in ARMS
        },
    }
