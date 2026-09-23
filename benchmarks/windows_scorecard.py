"""Conservative paired scorecard for externally qualified real Windows episodes.

``LabResult`` is always a controlled-lab rehearsal, and ``VmProtocolAdmission``
is only a protocol check. Neither is a performance result. This module accepts
separate, independently reviewed records; a trusted rig/reviewer must create
and authenticate those records outside this scorer. Their identifiers and
digests are consistency checks, not cryptographic attestation by this module.
Tests of this module use invented records and prove only validation and math.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

from benchmarks.lab_episodes import ArmKind, LabModel, NumericRule
from benchmarks.vm_lab_contract import VmProtocolAdmission

_REQUIRED_ARMS = frozenset(ArmKind)
_Z95 = 1.959963984540054


class ArmOutcome(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class IndependentQualification(LabModel):
    """External issuer's record identity; this scorer does not verify its issuer."""

    qualification_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rig_controller_id: str = Field(min_length=3, max_length=120)
    oracle_controller_id: str = Field(min_length=3, max_length=120)
    reviewer_id: str = Field(min_length=3, max_length=120)
    arm_executor_id: str = Field(min_length=3, max_length=120)


class ReviewedArm(LabModel):
    """One arm's externally timed, oracle-checked, reviewer-adjudicated result."""

    kind: ArmKind
    status: ArmOutcome
    warm_state: Literal["cold", "warm"]
    access_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    reset_proof_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    wall_ms: float = Field(ge=0, allow_inf_nan=False)
    claimed_cause_codes: tuple[str, ...] = Field(max_length=12)
    cause_supported: bool
    claimed_fixed: bool
    repair_attempted: bool
    repair_appropriate: bool | None
    action_journal_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    oracle_before: tuple[float, ...] = Field(min_length=2, max_length=10)
    oracle_after: tuple[float, ...] = Field(min_length=2, max_length=10)
    oracle_started_at: datetime
    oracle_finished_at: datetime
    oracle_record_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    recovery_reviewed: bool

    @field_validator("oracle_before", "oracle_after")
    @classmethod
    def finite_oracle_samples(cls, values: tuple[float, ...]) -> tuple[float, ...]:
        if not all(math.isfinite(value) for value in values):
            raise ValueError("oracle samples must be finite")
        return values


class ReviewedWindowsEpisode(LabModel):
    """One matched A/B/C fault episode, admitted by an external Windows rig.

    Unlike the existing rehearsal and VM protocol shapes, this is explicitly a
    *reviewed input*. The scorecard never converts a rehearsal into one.
    """

    schema_version: Literal[1] = 1
    episode_id: str = Field(min_length=4, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    source: Literal["independent_windows_vm", "independent_windows_physical"]
    scenario_id: str = Field(min_length=3, max_length=120)
    fault_recipe_id: str = Field(min_length=3, max_length=120)
    sealed_cause_codes: tuple[str, ...] = Field(max_length=12)
    expected_symptom: bool
    oracle_rule: NumericRule
    common_budget_ms: int = Field(ge=100, le=600_000)
    qualification: IndependentQualification
    vm_protocol: VmProtocolAdmission | None
    arms: tuple[ReviewedArm, ...] = Field(min_length=3, max_length=3)

    @model_validator(mode="after")
    def coherent_fault_label(self) -> Self:
        if self.expected_symptom != bool(self.sealed_cause_codes):
            raise ValueError("sealed cause labels must match symptom/control status")
        return self


@dataclass(frozen=True, slots=True)
class Interval:
    low: float
    high: float


@dataclass(frozen=True, slots=True)
class RateScore:
    n: int
    count: int
    fraction: float
    ci95_low: float
    ci95_high: float


@dataclass(frozen=True, slots=True)
class WallTimeScore:
    n: int
    p50_ms: float
    p95_ms: float
    p50_ci95_ms: Interval | None
    p95_ci95_ms: Interval | None
    uncertainty_note: str


@dataclass(frozen=True, slots=True)
class ArmScore:
    kind: ArmKind
    n: int
    failed: int
    timed_out: int
    cause_accuracy: RateScore
    false_fix: RateScore
    verified_recovery: RateScore
    wall_time: WallTimeScore


@dataclass(frozen=True, slots=True)
class PairedDifference:
    baseline: ArmKind
    comparator: ArmKind
    cause_accuracy_fraction: float
    false_fix_fraction: float
    verified_recovery_fraction: float
    cause_ci95: Interval | None
    false_fix_ci95: Interval | None
    recovery_ci95: Interval | None


@dataclass(frozen=True, slots=True)
class WindowsScorecard:
    episode_count: int
    evidence_class: Literal["reviewed_input_only"]
    source: Literal["independent_windows_vm", "independent_windows_physical"]
    warm_state: Literal["cold", "warm"]
    arms: tuple[ArmScore, ...]
    paired_differences: tuple[PairedDifference, ...]
    limitation: str


@dataclass(frozen=True, slots=True)
class _ArmBits:
    correct: int
    false_fix: int
    recovery: int
    wall_ms: float
    failed: int
    timed_out: int


def score_reviewed_episodes(episodes: tuple[ReviewedWindowsEpisode, ...]) -> WindowsScorecard:
    """Summarize matched runs; never infer a label or qualify a rig from JSON.

    Failures and timeouts each consume a denominator slot. Wall time is observed
    time to terminal state, *not* time to success; inspect recovery alongside it.
    Confidence intervals are descriptive under independent-episode sampling.
    """

    if not episodes:
        raise ValueError("at least one independently reviewed episode is required")
    ids: set[str] = set()
    qualification_digests: set[str] = set()
    reset_digests: set[str] = set()
    all_bits: list[dict[ArmKind, _ArmBits]] = []
    profiles: dict[ArmKind, str] = {}
    source: Literal["independent_windows_vm", "independent_windows_physical"] | None = None
    warm_state: Literal["cold", "warm"] | None = None
    for episode in episodes:
        if type(episode) is not ReviewedWindowsEpisode:
            raise TypeError("only independently reviewed Windows episodes are scoreable")
        episode = ReviewedWindowsEpisode.model_validate(episode.model_dump(mode="json"))
        if episode.episode_id in ids:
            raise ValueError("duplicate episode ID")
        ids.add(episode.episode_id)
        digest = episode.qualification.qualification_record_digest
        if digest in qualification_digests:
            raise ValueError("duplicate independent qualification record")
        qualification_digests.add(digest)
        if source is None:
            source = episode.source
        elif episode.source != source:
            raise ValueError("cannot pool VM and physical episodes in one scorecard")
        episode_warm_state = episode.arms[0].warm_state
        if warm_state is None:
            warm_state = episode_warm_state
        elif episode_warm_state != warm_state:
            raise ValueError("cannot pool cold and warm episodes in one scorecard")
        for arm in episode.arms:
            if arm.reset_proof_digest in reset_digests:
                raise ValueError("reset proof reused across reviewed episodes")
            reset_digests.add(arm.reset_proof_digest)
        all_bits.append(_admit_episode(episode, profiles))
    assert source is not None and warm_state is not None
    arm_scores = tuple(_arm_score(kind, [row[kind] for row in all_bits]) for kind in ArmKind)
    pairs = (
        (ArmKind.KEYWORD_BASELINE, ArmKind.DEEP_BRAIN_ONLY),
        (ArmKind.KEYWORD_BASELINE, ArmKind.DUAL_BRAIN),
        (ArmKind.DEEP_BRAIN_ONLY, ArmKind.DUAL_BRAIN),
    )
    differences = tuple(_paired_delta(a, b, all_bits) for a, b in pairs)
    return WindowsScorecard(
        episode_count=len(episodes),
        evidence_class="reviewed_input_only",
        source=source,
        warm_state=warm_state,
        arms=arm_scores,
        paired_differences=differences,
        limitation=(
            "External rig, reviewer, oracle, and journal authenticity are not established "
            "by this scorer. Time is to terminal state, not necessarily a fix; "
            "intervals assume independently sampled episodes."
        ),
    )


def _admit_episode(
    episode: ReviewedWindowsEpisode, profiles: dict[ArmKind, str]
) -> dict[ArmKind, _ArmBits]:
    if episode.source == "independent_windows_vm":
        if episode.vm_protocol is None or not episode.vm_protocol.protocol_admitted:
            raise ValueError("VM protocol admission is required in addition to independent review")
    elif episode.vm_protocol is not None:
        raise ValueError("physical Windows episodes cannot claim VM protocol admission")
    ids = (
        episode.qualification.rig_controller_id,
        episode.qualification.oracle_controller_id,
        episode.qualification.reviewer_id,
        episode.qualification.arm_executor_id,
    )
    if len(set(ids)) != 4:
        raise ValueError("rig, oracle, reviewer, and arm executor must be independent")
    kinds = [arm.kind for arm in episode.arms]
    if len(kinds) != 3 or frozenset(kinds) != _REQUIRED_ARMS:
        raise ValueError("exactly three distinct A/B/C arms are required")
    if len({arm.access_digest for arm in episode.arms}) != 1:
        raise ValueError("arms must have equal access to the registered evidence")
    if len({arm.warm_state for arm in episode.arms}) != 1:
        raise ValueError("arms must share the same cold/warm state")
    if len({arm.reset_proof_digest for arm in episode.arms}) != 3:
        raise ValueError("each arm requires a distinct reset proof")
    bits: dict[ArmKind, _ArmBits] = {}
    for arm in episode.arms:
        previous = profiles.setdefault(arm.kind, arm.profile_digest)
        if previous != arm.profile_digest:
            raise ValueError("arm profile changed across paired episodes")
        bits[arm.kind] = _admit_arm(episode, arm)
    return bits


def _admit_arm(episode: ReviewedWindowsEpisode, arm: ReviewedArm) -> _ArmBits:
    if arm.repair_attempted != (arm.repair_appropriate is not None):
        raise ValueError("attempted repairs require an explicit reviewer appropriateness label")
    if arm.status is not ArmOutcome.COMPLETED and (arm.cause_supported or arm.recovery_reviewed):
        raise ValueError("failed or timed-out arms cannot receive a supported outcome")
    if arm.cause_supported and arm.claimed_cause_codes != episode.sealed_cause_codes:
        raise ValueError("reviewer cannot endorse a cause that mismatches sealed truth")
    if (
        arm.oracle_started_at.utcoffset() is None
        or arm.oracle_started_at.utcoffset() != timedelta(0)
        or arm.oracle_finished_at.utcoffset() is None
        or arm.oracle_finished_at.utcoffset() != timedelta(0)
        or arm.oracle_finished_at < arm.oracle_started_at
    ):
        raise ValueError("oracle observation window must be ordered UTC")
    before = tuple(episode.oracle_rule.symptom_present(value) for value in arm.oracle_before)
    after = tuple(episode.oracle_rule.symptom_present(value) for value in arm.oracle_after)
    if any(present != episode.expected_symptom for present in before):
        raise ValueError("independent baseline oracle contradicts seeded symptom")
    if arm.recovery_reviewed and not (
        episode.expected_symptom
        and arm.status is ArmOutcome.COMPLETED
        and arm.repair_attempted
        and arm.repair_appropriate is True
        and arm.action_journal_digest is not None
        and all(not present for present in after)
    ):
        raise ValueError(
            "reviewed recovery requires an appropriate journaled action and oracle recovery"
        )
    false_fix = (arm.claimed_fixed and not arm.recovery_reviewed) or (
        arm.repair_attempted and arm.repair_appropriate is False
    )
    return _ArmBits(
        correct=int(arm.status is ArmOutcome.COMPLETED and arm.cause_supported),
        false_fix=int(false_fix),
        recovery=int(arm.recovery_reviewed),
        wall_ms=arm.wall_ms,
        failed=int(arm.status is ArmOutcome.FAILED),
        timed_out=int(arm.status is ArmOutcome.TIMEOUT),
    )


def _rate(values: list[int]) -> RateScore:
    n = len(values)
    count = sum(values)
    raw = count / n
    denominator = 1 + _Z95**2 / n
    center = (raw + _Z95**2 / (2 * n)) / denominator
    half = (_Z95 / denominator) * math.sqrt(raw * (1 - raw) / n + _Z95**2 / (4 * n**2))
    return RateScore(n, count, raw, max(0.0, center - half), min(1.0, center + half))


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _bootstrap(values: list[float], statistic: float) -> Interval | None:
    # Extreme quantiles are not meaningfully bounded by tiny samples. These
    # bootstrap intervals are exploratory, never a field-performance guarantee.
    minimum_n = 60 if statistic >= 0.95 else 10
    if len(values) < minimum_n:
        return None
    rng = random.Random(0x805)
    n = len(values)
    samples = sorted(
        _percentile([values[rng.randrange(n)] for _ in range(n)], statistic) for _ in range(1000)
    )
    return Interval(samples[24], samples[974])


def _arm_score(kind: ArmKind, bits: list[_ArmBits]) -> ArmScore:
    walls = [item.wall_ms for item in bits]
    return ArmScore(
        kind=kind,
        n=len(bits),
        failed=sum(item.failed for item in bits),
        timed_out=sum(item.timed_out for item in bits),
        cause_accuracy=_rate([item.correct for item in bits]),
        false_fix=_rate([item.false_fix for item in bits]),
        verified_recovery=_rate([item.recovery for item in bits]),
        wall_time=WallTimeScore(
            n=len(walls),
            p50_ms=_percentile(walls, 0.5),
            p95_ms=_percentile(walls, 0.95),
            p50_ci95_ms=_bootstrap(walls, 0.5),
            p95_ci95_ms=_bootstrap(walls, 0.95),
            uncertainty_note=(
                "Exploratory paired-episode bootstrap; p50 interval requires n>=10, "
                "p95 interval requires n>=60. Missing intervals mean insufficient sample size."
            ),
        ),
    )


def _paired_interval(values: list[int]) -> Interval | None:
    # Hoeffding's bounded-difference interval is deliberately wider than a
    # naive bootstrap, which can be spuriously zero-width with five wins.
    n = len(values)
    mean = sum(values) / n
    radius = math.sqrt(2 * math.log(40) / n)
    return Interval(max(-1.0, mean - radius), min(1.0, mean + radius))


def _paired_delta(
    baseline: ArmKind, comparator: ArmKind, rows: list[dict[ArmKind, _ArmBits]]
) -> PairedDifference:
    cause = [row[comparator].correct - row[baseline].correct for row in rows]
    false_fix = [row[comparator].false_fix - row[baseline].false_fix for row in rows]
    recovery = [row[comparator].recovery - row[baseline].recovery for row in rows]
    n = len(rows)
    return PairedDifference(
        baseline=baseline,
        comparator=comparator,
        cause_accuracy_fraction=sum(cause) / n,
        false_fix_fraction=sum(false_fix) / n,
        verified_recovery_fraction=sum(recovery) / n,
        cause_ci95=_paired_interval(cause),
        false_fix_ci95=_paired_interval(false_fix),
        recovery_ci95=_paired_interval(recovery),
    )
