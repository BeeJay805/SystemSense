"""Controlled lab episodes with independent symptom checks and sealed fault labels.

This harness supplies only ``LabPublicSpec`` to an arm runner. It does not inject
Windows settings, run a repair, or infer diagnostic accuracy from a symptom change.
An owned loopback listener provides a safe harness self-test; actual qualification
requires a real coordinator adapter, reviewed cause labels, and lab fault recipes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import secrets
import socket
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from systemsense.evaluation.models import (
    EpisodeArtifact,
    EpisodeSpec,
    EvaluationMode,
    MeasurementSource,
)


class LabModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NumericRule(LabModel):
    """A calibrated, fixed symptom threshold, independent of the investigator."""

    lt: float | None = None
    gt: float | None = None

    @model_validator(mode="after")
    def exactly_one_finite_limit(self) -> Self:
        limits = [value for value in (self.lt, self.gt) if value is not None]
        if len(limits) != 1 or not math.isfinite(limits[0]):
            raise ValueError("exactly one finite symptom threshold is required")
        return self

    def symptom_present(self, value: float) -> bool:
        if not math.isfinite(value):
            raise ValueError("oracle values must be finite")
        if self.lt is not None:
            return value < self.lt
        assert self.gt is not None
        return value > self.gt


class OracleContract(LabModel):
    """Grading-only symptom measure; excluded from an arm's input."""

    name: str = Field(min_length=1, max_length=120)
    rule: NumericRule
    sample_count: int = Field(default=3, ge=2, le=10)


class LabPublicSpec(LabModel):
    schema_version: Literal[1] = 1
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    objective: str = Field(min_length=1, max_length=2000)
    machine_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    code_revision: str = Field(min_length=7, max_length=120)
    probe_catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    budget_ms: int = Field(ge=100, le=600_000)
    max_rounds: int = Field(ge=1, le=12)
    max_probes: int = Field(ge=1, le=64)


class SealedFault(LabModel):
    """Harness-only recipe identity and ground truth; never passed to an arm."""

    injection_id: str = Field(min_length=1, max_length=120)
    expected_cause_codes: tuple[str, ...] = Field(max_length=12)
    reset_id: str = Field(min_length=1, max_length=120)
    expected_symptom: bool = True
    nonce: str = Field(default_factory=lambda: secrets.token_hex(16), pattern=r"^[0-9a-f]{32}$")

    @model_validator(mode="after")
    def causes_match_control(self) -> Self:
        if self.expected_symptom != bool(self.expected_cause_codes):
            raise ValueError("fault and healthy-control cause labels must match")
        return self


class FaultManifest(LabModel):
    schema_version: Literal[1] = 1
    public: LabPublicSpec
    oracle: OracleContract
    sealed: SealedFault

    def sealed_sha256(self) -> str:
        encoded = json.dumps(
            self.sealed.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class ArmKind(StrEnum):
    KEYWORD_BASELINE = "keyword_baseline"
    DEEP_BRAIN_ONLY = "deep_brain_only"
    DUAL_BRAIN = "dual_brain"


class ArmSpec(LabModel):
    """Pre-registered arm settings; cold/warm state is not yet independently enforced."""

    kind: ArmKind
    warm_state: Literal["cold", "warm"]
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision_provider_id: str = Field(min_length=1, max_length=80)
    reasoning_provider_id: str = Field(min_length=1, max_length=80)


class RunIdentity(LabModel):
    """Arm-reported fingerprint, structurally matched but not independently attested."""

    machine_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    probe_catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    warm_state: Literal["cold", "warm"]


class ArmResult(LabModel):
    """Arm output. A real coordinator recording is required for quality review."""

    claimed_fixed: bool
    claimed_cause_codes: tuple[str, ...] = ()
    cited_evidence_ids: tuple[str, ...] = ()
    action_execution_id: str | None = Field(default=None, min_length=1, max_length=120)
    proposal_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    target_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    episode: EpisodeArtifact | None = None
    evidence_store_id: str | None = Field(default=None, pattern=r"^db_[0-9a-f]{32}$")
    run_identity: RunIdentity | None = None


class ActionJournalProof(LabModel):
    """A separate journal lookup result, never supplied by the model arm."""

    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    action_execution_id: str = Field(min_length=1, max_length=120)
    journal_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    terminal_outcome: Literal["verified", "failed", "rolled_back"]
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def completed_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("action completion time must be UTC")
        return value


class OracleReading(LabModel):
    value: float
    observed_at: datetime
    symptom_present: bool

    @field_validator("value")
    @classmethod
    def finite_value(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("oracle values must be finite")
        return value


class TrialStatus(StrEnum):
    VALID = "valid"
    INVALID_BASELINE = "invalid_baseline"
    INVALID_INJECTION = "invalid_injection"
    INVALID_RESTORE = "invalid_restore"
    INJECTION_ERROR = "injection_error"
    ARM_ERROR = "arm_error"
    ORACLE_ERROR = "oracle_error"


class LabTrial(LabModel):
    arm: ArmSpec
    status: TrialStatus
    clean: tuple[OracleReading, ...]
    injected: tuple[OracleReading, ...]
    after_arm: tuple[OracleReading, ...]
    after_restore: tuple[OracleReading, ...]
    arm_elapsed_ms: float | None = Field(default=None, ge=0)
    arm_result: ArmResult | None = None
    false_fix: bool = False
    false_positive_repair: bool = False
    action_journal_verified: bool = False
    action_journal_proof: ActionJournalProof | None = None
    symptom_recovered_after_action: bool = False
    repair_verified: Literal[False] = False
    reference_recovery_verified: bool = False
    reset_state_verified: Literal[False] = False
    error_type: str | None = Field(default=None, max_length=120)


class LabResult(LabModel):
    schema_version: Literal[1] = 1
    classification: Literal["controlled_lab_rehearsal"] = "controlled_lab_rehearsal"
    public: LabPublicSpec
    oracle: OracleContract
    sealed_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trials: tuple[LabTrial, ...] = Field(min_length=1, max_length=16)
    diagnostic_accuracy_claim: Literal[False] = False


class FaultController(Protocol):
    def inject(self) -> None: ...

    def restore(self) -> None: ...


class SymptomOracle(Protocol):
    def sample_value(self) -> float: ...


class ArmRunner(Protocol):
    def __call__(self, public: LabPublicSpec, arm: ArmSpec, /) -> ArmResult: ...


class ActionJournalVerifier(Protocol):
    """Independent lookup of an exact case/action pair in an execution journal."""

    def __call__(self, case_id: str, action_execution_id: str, /) -> ActionJournalProof | None: ...


class LabEpisodeHarness:
    """Run matched arms from a clean state with sealed cause and real oracle checks."""

    def run(
        self,
        *,
        manifest: FaultManifest,
        oracle: SymptomOracle,
        fault: FaultController,
        arms: tuple[ArmSpec, ...],
        run_arm: ArmRunner,
        verify_action: ActionJournalVerifier | None = None,
    ) -> LabResult:
        if not arms or len(arms) > 16:
            raise ValueError("between one and sixteen arms are required")
        trials: list[LabTrial] = []
        seen_case_ids: set[str] = set()
        for arm in arms:
            trial = self._trial(
                manifest.public,
                manifest.oracle,
                manifest.sealed.expected_symptom,
                oracle,
                fault,
                arm,
                run_arm,
                verify_action,
            )
            episode = trial.arm_result.episode if trial.arm_result is not None else None
            if episode is not None:
                case_id = str(episode.case_id)
                if case_id in seen_case_ids:
                    trial = trial.model_copy(
                        update={
                            "status": TrialStatus.ARM_ERROR,
                            "error_type": "CaseReused",
                            "repair_verified": False,
                            "action_journal_verified": False,
                            "symptom_recovered_after_action": False,
                        }
                    )
                seen_case_ids.add(case_id)
            trials.append(trial)
            if trial.status in {TrialStatus.INVALID_BASELINE, TrialStatus.INVALID_RESTORE}:
                break
        return LabResult(
            public=manifest.public,
            oracle=manifest.oracle,
            sealed_sha256=manifest.sealed_sha256(),
            trials=tuple(trials),
        )

    def _trial(
        self,
        public: LabPublicSpec,
        oracle_contract: OracleContract,
        expected_symptom: bool,
        oracle: SymptomOracle,
        fault: FaultController,
        arm: ArmSpec,
        run_arm: ArmRunner,
        verify_action: ActionJournalVerifier | None,
    ) -> LabTrial:
        clean: tuple[OracleReading, ...] = ()
        injected: tuple[OracleReading, ...] = ()
        after_arm: tuple[OracleReading, ...] = ()
        after_restore: tuple[OracleReading, ...] = ()
        arm_result: ArmResult | None = None
        action_journal_verified = False
        action_journal_proof: ActionJournalProof | None = None
        elapsed_ms: float | None = None
        status = TrialStatus.VALID
        error_type: str | None = None
        try:
            clean = self._sample(oracle_contract, oracle)
            if any(item.symptom_present for item in clean):
                status = TrialStatus.INVALID_BASELINE
            else:
                try:
                    fault.inject()
                except Exception as error:
                    status, error_type = TrialStatus.INJECTION_ERROR, type(error).__name__
                else:
                    injected = self._sample(oracle_contract, oracle)
                    injection_valid = (
                        all(item.symptom_present for item in injected)
                        if expected_symptom
                        else all(not item.symptom_present for item in injected)
                    )
                    if not injection_valid:
                        status = TrialStatus.INVALID_INJECTION
                    else:
                        started = time.perf_counter()
                        arm_started_at = datetime.now(UTC)
                        try:
                            arm_result = run_arm(public, arm)
                            arm_finished_at = datetime.now(UTC)
                            if arm_result.episode is not None and not self._episode_matches(
                                public,
                                arm,
                                arm_result.episode,
                                arm_result.run_identity,
                                arm_started_at=arm_started_at,
                                arm_finished_at=arm_finished_at,
                            ):
                                status, error_type = TrialStatus.ARM_ERROR, "EpisodeMismatch"
                        except Exception as error:
                            status, error_type = TrialStatus.ARM_ERROR, type(error).__name__
                        finally:
                            elapsed_ms = (time.perf_counter() - started) * 1000
                        after_arm = self._sample(oracle_contract, oracle)
                        if (
                            status is TrialStatus.VALID
                            and verify_action is not None
                            and arm_result is not None
                            and arm_result.episode is not None
                            and arm_result.action_execution_id is not None
                        ):
                            try:
                                action_journal_proof = verify_action(
                                    str(arm_result.episode.case_id),
                                    arm_result.action_execution_id,
                                )
                                if action_journal_proof is not None:
                                    if (
                                        action_journal_proof.case_id
                                        != str(arm_result.episode.case_id)
                                        or action_journal_proof.action_execution_id
                                        != arm_result.action_execution_id
                                        or action_journal_proof.proposal_digest
                                        != arm_result.proposal_digest
                                        or action_journal_proof.target_digest
                                        != arm_result.target_digest
                                    ):
                                        status, error_type = (
                                            TrialStatus.ARM_ERROR,
                                            "JournalMismatch",
                                        )
                                    else:
                                        action_journal_verified = bool(
                                            action_journal_proof.terminal_outcome == "verified"
                                            and injected
                                            and after_arm
                                            and injected[-1].observed_at
                                            < action_journal_proof.completed_at
                                            <= after_arm[0].observed_at
                                        )
                            except Exception as error:
                                status, error_type = (
                                    TrialStatus.ARM_ERROR,
                                    type(error).__name__,
                                )
        except Exception as error:
            status, error_type = TrialStatus.ORACLE_ERROR, type(error).__name__
        finally:
            try:
                fault.restore()
                after_restore = self._sample(oracle_contract, oracle)
                if any(item.symptom_present for item in after_restore):
                    status = TrialStatus.INVALID_RESTORE
            except Exception as error:
                status, error_type = TrialStatus.INVALID_RESTORE, type(error).__name__
        resolved = bool(after_arm) and all(not item.symptom_present for item in after_arm)
        false_fix = bool(
            expected_symptom
            and arm_result
            and arm_result.claimed_fixed
            and after_arm
            and not resolved
        )
        false_positive_repair = bool(
            not expected_symptom
            and arm_result
            and (arm_result.claimed_fixed or arm_result.action_execution_id)
        )
        symptom_recovered_after_action = bool(
            status is TrialStatus.VALID
            and expected_symptom
            and arm_result
            and arm_result.claimed_fixed
            and arm_result.action_execution_id
            and arm_result.episode is not None
            and action_journal_verified
            and resolved
        )
        reference_recovery_verified = bool(
            expected_symptom
            and not resolved
            and injected
            and all(item.symptom_present for item in injected)
            and after_restore
            and all(not item.symptom_present for item in after_restore)
        )
        return LabTrial(
            arm=arm,
            status=status,
            clean=clean,
            injected=injected,
            after_arm=after_arm,
            after_restore=after_restore,
            arm_elapsed_ms=elapsed_ms,
            arm_result=arm_result,
            false_fix=false_fix,
            false_positive_repair=false_positive_repair,
            action_journal_verified=action_journal_verified,
            action_journal_proof=action_journal_proof,
            symptom_recovered_after_action=symptom_recovered_after_action,
            reference_recovery_verified=reference_recovery_verified,
            error_type=error_type,
        )

    @staticmethod
    def _sample(
        oracle_contract: OracleContract, oracle: SymptomOracle
    ) -> tuple[OracleReading, ...]:
        readings: list[OracleReading] = []
        for _ in range(oracle_contract.sample_count):
            value = oracle.sample_value()
            readings.append(
                OracleReading(
                    value=value,
                    observed_at=datetime.now(UTC),
                    symptom_present=oracle_contract.rule.symptom_present(value),
                )
            )
        return tuple(readings)

    @staticmethod
    def _episode_matches(
        public: LabPublicSpec,
        arm: ArmSpec,
        episode: EpisodeArtifact,
        run_identity: RunIdentity | None,
        *,
        arm_started_at: datetime,
        arm_finished_at: datetime,
    ) -> bool:
        expected_mode = (
            EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC
            if arm.kind is ArmKind.KEYWORD_BASELINE
            else EvaluationMode.CONFIGURED_PROVIDERS
        )
        return (
            run_identity is not None
            and run_identity.machine_fingerprint == public.machine_fingerprint
            and run_identity.probe_catalog_digest == public.probe_catalog_digest
            and run_identity.profile_digest == arm.profile_digest
            and run_identity.warm_state == arm.warm_state
            and episode.scenario_id == public.scenario_id
            and episode.objective == public.objective
            and episode.budget_ms == public.budget_ms
            and episode.max_rounds == public.max_rounds
            and episode.max_probes == public.max_probes
            and episode.measurement_source is MeasurementSource.LIVE
            and episode.mode is expected_mode
            and episode.decision.provider_id == arm.decision_provider_id
            and episode.reasoning.provider_id == arm.reasoning_provider_id
            and arm_started_at <= episode.started_at <= episode.finished_at <= arm_finished_at
        )


class OwnedLoopbackListener:
    """Only owns an ephemeral 127.0.0.1 TCP listener; useful for harness self-tests."""

    def __init__(self) -> None:
        self._socket: socket.socket | None = self._bind(0)
        self.port = self._socket.getsockname()[1]

    @staticmethod
    def _bind(port: int) -> socket.socket:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(8)
            listener.settimeout(0.3)
            return listener
        except OSError:
            listener.close()
            raise

    def inject(self) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def restore(self) -> None:
        if self._socket is None:
            self._socket = self._bind(self.port)

    def sample_value(self) -> float:
        if self._socket is None:
            return 0.0
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.3):
                accepted, _ = self._socket.accept()
                accepted.close()
                return 1.0
        except OSError:
            return 0.0

    def close(self) -> None:
        self.inject()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def run_owned_loopback_rehearsal(
    *,
    code_revision: str,
    database_path: Path,
    budget_ms: int = 30_000,
) -> LabResult:
    """Exercise the real Windows coordinator around an owned local listener fault.

    The harness closes only its own ephemeral listener. A reference rebind proves
    that the symptom can recover; it is never counted as a SystemSense repair.
    This is a measurement-pipeline rehearsal, not a Windows diagnostic score.
    """

    if os.name != "nt":
        raise RuntimeError("the live loopback rehearsal requires Windows")
    if database_path.exists():
        raise FileExistsError(f"lab database already exists: {database_path}")
    from systemsense.application.bootstrap import default_investigator
    from systemsense.evaluation.recorder import EpisodeRecorder
    from systemsense.evaluation.tracking import (
        TrackedDecisionProvider,
        TrackedReasoningProvider,
    )
    from systemsense.packs.runtime import default_probe_definitions
    from systemsense.storage.sqlite_store import SQLiteStore

    platform_identity = platform.uname()
    machine_digest = _digest(
        {
            "system": platform_identity.system,
            "release": platform_identity.release,
            "version": platform_identity.version,
            "machine": platform_identity.machine,
            "processor": platform_identity.processor,
            "logical_cpus": os.cpu_count(),
        }
    )
    catalog_digest = _digest(
        [item.manifest.model_dump(mode="json") for item in default_probe_definitions()]
    )
    profile_digest = _digest(
        {"decision": "keyword-baseline", "reasoning": "deterministic-reviewed"}
    )
    evidence_store_id = f"db_{secrets.token_hex(16)}"
    with OwnedLoopbackListener() as listener:
        public = LabPublicSpec(
            scenario_id="lab.owned-loopback-listener",
            objective=(
                f"Why is the owned local TCP listener at 127.0.0.1:{listener.port} "
                "unreachable? Identify the observed listener state and uncertainty."
            ),
            machine_fingerprint=machine_digest,
            code_revision=code_revision,
            probe_catalog_digest=catalog_digest,
            budget_ms=budget_ms,
            max_rounds=2,
            max_probes=8,
        )
        manifest = FaultManifest(
            public=public,
            oracle=OracleContract(
                name="owned_loopback_tcp_connect",
                rule=NumericRule(lt=0.5),
                sample_count=3,
            ),
            sealed=SealedFault(
                injection_id="close-owned-loopback-listener-v1",
                expected_cause_codes=("owned_listener_stopped",),
                reset_id="rebind-owned-loopback-listener-v1",
            ),
        )
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with SQLiteStore(database_path) as store:

            def run_arm(spec: LabPublicSpec, arm: ArmSpec) -> ArmResult:
                if arm.kind is not ArmKind.KEYWORD_BASELINE:
                    raise ValueError("rehearsal default runner only configures the keyword arm")
                investigator = default_investigator(store)
                decision = TrackedDecisionProvider(investigator.decision)
                reasoning = TrackedReasoningProvider(investigator.reasoning)
                investigator.decision = decision
                investigator.reasoning = reasoning
                episode = EpisodeRecorder().record(
                    investigator=investigator,
                    decision=decision,
                    reasoning=reasoning,
                    spec=EpisodeSpec(
                        scenario_id=spec.scenario_id,
                        objective=spec.objective,
                        measurement_source=MeasurementSource.LIVE,
                        synthetic=True,
                        mode=EvaluationMode.KEYWORD_BASELINE_DETERMINISTIC,
                        budget_ms=spec.budget_ms,
                        max_rounds=spec.max_rounds,
                        max_probes=spec.max_probes,
                    ),
                )
                return ArmResult(
                    claimed_fixed=False,
                    episode=episode,
                    evidence_store_id=evidence_store_id,
                    run_identity=RunIdentity(
                        machine_fingerprint=spec.machine_fingerprint,
                        probe_catalog_digest=spec.probe_catalog_digest,
                        profile_digest=arm.profile_digest,
                        warm_state=arm.warm_state,
                    ),
                )

            return LabEpisodeHarness().run(
                manifest=manifest,
                oracle=listener,
                fault=listener,
                arms=(
                    ArmSpec(
                        kind=ArmKind.KEYWORD_BASELINE,
                        warm_state="warm",
                        profile_digest=profile_digest,
                        decision_provider_id="keyword-baseline",
                        reasoning_provider_id="deterministic-reasoning",
                    ),
                ),
                run_arm=run_arm,
            )


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-loopback-rehearsal", action="store_true", required=True)
    parser.add_argument("--code-revision", required=True)
    parser.add_argument("--budget-ms", type=int, default=30_000)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.database.resolve() == args.output.resolve():
        raise ValueError("lab database and output must use different paths")
    if args.output.exists():
        raise FileExistsError(f"lab output already exists: {args.output}")
    result = run_owned_loopback_rehearsal(
        code_revision=args.code_revision,
        database_path=args.database,
        budget_ms=args.budget_ms,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(result.model_dump_json(indent=2))
    print(json.dumps({"output": str(args.output), "status": result.trials[0].status.value}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
