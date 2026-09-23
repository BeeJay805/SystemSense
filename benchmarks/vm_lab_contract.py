"""Fail-closed admission for independently controlled Windows VM episodes.

This validates a *trusted rig controller's* protocol record against a lab
episode. It does not implement a hypervisor adapter, attest a controller's
identity cryptographically, or establish diagnostic or repair quality. An
ordinary model/arm callback must never be allowed to mint these proofs.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from typing import Literal

from pydantic import Field, field_validator

from benchmarks.lab_episodes import (
    ArmKind,
    ArmSpec,
    FaultManifest,
    LabModel,
    LabResult,
    LabTrial,
    NumericRule,
    OracleReading,
    RunIdentity,
    TrialStatus,
)

type Sha256 = str


class VmRecipeId(StrEnum):
    """Fixed rig-owned recipes, never commands, paths, URLs, or model arguments."""

    WRONG_WININET_PROXY_V1 = "vm.wrong_wininet_proxy.v1"
    HEALTHY_CONTROL_V1 = "vm.healthy_control.v1"


_RECIPE_CONTRACTS: dict[VmRecipeId, tuple[str, str, tuple[str, ...]]] = {
    VmRecipeId.WRONG_WININET_PROXY_V1: (
        "lab.vm.wininet-proxy",
        "vm-clean-checkpoint-v1",
        ("wininet_proxy_wrong_server",),
    ),
    VmRecipeId.HEALTHY_CONTROL_V1: (
        "lab.vm.healthy-control",
        "vm-clean-checkpoint-v1",
        (),
    ),
}


class VmRecipe(LabModel):
    recipe_id: VmRecipeId
    seed: int = Field(ge=0, le=2**63 - 1)
    image_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    clean_state_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    fault_signature_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")


class VmRigAttestation(LabModel):
    vm_id: str = Field(pattern=r"^vm_[0-9a-f]{32}$")
    hypervisor: Literal["hyper_v", "virtualbox", "qemu"]
    rig_controller_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,79}$")
    image_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    checkpoint_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    machine_fingerprint: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    probe_catalog_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    code_revision: str = Field(min_length=7, max_length=120)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def utc_observation(cls, value: datetime) -> datetime:
        return _require_utc(value)


class VmResetProof(LabModel):
    """Issued after a full VM checkpoint revert and independent state readback."""

    vm_id: str = Field(pattern=r"^vm_[0-9a-f]{32}$")
    checkpoint_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    generation_id: str = Field(pattern=r"^generation-[a-z0-9-]{3,80}$")
    clean_state_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def utc_completion(cls, value: datetime) -> datetime:
        return _require_utc(value)


class VmInjectionProof(LabModel):
    vm_id: str = Field(pattern=r"^vm_[0-9a-f]{32}$")
    generation_id: str = Field(pattern=r"^generation-[a-z0-9-]{3,80}$")
    recipe_id: VmRecipeId
    seed: int = Field(ge=0, le=2**63 - 1)
    fault_signature_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def utc_completion(cls, value: datetime) -> datetime:
        return _require_utc(value)


class VmArmProof(LabModel):
    arm: ArmSpec
    run_identity: RunIdentity
    before: VmResetProof
    injection: VmInjectionProof
    after: VmResetProof


class VmRunProof(LabModel):
    schema_version: Literal[2] = 2
    episode_id: str = Field(min_length=4, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    attestation: VmRigAttestation
    oracle_name: str = Field(min_length=1, max_length=120)
    oracle_controller_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,79}$")
    arm_executor_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{2,79}$")
    trials: tuple[VmArmProof, ...] = Field(min_length=1, max_length=16)


class VmArmBinding(LabModel):
    kind: ArmKind
    trial_status: TrialStatus
    warm_state: Literal["cold", "warm"]
    profile_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    reset_proof_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    trial_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")


class VmProtocolBinding(LabModel):
    """Content and identity links, not an attestation of their real-world origin."""

    manifest_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    episode_id: str = Field(min_length=4, max_length=120, pattern=r"^[a-z0-9][a-z0-9_.-]+$")
    result_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    recipe_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    proof_digest: Sha256 = Field(pattern=r"^[0-9a-f]{64}$")
    scenario_id: str
    fault_recipe_id: VmRecipeId
    sealed_cause_codes: tuple[str, ...]
    expected_symptom: bool
    oracle_rule: NumericRule
    common_budget_ms: int
    rig_controller_id: str
    oracle_controller_id: str
    arm_executor_id: str
    arms: tuple[VmArmBinding, ...]


class VmProtocolAdmission(LabModel):
    schema_version: Literal[2] = 2
    classification: Literal["vm_protocol_only"] = "vm_protocol_only"
    protocol_admitted: bool
    reason_codes: tuple[str, ...]
    binding: VmProtocolBinding
    diagnostic_accuracy_claim: Literal[False] = False
    repair_verified: Literal[False] = False


def vm_record_digest(record: LabModel) -> Sha256:
    """Canonical content digest; a caller can still forge the content itself."""

    encoded = json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def admit_vm_run(
    manifest: FaultManifest,
    result: LabResult,
    recipe: VmRecipe,
    proof: VmRunProof,
) -> VmProtocolAdmission:
    """Check rig protocol integrity; keep every arm failure in the result.

    A passing result is eligible for later blinded cause review, not a verified
    repair. The calling rig must be independently audited and isolated from the
    arm. This function cannot establish that merely from JSON fields.
    """

    reasons: set[str] = set()
    attestation = proof.attestation
    if (
        result.public != manifest.public
        or result.oracle != manifest.oracle
        or result.sealed_sha256 != manifest.sealed_sha256()
    ):
        reasons.add("manifest_mismatch")
    expected_scenario, expected_reset, expected_causes = _RECIPE_CONTRACTS[recipe.recipe_id]
    if (
        recipe.recipe_id.value != manifest.sealed.injection_id
        or (recipe.recipe_id is VmRecipeId.HEALTHY_CONTROL_V1)
        != (not manifest.sealed.expected_symptom)
        or manifest.public.scenario_id != expected_scenario
        or manifest.sealed.reset_id != expected_reset
        or manifest.sealed.expected_cause_codes != expected_causes
    ):
        reasons.add("recipe_mismatch")
    if (
        attestation.machine_fingerprint != manifest.public.machine_fingerprint
        or attestation.probe_catalog_digest != manifest.public.probe_catalog_digest
        or attestation.code_revision != manifest.public.code_revision
        or attestation.image_digest != recipe.image_digest
        or attestation.checkpoint_digest != recipe.checkpoint_digest
    ):
        reasons.add("rig_identity_mismatch")
    if (
        proof.oracle_name != manifest.oracle.name
        or len(
            {
                proof.oracle_controller_id,
                proof.arm_executor_id,
                attestation.rig_controller_id,
            }
        )
        != 3
    ):
        reasons.add("nonindependent_oracle")
    if len(result.trials) != len(proof.trials):
        reasons.add("trial_count_mismatch")

    generations: set[str] = set()
    for trial, arm_proof in zip(result.trials, proof.trials, strict=False):
        before, injection, after = arm_proof.before, arm_proof.injection, arm_proof.after
        if (
            not _is_utc(attestation.observed_at)
            or not _is_utc(before.completed_at)
            or not timedelta(0)
            <= before.completed_at - attestation.observed_at
            <= timedelta(minutes=5)
        ):
            reasons.add("attestation_stale")
        if (
            trial.arm != arm_proof.arm
            or arm_proof.run_identity.machine_fingerprint != manifest.public.machine_fingerprint
            or arm_proof.run_identity.probe_catalog_digest != manifest.public.probe_catalog_digest
            or arm_proof.run_identity.profile_digest != trial.arm.profile_digest
            or arm_proof.run_identity.warm_state != trial.arm.warm_state
            or (
                trial.arm_result is not None
                and trial.arm_result.run_identity is not None
                and trial.arm_result.run_identity != arm_proof.run_identity
            )
        ):
            reasons.add("arm_identity_mismatch")
        if (
            before.vm_id != attestation.vm_id
            or after.vm_id != attestation.vm_id
            or before.checkpoint_digest != recipe.checkpoint_digest
            or after.checkpoint_digest != recipe.checkpoint_digest
            or before.clean_state_digest != recipe.clean_state_digest
            or after.clean_state_digest != recipe.clean_state_digest
        ):
            reasons.add("reset_state_mismatch")
        if (
            before.generation_id == after.generation_id
            or before.generation_id in generations
            or after.generation_id in generations
        ):
            reasons.add("generation_reused")
        generations.update((before.generation_id, after.generation_id))
        if (
            injection.vm_id != attestation.vm_id
            or injection.generation_id != before.generation_id
            or injection.recipe_id != recipe.recipe_id
            or injection.seed != recipe.seed
            or injection.fault_signature_digest != recipe.fault_signature_digest
        ):
            reasons.add("fault_proof_mismatch")
        if (
            len(trial.clean) != manifest.oracle.sample_count
            or len(trial.injected) != manifest.oracle.sample_count
            or len(trial.after_arm) != manifest.oracle.sample_count
            or len(trial.after_restore) != manifest.oracle.sample_count
            or any(item.symptom_present for item in trial.clean)
            or any(
                item.symptom_present != manifest.sealed.expected_symptom for item in trial.injected
            )
            or any(item.symptom_present for item in trial.after_restore)
            or trial.status not in {TrialStatus.VALID, TrialStatus.ARM_ERROR}
            or any(
                _inconsistent_reading(manifest, item)
                for reading_set in (
                    trial.clean,
                    trial.injected,
                    trial.after_arm,
                    trial.after_restore,
                )
                for item in reading_set
            )
        ):
            reasons.add("oracle_sequence_invalid")
        if trial.status is TrialStatus.VALID and (
            trial.arm_result is None or trial.arm_result.episode is None
        ):
            reasons.add("episode_missing")
        if (
            not trial.clean
            or not trial.injected
            or not trial.after_arm
            or not trial.after_restore
            or not _ordered_episode(attestation, arm_proof, trial)
        ):
            reasons.add("event_order_invalid")
    return VmProtocolAdmission(
        protocol_admitted=not reasons,
        reason_codes=tuple(sorted(reasons)),
        binding=VmProtocolBinding(
            manifest_digest=vm_record_digest(manifest),
            episode_id=proof.episode_id,
            result_digest=vm_record_digest(result),
            recipe_digest=vm_record_digest(recipe),
            proof_digest=vm_record_digest(proof),
            scenario_id=manifest.public.scenario_id,
            fault_recipe_id=recipe.recipe_id,
            sealed_cause_codes=manifest.sealed.expected_cause_codes,
            expected_symptom=manifest.sealed.expected_symptom,
            oracle_rule=manifest.oracle.rule,
            common_budget_ms=manifest.public.budget_ms,
            rig_controller_id=proof.attestation.rig_controller_id,
            oracle_controller_id=proof.oracle_controller_id,
            arm_executor_id=proof.arm_executor_id,
            arms=tuple(
                VmArmBinding(
                    kind=arm.arm.kind,
                    trial_status=trial.status,
                    warm_state=arm.arm.warm_state,
                    profile_digest=arm.arm.profile_digest,
                    reset_proof_digest=vm_record_digest(arm.before),
                    trial_digest=vm_record_digest(trial),
                )
                for trial, arm in zip(result.trials, proof.trials, strict=False)
            ),
        ),
    )


def _require_utc(value: datetime) -> datetime:
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("VM proof timestamps must be UTC")
    return value


def _inconsistent_reading(manifest: FaultManifest, reading: OracleReading) -> bool:
    try:
        return manifest.oracle.rule.symptom_present(reading.value) != reading.symptom_present
    except ValueError:
        return True


def _ordered_episode(attestation: VmRigAttestation, proof: VmArmProof, trial: LabTrial) -> bool:
    sequences = (trial.clean, trial.injected, trial.after_arm, trial.after_restore)
    stamps = (
        attestation.observed_at,
        proof.before.completed_at,
        proof.injection.completed_at,
        proof.after.completed_at,
        *(item.observed_at for sequence in sequences for item in sequence),
    )
    if not all(_is_utc(stamp) for stamp in stamps):
        return False
    if any(
        left.observed_at > right.observed_at
        for sequence in sequences
        for left, right in pairwise(sequence)
    ):
        return False
    return (
        attestation.observed_at
        <= proof.before.completed_at
        < trial.clean[0].observed_at
        <= trial.clean[-1].observed_at
        < proof.injection.completed_at
        < trial.injected[0].observed_at
        <= trial.injected[-1].observed_at
        < trial.after_arm[0].observed_at
        <= trial.after_arm[-1].observed_at
        < proof.after.completed_at
        < trial.after_restore[0].observed_at
    )


def _is_utc(value: datetime) -> bool:
    offset = value.utcoffset()
    return offset is not None and offset.total_seconds() == 0
