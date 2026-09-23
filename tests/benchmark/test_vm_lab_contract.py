"""Contract checks for a future isolated Windows VM rig, with no host mutation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from benchmarks.lab_episodes import (
    ArmKind,
    ArmResult,
    ArmSpec,
    FaultManifest,
    LabPublicSpec,
    LabResult,
    LabTrial,
    NumericRule,
    OracleContract,
    OracleReading,
    RunIdentity,
    SealedFault,
    TrialStatus,
)
from benchmarks.vm_lab_contract import (
    VmArmProof,
    VmInjectionProof,
    VmRecipe,
    VmRecipeId,
    VmResetProof,
    VmRigAttestation,
    VmRunProof,
    admit_vm_run,
    vm_record_digest,
)

T0 = datetime(2026, 9, 22, 12, tzinfo=UTC)
VM_ID = "vm_" + "a" * 32
CLEAN = "1" * 64
FAULT = "2" * 64
CHECKPOINT = "3" * 64
IMAGE = "4" * 64
MACHINE = "5" * 64
CATALOG = "6" * 64
PROFILE = "7" * 64


def _packet() -> tuple[FaultManifest, LabResult, VmRecipe, VmRunProof]:
    public = LabPublicSpec(
        scenario_id="lab.vm.wininet-proxy",
        objective="The lab-owned HTTPS test endpoint is unreachable through WinINet.",
        machine_fingerprint=MACHINE,
        code_revision="commit-abcdef0",
        probe_catalog_digest=CATALOG,
        budget_ms=30_000,
        max_rounds=2,
        max_probes=8,
    )
    oracle = OracleContract(name="lab_https_oracle_v1", rule=NumericRule(lt=0.5))
    manifest = FaultManifest(
        public=public,
        oracle=oracle,
        sealed=SealedFault(
            injection_id=VmRecipeId.WRONG_WININET_PROXY_V1.value,
            expected_cause_codes=("wininet_proxy_wrong_server",),
            reset_id="vm-clean-checkpoint-v1",
        ),
    )
    arm = ArmSpec(
        kind=ArmKind.KEYWORD_BASELINE,
        warm_state="cold",
        profile_digest=PROFILE,
        decision_provider_id="keyword-baseline",
        reasoning_provider_id="deterministic-reviewed",
    )
    identity = RunIdentity(
        machine_fingerprint=MACHINE,
        probe_catalog_digest=CATALOG,
        profile_digest=PROFILE,
        warm_state="cold",
    )

    def readings(value: float, start: int) -> tuple[OracleReading, ...]:
        return tuple(
            OracleReading(
                value=value,
                observed_at=T0 + timedelta(seconds=start + index),
                symptom_present=value < 0.5,
            )
            for index in range(3)
        )

    trial = LabTrial(
        arm=arm,
        status=TrialStatus.ARM_ERROR,
        clean=readings(1.0, 10),
        injected=readings(0.0, 30),
        after_arm=readings(0.0, 50),
        after_restore=readings(1.0, 70),
        arm_result=ArmResult(claimed_fixed=False, run_identity=identity),
        error_type="ModelTimeout",
    )
    result = LabResult(
        public=public,
        oracle=oracle,
        sealed_sha256=manifest.sealed_sha256(),
        trials=(trial,),
    )
    recipe = VmRecipe(
        recipe_id=VmRecipeId.WRONG_WININET_PROXY_V1,
        seed=42,
        image_digest=IMAGE,
        checkpoint_digest=CHECKPOINT,
        clean_state_digest=CLEAN,
        fault_signature_digest=FAULT,
    )
    attestation = VmRigAttestation(
        vm_id=VM_ID,
        hypervisor="hyper_v",
        rig_controller_id="rig-controller",
        image_digest=IMAGE,
        checkpoint_digest=CHECKPOINT,
        machine_fingerprint=MACHINE,
        probe_catalog_digest=CATALOG,
        code_revision=public.code_revision,
        observed_at=T0,
    )
    proof = VmRunProof(
        episode_id="windows-run-0",
        attestation=attestation,
        oracle_name=oracle.name,
        oracle_controller_id="oracle-controller",
        arm_executor_id="model-worker",
        trials=(
            VmArmProof(
                arm=arm,
                run_identity=identity,
                before=VmResetProof(
                    vm_id=VM_ID,
                    checkpoint_digest=CHECKPOINT,
                    generation_id="generation-before-1",
                    clean_state_digest=CLEAN,
                    completed_at=T0 + timedelta(seconds=5),
                ),
                injection=VmInjectionProof(
                    vm_id=VM_ID,
                    generation_id="generation-before-1",
                    recipe_id=VmRecipeId.WRONG_WININET_PROXY_V1,
                    seed=42,
                    fault_signature_digest=FAULT,
                    completed_at=T0 + timedelta(seconds=25),
                ),
                after=VmResetProof(
                    vm_id=VM_ID,
                    checkpoint_digest=CHECKPOINT,
                    generation_id="generation-after-1",
                    clean_state_digest=CLEAN,
                    completed_at=T0 + timedelta(seconds=65),
                ),
            ),
        ),
    )
    return manifest, result, recipe, proof


def test_vm_contract_admits_protocol_valid_arm_failure_without_claiming_quality() -> None:
    manifest, result, recipe, proof = _packet()
    admission = admit_vm_run(manifest, result, recipe, proof)
    assert admission.protocol_admitted is True
    assert admission.reason_codes == ()
    assert admission.diagnostic_accuracy_claim is False
    assert result.trials[0].status is TrialStatus.ARM_ERROR
    assert admission.binding.manifest_digest == vm_record_digest(manifest)
    assert admission.binding.episode_id == proof.episode_id
    assert admission.binding.result_digest == vm_record_digest(result)
    assert admission.binding.recipe_digest == vm_record_digest(recipe)
    assert admission.binding.proof_digest == vm_record_digest(proof)
    assert admission.binding.arms[0].reset_proof_digest == vm_record_digest(proof.trials[0].before)
    assert admission.binding.arms[0].trial_digest == vm_record_digest(result.trials[0])


def test_vm_contract_rejects_reset_that_only_recovers_symptom() -> None:
    manifest, result, recipe, proof = _packet()
    trial = proof.trials[0]
    changed = proof.model_copy(
        update={
            "trials": (
                trial.model_copy(
                    update={"after": trial.after.model_copy(update={"clean_state_digest": FAULT})}
                ),
            )
        }
    )
    assert "reset_state_mismatch" in admit_vm_run(manifest, result, recipe, changed).reason_codes


def test_vm_contract_rejects_shared_oracle_and_rig_authority() -> None:
    manifest, result, recipe, proof = _packet()
    changed = proof.model_copy(update={"oracle_controller_id": "rig-controller"})
    assert "nonindependent_oracle" in admit_vm_run(manifest, result, recipe, changed).reason_codes


def test_vm_contract_rejects_wrong_arm_profile_and_sealed_recipe() -> None:
    manifest, result, recipe, proof = _packet()
    trial = proof.trials[0]
    changed = proof.model_copy(
        update={
            "trials": (
                trial.model_copy(
                    update={
                        "run_identity": trial.run_identity.model_copy(
                            update={"profile_digest": "8" * 64}
                        )
                    }
                ),
            )
        }
    )
    assert "arm_identity_mismatch" in admit_vm_run(manifest, result, recipe, changed).reason_codes
    wrong_recipe = recipe.model_copy(update={"recipe_id": VmRecipeId.HEALTHY_CONTROL_V1})
    assert "recipe_mismatch" in admit_vm_run(manifest, result, wrong_recipe, proof).reason_codes


def test_vm_contract_rejects_out_of_order_fault_proof() -> None:
    manifest, result, recipe, proof = _packet()
    trial = proof.trials[0]
    changed = proof.model_copy(
        update={
            "trials": (
                trial.model_copy(
                    update={
                        "injection": trial.injection.model_copy(
                            update={"completed_at": T0 + timedelta(seconds=31)}
                        )
                    }
                ),
            )
        }
    )
    assert "event_order_invalid" in admit_vm_run(manifest, result, recipe, changed).reason_codes


def test_vm_contract_recomputes_oracle_threshold_instead_of_trusting_label() -> None:
    manifest, result, recipe, proof = _packet()
    trial = result.trials[0]
    bad_reading = trial.injected[0].model_copy(update={"value": 1.0})
    changed = result.model_copy(
        update={
            "trials": (trial.model_copy(update={"injected": (bad_reading, *trial.injected[1:])}),)
        }
    )
    assert "oracle_sequence_invalid" in admit_vm_run(manifest, changed, recipe, proof).reason_codes


def test_vm_contract_rejects_wrong_sealed_cause_for_registered_recipe() -> None:
    manifest, result, recipe, proof = _packet()
    wrong = manifest.model_copy(
        update={
            "sealed": manifest.sealed.model_copy(
                update={"expected_cause_codes": ("gpu_power_limit",)}
            )
        }
    )
    changed_result = result.model_copy(update={"sealed_sha256": wrong.sealed_sha256()})
    assert "recipe_mismatch" in admit_vm_run(wrong, changed_result, recipe, proof).reason_codes


def test_vm_contract_rejects_valid_arm_without_coordinator_record() -> None:
    manifest, result, recipe, proof = _packet()
    trial = result.trials[0]
    changed = result.model_copy(
        update={"trials": (trial.model_copy(update={"status": TrialStatus.VALID}),)}
    )
    assert "episode_missing" in admit_vm_run(manifest, changed, recipe, proof).reason_codes


def test_vm_contract_rejects_naive_oracle_time_without_crashing() -> None:
    manifest, result, recipe, proof = _packet()
    trial = result.trials[0]
    naive = trial.clean[0].model_copy(update={"observed_at": T0.replace(tzinfo=None)})
    changed = result.model_copy(
        update={"trials": (trial.model_copy(update={"clean": (naive, *trial.clean[1:])}),)}
    )
    assert "event_order_invalid" in admit_vm_run(manifest, changed, recipe, proof).reason_codes


def test_vm_contract_rejects_rig_attestation_older_than_restore() -> None:
    manifest, result, recipe, proof = _packet()
    changed = proof.model_copy(
        update={
            "attestation": proof.attestation.model_copy(
                update={"observed_at": T0 - timedelta(days=1)}
            )
        }
    )
    assert "attestation_stale" in admit_vm_run(manifest, result, recipe, changed).reason_codes
