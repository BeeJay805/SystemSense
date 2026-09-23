"""Lab harness checks use an owned loopback listener, never host fault injection."""

from __future__ import annotations

import os
import socket
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from benchmarks.lab_episodes import (
    ActionJournalProof,
    ArmKind,
    ArmResult,
    ArmSpec,
    FaultManifest,
    LabEpisodeHarness,
    LabPublicSpec,
    NumericRule,
    OracleContract,
    OwnedLoopbackListener,
    RunIdentity,
    SealedFault,
    TrialStatus,
    main,
    run_owned_loopback_rehearsal,
)
from benchmarks.local_episodes import run_local_episode_benchmark
from systemsense.evaluation.models import EpisodeArtifact


def _manifest(port: int) -> FaultManifest:
    return FaultManifest(
        public=LabPublicSpec(
            scenario_id="owned-listener",
            objective=f"Why is the owned listener on 127.0.0.1:{port} unreachable?",
            machine_fingerprint="b" * 64,
            code_revision="test-revision",
            probe_catalog_digest="c" * 64,
            budget_ms=1_000,
            max_rounds=2,
            max_probes=2,
        ),
        oracle=OracleContract(
            rule=NumericRule(lt=0.5),
            name="owned_loopback_tcp_accept",
            sample_count=3,
        ),
        sealed=SealedFault(
            injection_id="close-owned-listener-v1",
            expected_cause_codes=("owned_listener_stopped",),
            reset_id="owned-listener-rebind-v1",
        ),
    )


def _arm(kind: ArmKind = ArmKind.KEYWORD_BASELINE) -> ArmSpec:
    decision = "laya-local-decision" if kind is ArmKind.DUAL_BRAIN else "keyword-baseline"
    reasoning = (
        "deterministic-reasoning" if kind is ArmKind.KEYWORD_BASELINE else "ollama-local-reasoning"
    )
    return ArmSpec(
        kind=kind,
        warm_state="warm",
        profile_digest="a" * 64,
        decision_provider_id=decision,
        reasoning_provider_id=reasoning,
    )


def _identity(public: LabPublicSpec, arm: ArmSpec) -> RunIdentity:
    return RunIdentity(
        machine_fingerprint=public.machine_fingerprint,
        probe_catalog_digest=public.probe_catalog_digest,
        profile_digest=arm.profile_digest,
        warm_state=arm.warm_state,
    )


def test_invalid_injection_is_recorded_without_running_an_arm() -> None:
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        calls = 0

        class IneffectiveFault:
            def inject(self) -> None:
                pass

            def restore(self) -> None:
                pass

        def run_arm(_public: LabPublicSpec, _arm: ArmSpec) -> ArmResult:
            nonlocal calls
            calls += 1
            return ArmResult(claimed_fixed=False)

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=IneffectiveFault(),
            arms=(_arm(),),
            run_arm=run_arm,
        )

    assert calls == 0
    assert result.trials[0].status is TrialStatus.INVALID_INJECTION
    assert result.trials[0].arm_result is None
    assert result.trials[0].repair_verified is False


def test_persistent_symptom_rejects_claimed_fix() -> None:
    with OwnedLoopbackListener() as listener:
        result = LabEpisodeHarness().run(
            manifest=_manifest(listener.port),
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=lambda _public, _arm: ArmResult(
                claimed_fixed=True,
                claimed_cause_codes=("owned_listener_stopped",),
                action_execution_id="exec-owned-1",
            ),
        )

    trial = result.trials[0]
    assert trial.status is TrialStatus.VALID
    assert trial.false_fix is True
    assert trial.repair_verified is False
    assert all(sample.symptom_present for sample in trial.after_arm)
    assert all(not sample.symptom_present for sample in trial.after_restore)
    assert trial.reference_recovery_verified is True
    assert result.diagnostic_accuracy_claim is False


def test_reference_restore_is_not_attributed_as_a_product_repair() -> None:
    with OwnedLoopbackListener() as listener:
        result = LabEpisodeHarness().run(
            manifest=_manifest(listener.port),
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=lambda _public, _arm: ArmResult(claimed_fixed=False),
        )

    trial = result.trials[0]
    assert trial.status is TrialStatus.VALID
    assert trial.repair_verified is False
    assert all(not sample.symptom_present for sample in trial.after_restore)
    assert trial.reference_recovery_verified is True
    assert trial.reset_state_verified is False


def test_oracle_does_not_count_an_unowned_replacement_listener() -> None:
    with OwnedLoopbackListener() as listener:
        port = listener.port
        listener.inject()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other:
            other.bind(("127.0.0.1", port))
            other.listen(1)
            assert listener.sample_value() == 0.0


def test_healthy_control_rejects_a_false_positive_repair_claim() -> None:
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port).model_copy(
            update={
                "sealed": SealedFault(
                    injection_id="healthy-no-op-v1",
                    expected_cause_codes=(),
                    reset_id="healthy-no-op-v1",
                    expected_symptom=False,
                )
            }
        )

        class NoFault:
            def inject(self) -> None:
                pass

            def restore(self) -> None:
                pass

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=NoFault(),
            arms=(_arm(),),
            run_arm=lambda _public, _arm: ArmResult(
                claimed_fixed=True, action_execution_id="exec-unnecessary"
            ),
        )

    trial = result.trials[0]
    assert trial.status is TrialStatus.VALID
    assert trial.false_positive_repair is True
    assert trial.repair_verified is False


def test_matched_arms_each_receive_a_restored_clean_start_without_sealed_truth() -> None:
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        seen: list[tuple[LabPublicSpec, ArmSpec]] = []

        def run_arm(public: LabPublicSpec, arm: ArmSpec) -> ArmResult:
            seen.append((public, arm))
            assert listener.sample_value() == 0.0
            return ArmResult(claimed_fixed=False)

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(
                _arm(),
                _arm(ArmKind.DEEP_BRAIN_ONLY),
                _arm(ArmKind.DUAL_BRAIN),
            ),
            run_arm=run_arm,
        )

    assert [arm.kind for _, arm in seen] == [
        ArmKind.KEYWORD_BASELINE,
        ArmKind.DEEP_BRAIN_ONLY,
        ArmKind.DUAL_BRAIN,
    ]
    assert all(public == manifest.public for public, _ in seen)
    assert not hasattr(manifest.public, "rule")
    assert not hasattr(manifest.public, "oracle_name")
    assert all(trial.status is TrialStatus.VALID for trial in result.trials)
    assert len({trial.arm.kind for trial in result.trials}) == 3
    assert len(result.sealed_sha256) == 64
    assert "owned_listener_stopped" not in result.model_dump_json()


def test_sealed_fault_hash_uses_a_distinct_nonce_for_same_recipe() -> None:
    with OwnedLoopbackListener() as listener:
        first = _manifest(listener.port)
        second = _manifest(listener.port)

    assert first.sealed.expected_cause_codes == second.sealed.expected_cause_codes
    assert first.sealed_sha256() != second.sealed_sha256()


def test_unrelated_coordinator_episode_cannot_be_scored_as_this_fault() -> None:
    unrelated = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        result = LabEpisodeHarness().run(
            manifest=_manifest(listener.port),
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=lambda public, arm: ArmResult(
                claimed_fixed=False, episode=unrelated, run_identity=_identity(public, arm)
            ),
        )

    assert result.trials[0].status is TrialStatus.ARM_ERROR
    assert result.trials[0].error_type == "EpisodeMismatch"
    assert result.trials[0].repair_verified is False


def test_stale_record_from_before_injection_is_rejected() -> None:
    original = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        payload = original.model_dump(mode="json")
        payload.update(
            scenario_id=manifest.public.scenario_id,
            objective=manifest.public.objective,
            budget_ms=manifest.public.budget_ms,
            max_rounds=manifest.public.max_rounds,
            max_probes=manifest.public.max_probes,
            measurement_source="live",
        )
        stale_record = EpisodeArtifact.model_validate(payload)
        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=lambda public, arm: ArmResult(
                claimed_fixed=False,
                episode=stale_record,
                run_identity=_identity(public, arm),
            ),
        )

    assert result.trials[0].status is TrialStatus.ARM_ERROR
    assert result.trials[0].error_type == "EpisodeMismatch"


def test_reused_case_id_cannot_be_counted_as_a_second_arm() -> None:
    original = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        payload = original.model_dump(mode="json")
        payload.update(
            scenario_id=manifest.public.scenario_id,
            objective=manifest.public.objective,
            budget_ms=manifest.public.budget_ms,
            max_rounds=manifest.public.max_rounds,
            max_probes=manifest.public.max_probes,
            measurement_source="live",
        )

        def run_arm(public: LabPublicSpec, arm: ArmSpec) -> ArmResult:
            now = datetime.now(UTC).isoformat()
            payload["started_at"] = now
            payload["finished_at"] = now
            return ArmResult(
                claimed_fixed=False,
                episode=EpisodeArtifact.model_validate(payload),
                run_identity=_identity(public, arm),
            )

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(_arm(), _arm()),
            run_arm=run_arm,
        )

    assert [trial.status for trial in result.trials] == [
        TrialStatus.VALID,
        TrialStatus.ARM_ERROR,
    ]
    assert result.trials[1].error_type == "CaseReused"


def test_reused_case_clears_positive_action_recovery_credit() -> None:
    original = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        payload = original.model_dump(mode="json")
        payload.update(
            scenario_id=manifest.public.scenario_id,
            objective=manifest.public.objective,
            budget_ms=manifest.public.budget_ms,
            max_rounds=manifest.public.max_rounds,
            max_probes=manifest.public.max_probes,
            measurement_source="live",
        )
        completed_at: datetime | None = None

        def run_arm(public: LabPublicSpec, arm: ArmSpec) -> ArmResult:
            nonlocal completed_at
            now = datetime.now(UTC).isoformat()
            payload["started_at"] = now
            payload["finished_at"] = now
            episode = EpisodeArtifact.model_validate(payload)
            time.sleep(0.04)
            listener.restore()
            completed_at = datetime.now(UTC)
            time.sleep(0.04)
            return ArmResult(
                claimed_fixed=True,
                action_execution_id="action-1",
                proposal_digest="1" * 64,
                target_digest="2" * 64,
                episode=episode,
                run_identity=_identity(public, arm),
            )

        def verify_action(case_id: str, execution_id: str) -> ActionJournalProof:
            assert completed_at is not None
            return ActionJournalProof(
                case_id=case_id,
                action_execution_id=execution_id,
                journal_record_sha256="d" * 64,
                authorization_digest="e" * 64,
                proposal_digest="1" * 64,
                target_digest="2" * 64,
                terminal_outcome="verified",
                completed_at=completed_at,
            )

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(_arm(), _arm()),
            run_arm=run_arm,
            verify_action=verify_action,
        )

    assert result.trials[0].symptom_recovered_after_action is True, (
        result.trials[0].status,
        result.trials[0].error_type,
        result.trials[0].action_journal_verified,
        result.trials[0].after_arm[0].observed_at.isoformat(),
        result.trials[0].injected[-1].observed_at.isoformat(),
        result.trials[0].action_journal_proof.completed_at.isoformat()
        if result.trials[0].action_journal_proof
        else None,
    )
    assert result.trials[1].status is TrialStatus.ARM_ERROR
    assert result.trials[1].error_type == "CaseReused"
    assert result.trials[1].symptom_recovered_after_action is False
    assert result.trials[1].action_journal_verified is False


def test_wrong_model_profile_binding_is_rejected() -> None:
    original = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        payload = original.model_dump(mode="json")
        payload.update(
            scenario_id=manifest.public.scenario_id,
            objective=manifest.public.objective,
            budget_ms=manifest.public.budget_ms,
            max_rounds=manifest.public.max_rounds,
            max_probes=manifest.public.max_probes,
            measurement_source="live",
        )

        def run_arm(public: LabPublicSpec, arm: ArmSpec) -> ArmResult:
            now = datetime.now(UTC).isoformat()
            payload["started_at"] = now
            payload["finished_at"] = now
            return ArmResult(
                claimed_fixed=False,
                episode=EpisodeArtifact.model_validate(payload),
                run_identity=_identity(public, arm).model_copy(update={"profile_digest": "f" * 64}),
            )

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=run_arm,
        )

    assert result.trials[0].status is TrialStatus.ARM_ERROR
    assert result.trials[0].error_type == "EpisodeMismatch"


def test_recovery_with_action_id_but_no_independent_journal_is_unverified() -> None:
    original = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        payload = original.model_dump(mode="json")
        payload.update(
            scenario_id=manifest.public.scenario_id,
            objective=manifest.public.objective,
            budget_ms=manifest.public.budget_ms,
            max_rounds=manifest.public.max_rounds,
            max_probes=manifest.public.max_probes,
            measurement_source="live",
        )

        def run_arm(public: LabPublicSpec, arm: ArmSpec) -> ArmResult:
            now = datetime.now(UTC).isoformat()
            payload["started_at"] = now
            payload["finished_at"] = now
            matching_record = EpisodeArtifact.model_validate(payload)
            listener.restore()
            return ArmResult(
                claimed_fixed=True,
                action_execution_id="unverified-action-1",
                episode=matching_record,
                run_identity=_identity(public, arm),
            )

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=run_arm,
        )

    trial = result.trials[0]
    assert trial.status is TrialStatus.VALID
    assert all(not item.symptom_present for item in trial.after_arm)
    assert trial.action_journal_verified is False
    assert trial.repair_verified is False


def test_journal_proof_must_match_the_case_and_execution() -> None:
    original = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        payload = original.model_dump(mode="json")
        payload.update(
            scenario_id=manifest.public.scenario_id,
            objective=manifest.public.objective,
            budget_ms=manifest.public.budget_ms,
            max_rounds=manifest.public.max_rounds,
            max_probes=manifest.public.max_probes,
            measurement_source="live",
        )

        def run_arm(public: LabPublicSpec, arm: ArmSpec) -> ArmResult:
            now = datetime.now(UTC).isoformat()
            payload["started_at"] = now
            payload["finished_at"] = now
            episode = EpisodeArtifact.model_validate(payload)
            listener.restore()
            return ArmResult(
                claimed_fixed=True,
                action_execution_id="action-1",
                episode=episode,
                run_identity=_identity(public, arm),
                proposal_digest="1" * 64,
                target_digest="2" * 64,
            )

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=run_arm,
            verify_action=lambda _case_id, _execution_id: ActionJournalProof(
                case_id="case_" + "0" * 32,
                action_execution_id="action-1",
                journal_record_sha256="d" * 64,
                authorization_digest="e" * 64,
                proposal_digest="1" * 64,
                target_digest="2" * 64,
                terminal_outcome="verified",
                completed_at=datetime.now(UTC),
            ),
        )

    assert result.trials[0].status is TrialStatus.ARM_ERROR
    assert result.trials[0].error_type == "JournalMismatch"
    assert result.trials[0].repair_verified is False


def test_same_id_rolled_back_action_cannot_credit_recovery() -> None:
    original = run_local_episode_benchmark().episodes[0]
    with OwnedLoopbackListener() as listener:
        manifest = _manifest(listener.port)
        payload = original.model_dump(mode="json")
        payload.update(
            scenario_id=manifest.public.scenario_id,
            objective=manifest.public.objective,
            budget_ms=manifest.public.budget_ms,
            max_rounds=manifest.public.max_rounds,
            max_probes=manifest.public.max_probes,
            measurement_source="live",
        )
        completed_at: datetime | None = None

        def run_arm(public: LabPublicSpec, arm: ArmSpec) -> ArmResult:
            nonlocal completed_at
            now = datetime.now(UTC).isoformat()
            payload["started_at"] = now
            payload["finished_at"] = now
            episode = EpisodeArtifact.model_validate(payload)
            listener.restore()
            completed_at = datetime.now(UTC)
            return ArmResult(
                claimed_fixed=True,
                action_execution_id="action-rolled-back",
                episode=episode,
                run_identity=_identity(public, arm),
                proposal_digest="1" * 64,
                target_digest="2" * 64,
            )

        def verify_action(case_id: str, execution_id: str) -> ActionJournalProof:
            assert completed_at is not None
            return ActionJournalProof(
                case_id=case_id,
                action_execution_id=execution_id,
                journal_record_sha256="d" * 64,
                authorization_digest="e" * 64,
                proposal_digest="1" * 64,
                target_digest="2" * 64,
                terminal_outcome="rolled_back",
                completed_at=completed_at,
            )

        result = LabEpisodeHarness().run(
            manifest=manifest,
            oracle=listener,
            fault=listener,
            arms=(_arm(),),
            run_arm=run_arm,
            verify_action=verify_action,
        )

    trial = result.trials[0]
    assert trial.status is TrialStatus.VALID
    assert all(not item.symptom_present for item in trial.after_arm)
    assert trial.action_journal_verified is False
    assert trial.symptom_recovered_after_action is False
    assert trial.repair_verified is False


def test_cli_rejects_same_output_and_evidence_database_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared_path = tmp_path / "collision.db"
    monkeypatch.setattr(
        "sys.argv",
        [
            "lab_episodes",
            "--owned-loopback-rehearsal",
            "--code-revision",
            "test-revision",
            "--database",
            str(shared_path),
            "--output",
            str(shared_path),
        ],
    )
    with pytest.raises(ValueError, match="different paths"):
        main()
    assert not shared_path.exists()


def test_cli_exclusively_creates_output_after_long_running_episode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "result.json"
    database_path = tmp_path / "evidence.db"

    def concurrent_creator(**_kwargs: object) -> object:
        output_path.write_text("owned by another process", encoding="utf-8")
        return object()

    monkeypatch.setattr("benchmarks.lab_episodes.run_owned_loopback_rehearsal", concurrent_creator)
    monkeypatch.setattr(
        "sys.argv",
        [
            "lab_episodes",
            "--owned-loopback-rehearsal",
            "--code-revision",
            "test-revision",
            "--database",
            str(database_path),
            "--output",
            str(output_path),
        ],
    )
    with pytest.raises(FileExistsError):
        main()
    assert output_path.read_text(encoding="utf-8") == "owned by another process"


@pytest.mark.skipif(os.name != "nt", reason="live Windows collectors required")
def test_owned_loopback_rehearsal_runs_real_coordinator_then_reference_restore(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "rehearsal.db"
    result = run_owned_loopback_rehearsal(
        code_revision="test-revision",
        budget_ms=30_000,
        database_path=database_path,
    )

    trial = result.trials[0]
    assert result.classification == "controlled_lab_rehearsal"
    assert trial.status is TrialStatus.VALID
    assert trial.arm_result is not None
    assert trial.arm_result.episode is not None
    assert trial.arm_result.evidence_store_id is not None
    assert str(database_path) not in result.model_dump_json()
    assert database_path.is_file()
    assert trial.arm_result.episode.probe_attempts.total > 0
    assert all(reading.symptom_present for reading in trial.injected)
    assert all(reading.symptom_present for reading in trial.after_arm)
    assert trial.reference_recovery_verified is True
    assert trial.repair_verified is False
