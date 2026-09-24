"""Candidate-ID review contracts are distinct from legacy probe-ID labels."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.evaluation.attention_labels import ExpertAttentionLabel


def _module() -> Any:
    return importlib.import_module("systemsense.evaluation.candidate_attention_labels")


def _label() -> Any:
    contract = _module()
    case_id = CaseId.new()
    now = datetime.now(UTC)
    candidates = (
        contract.FrozenCandidateRef(
            candidate_id="cand_v1_" + "1" * 32,
            probe_id="application.target_pressure",
            manifest_sha256="a" * 64,
            invocation_sha256="b" * 64,
            registry_entry_sha256="c" * 64,
            description_sha256="d" * 64,
            target_binding_sha256="a" * 64,
            window_binding_sha256="0" * 64,
        ),
        contract.FrozenCandidateRef(
            candidate_id="cand_v1_" + "2" * 32,
            probe_id="application.target_pressure",
            manifest_sha256="a" * 64,
            invocation_sha256="e" * 64,
            registry_entry_sha256="f" * 64,
            description_sha256="0" * 64,
            target_binding_sha256="b" * 64,
            window_binding_sha256="0" * 64,
        ),
    )
    snapshot = contract.FrozenCandidateSnapshot(
        snapshot_id="decision_snapshot_" + "3" * 32,
        case_id=case_id,
        state_version=7,
        captured_at=now,
        request_sha256="4" * 64,
        request_candidate_manifest_sha256="f" * 64,
        reference_manifest_sha256=contract.candidate_reference_manifest_sha256(candidates),
        candidates=candidates,
    )
    outcome = contract.ObservedCandidateOutcome(
        case_id=case_id,
        snapshot_id=snapshot.snapshot_id,
        candidate_id=candidates[1].candidate_id,
        execution_id=ExecutionId.new(),
        started_at=now + timedelta(seconds=2),
        finished_at=now + timedelta(seconds=3),
        result="informative",
        evidence_ids=(EvidenceId.new(),),
    )
    return contract.ExpertCandidateLabel(
        label_id="label_" + "5" * 32,
        split_keys=contract.SplitKeys(
            case_id=case_id,
            machine_key="6" * 64,
            application_key="7" * 64,
            application_version="1.0",
            fault_family="pdf_slowness",
        ),
        snapshot=snapshot,
        discriminating_question="Does pressure follow the PDF process or the renderer?",
        question_frozen_at=now + timedelta(seconds=1),
        adjudications=(
            contract.CandidateAdjudication(
                candidate_id=candidates[0].candidate_id, utility="unknown"
            ),
            contract.CandidateAdjudication(
                candidate_id=candidates[1].candidate_id,
                utility="useful",
                outcome=outcome,
            ),
        ),
        abstain=False,
        reviewer_claim=contract.ReviewerConsentClaim(
            reviewer_id="reviewer_1",
            reviewed_at=now + timedelta(seconds=4),
            reviewer_receipt_sha256="8" * 64,
            consent_receipt_sha256="9" * 64,
        ),
        source_kind="recorded",
    )


def test_two_targets_of_one_probe_keep_distinct_candidate_identity() -> None:
    label = _label()
    assert [item.probe_id for item in label.snapshot.candidates] == [
        "application.target_pressure",
        "application.target_pressure",
    ]
    assert label.adjudications[0].utility == "unknown"
    assert label.adjudications[1].utility == "useful"
    assert label.trainable is False
    assert label.reviewer_claim.authenticity == "unverified"
    assert (
        label.snapshot.request_candidate_manifest_sha256 != label.snapshot.reference_manifest_sha256
    )


def test_one_target_two_windows_keep_distinct_candidate_identity() -> None:
    contract = _module()
    first = _label().snapshot.candidates[0]
    later_window = first.model_copy(
        update={
            "candidate_id": "cand_v1_" + "a" * 32,
            "invocation_sha256": "f" * 64,
            "window_binding_sha256": "1" * 64,
        }
    )
    snapshot = _label().snapshot
    candidates = (first, later_window)
    frozen = contract.FrozenCandidateSnapshot.model_validate(
        snapshot.model_copy(
            update={
                "candidates": candidates,
                "reference_manifest_sha256": contract.candidate_reference_manifest_sha256(
                    candidates
                ),
            }
        ).model_dump(mode="json")
    )
    assert frozen.candidates[0].target_binding_sha256 == frozen.candidates[1].target_binding_sha256
    assert frozen.candidates[0].window_binding_sha256 != frozen.candidates[1].window_binding_sha256


def test_duplicate_candidate_id_and_order_tampering_are_rejected() -> None:
    contract = _module()
    label = _label()
    first, second = label.snapshot.candidates
    with pytest.raises(ValidationError, match="unique"):
        contract.FrozenCandidateSnapshot.model_validate(
            label.snapshot.model_copy(
                update={
                    "candidates": (
                        first,
                        second.model_copy(update={"candidate_id": first.candidate_id}),
                    )
                }
            ).model_dump(mode="json")
        )
    with pytest.raises(ValidationError, match="manifest"):
        contract.FrozenCandidateSnapshot.model_validate(
            label.snapshot.model_copy(update={"candidates": (second, first)}).model_dump(
                mode="json"
            )
        )


def test_cross_case_and_cross_snapshot_outcomes_are_rejected() -> None:
    contract = _module()
    label = _label()
    with pytest.raises(ValidationError, match="case"):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(
                update={"split_keys": label.split_keys.model_copy(update={"case_id": CaseId.new()})}
            ).model_dump(mode="json")
        )
    observed = label.adjudications[1]
    assert observed.outcome is not None
    wrong = observed.outcome.model_copy(update={"snapshot_id": "decision_snapshot_" + "a" * 32})
    with pytest.raises(ValidationError, match="snapshot"):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(
                update={
                    "adjudications": (
                        label.adjudications[0],
                        observed.model_copy(update={"outcome": wrong}),
                    )
                }
            ).model_dump(mode="json")
        )


def test_unrun_candidate_cannot_be_labeled_negative() -> None:
    contract = _module()
    label = _label()
    with pytest.raises(ValidationError, match="observed"):
        contract.CandidateAdjudication(
            candidate_id=label.snapshot.candidates[0].candidate_id,
            utility="negative",
        )
    with pytest.raises(ValidationError, match="unknown"):
        contract.CandidateAdjudication(
            candidate_id=label.snapshot.candidates[1].candidate_id,
            utility="unknown",
            outcome=label.adjudications[1].outcome,
        )


def test_question_must_precede_result_and_abstention_has_no_selected_utility() -> None:
    contract = _module()
    label = _label()
    with pytest.raises(ValidationError, match="question"):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(
                update={"question_frozen_at": label.reviewer_claim.reviewed_at}
            ).model_dump(mode="json")
        )
    with pytest.raises(ValidationError, match="abstain"):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(update={"abstain": True}).model_dump(mode="json")
        )


def test_vnext_cannot_be_reinterpreted_as_legacy_or_trainable() -> None:
    contract = _module()
    label = _label()
    with pytest.raises(ValidationError):
        ExpertAttentionLabel.model_validate(label.model_dump(mode="json"))
    with pytest.raises(ValidationError):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(update={"schema_version": 2}).model_dump(mode="json")
        )
    with pytest.raises(ValidationError):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(update={"trainable": True}).model_dump(mode="json")
        )
    with pytest.raises(ValidationError):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(update={"label_origin": "local_model_weak"}).model_dump(mode="json")
        )
    with pytest.raises(ValidationError):
        contract.ExpertCandidateLabel.model_validate(
            label.model_copy(update={"synthetic": True}).model_dump(mode="json")
        )
