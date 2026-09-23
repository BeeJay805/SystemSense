"""Human-reviewed next-probe labels stay auditable and split safely."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.evaluation.attention_labels import (
    AttentionSnapshot,
    ExpertAttentionLabel,
    ProbeOutcome,
    RedactionAttestation,
    RegisteredProbe,
    SplitKeys,
    validate_group_splits,
)

NOW = datetime(2026, 9, 22, tzinfo=UTC)


def _manifest() -> ProbeManifest:
    return ProbeManifest(
        probe_id="windows.eventlog",
        version=1,
        implementation_id="builtin.windows.eventlog",
        question="Read relevant events",
        safety=ProbeSafety(
            safety_class=SafetyClass.R1,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
        ),
        input_model="EventlogV1",
        limits=ProbeLimits(timeout_ms=100, max_output_bytes=1024, max_records=100),
        category="windows",
    )


def _label(**changes: object) -> ExpertAttentionLabel:
    data: dict[str, object] = {
        "label_id": "label_" + "1" * 32,
        "split_keys": SplitKeys(
            case_id=CaseId.new(),
            machine_key="a" * 64,
            application_key="b" * 64,
            application_version="1.2.3",
            fault_family="startup_failure",
        ),
        "snapshot": AttentionSnapshot(
            state_version=2,
            case_opened_at=NOW - timedelta(hours=1),
            captured_at=NOW,
            evidence_ids=(EvidenceId.new(),),
            candidate_probes=(RegisteredProbe.from_manifest(_manifest()),),
        ),
        "useful_probe_ids": ("windows.eventlog",),
        "negative_probe_ids": (),
        "abstain": False,
        "outcomes": (
            ProbeOutcome(
                probe_id="windows.eventlog",
                execution_id=ExecutionId.new(),
                started_at=NOW + timedelta(seconds=1),
                finished_at=NOW + timedelta(seconds=2),
                evidence_ids=(EvidenceId.new(),),
                result="informative",
            ),
        ),
        "reviewer_id": "reviewer_01",
        "reviewed_at": NOW + timedelta(minutes=1),
        "label_origin": "human_expert",
        "source_kind": "live",
        "synthetic": False,
        "redaction": RedactionAttestation(
            method="identifiers_only",
            checked_by="reviewer_01",
            checked_at=NOW + timedelta(seconds=3),
        ),
    }
    data.update(changes)
    return ExpertAttentionLabel.model_validate(data)


def test_expert_label_retains_snapshot_and_post_probe_provenance() -> None:
    label = _label()
    assert label.snapshot.evidence_ids
    assert label.snapshot.candidate_probes[0].manifest_version == 1
    assert label.outcomes[0].execution_id
    assert label.schema_version == 1


def test_candidate_contains_only_catalog_reference_and_validates_trusted_manifest() -> None:
    label = _label()
    candidate = label.snapshot.candidate_probes[0]
    assert set(candidate.model_dump()) == {"probe_id", "manifest_version", "catalog_sha256"}
    label.validate_against_catalog({"windows.eventlog": _manifest()})


def test_candidate_rejects_wrong_trusted_manifest_version_or_digest() -> None:
    label = _label()
    changed = _manifest().model_copy(update={"version": 2})
    with pytest.raises(ValueError, match="catalog"):
        label.validate_against_catalog({"windows.eventlog": changed})
    changed = _manifest().model_copy(update={"question": "Different catalog definition"})
    with pytest.raises(ValueError, match="catalog"):
        label.validate_against_catalog({"windows.eventlog": changed})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("label_origin", "model_generated"),
        ("synthetic", True),
        ("useful_probe_ids", ("arbitrary.command",)),
        ("negative_probe_ids", ("windows.eventlog",)),
        ("redaction", {"method": "none", "checked_by": "reviewer_01", "checked_at": NOW}),
    ],
)
def test_rejects_unreviewable_or_unregistered_ground_truth(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _label(**{field: value})


def test_selected_probe_requires_post_snapshot_outcome() -> None:
    with pytest.raises(ValidationError, match="outcome"):
        _label(outcomes=())


def test_failed_probe_requires_an_explicit_limitation() -> None:
    label = _label()
    outcome = label.outcomes[0].model_dump()
    outcome["result"] = "failed"
    with pytest.raises(ValidationError, match="limitation"):
        _label(outcomes=(outcome,))


@pytest.mark.parametrize("result", ["uninformative", "inconclusive", "failed"])
def test_useful_label_requires_informative_outcome(result: str) -> None:
    label = _label()
    outcome = label.outcomes[0].model_dump()
    outcome["result"] = result
    if result in {"inconclusive", "failed"}:
        outcome["limitation_codes"] = ("source_unavailable",)
    with pytest.raises(ValidationError, match="useful"):
        _label(outcomes=(outcome,))


def test_negative_label_rejects_informative_outcome() -> None:
    label = _label()
    with pytest.raises(ValidationError, match="negative"):
        _label(
            useful_probe_ids=(),
            negative_probe_ids=("windows.eventlog",),
            outcomes=label.outcomes,
        )


def test_redaction_check_must_cover_post_probe_outcome() -> None:
    with pytest.raises(ValidationError, match="redaction"):
        _label(
            redaction=RedactionAttestation(
                method="identifiers_only", checked_by="reviewer_01", checked_at=NOW
            )
        )


def test_rejects_case_open_time_after_snapshot() -> None:
    label = _label()
    snapshot = label.snapshot.model_dump()
    snapshot["case_opened_at"] = NOW + timedelta(days=1)
    with pytest.raises(ValidationError, match="case-open"):
        _label(snapshot=snapshot)


def test_candidate_rejects_unbounded_catalog_text() -> None:
    label = _label()
    snapshot = label.snapshot.model_dump()
    snapshot["candidate_probes"][0]["description"] = "password=secret"
    with pytest.raises(ValidationError, match="Extra inputs"):
        _label(snapshot=snapshot)


@pytest.mark.parametrize("outcome_ids", [(), "snapshot"])
def test_informative_outcome_requires_new_evidence(outcome_ids: object) -> None:
    label = _label()
    outcome = label.outcomes[0].model_dump()
    outcome["evidence_ids"] = (
        label.snapshot.evidence_ids if outcome_ids == "snapshot" else outcome_ids
    )
    with pytest.raises(ValidationError, match="new evidence"):
        _label(snapshot=label.snapshot, outcomes=(outcome,))


def test_abstain_and_negative_labels_are_explicit() -> None:
    abstain = _label(useful_probe_ids=(), outcomes=(), abstain=True)
    negative = _label(useful_probe_ids=(), outcomes=(), negative_probe_ids=("windows.eventlog",))
    assert abstain.abstain
    assert negative.negative_probe_ids == ("windows.eventlog",)


def test_split_rejects_shared_machine_even_when_cases_differ() -> None:
    first = _label()
    second = _label(label_id="label_" + "2" * 32)
    with pytest.raises(ValueError, match="machine"):
        validate_group_splits(
            {"train": (first,), "test": (second,)}, {"windows.eventlog": _manifest()}
        )


def test_split_rejects_duplicate_label_in_one_partition() -> None:
    label = _label()
    with pytest.raises(ValueError, match="label ID"):
        validate_group_splits({"train": (label, label)}, {"windows.eventlog": _manifest()})


def test_split_admission_rejects_catalog_mismatch() -> None:
    label = _label()
    with pytest.raises(ValueError, match="catalog"):
        validate_group_splits({"train": (label,)}, {})


def test_split_accepts_independent_groups() -> None:
    first = _label()
    second = _label(
        label_id="label_" + "2" * 32,
        split_keys=SplitKeys(
            case_id=CaseId.new(),
            machine_key="c" * 64,
            application_key="d" * 64,
            application_version="2.0",
            fault_family="network_timeout",
        ),
    )
    validate_group_splits({"train": (first,), "test": (second,)}, {"windows.eventlog": _manifest()})
