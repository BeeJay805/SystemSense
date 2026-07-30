import pytest
from pydantic import BaseModel, ValidationError

from systemsense.domain.ids import (
    ArtifactId,
    CaseId,
    EntityId,
    EvidenceId,
    ExecutionId,
    OpaqueId,
    TargetId,
    stable_source_id,
)


@pytest.mark.parametrize(
    ("id_type", "prefix"),
    [
        (CaseId, "case"),
        (TargetId, "target"),
        (EvidenceId, "ev"),
        (ArtifactId, "artifact"),
        (ExecutionId, "exec"),
        (EntityId, "entity"),
    ],
)
def test_new_opaque_id_has_expected_prefix_and_round_trips(
    id_type: type[OpaqueId],
    prefix: str,
) -> None:
    identifier = id_type.new()

    assert str(identifier).startswith(f"{prefix}_")
    assert id_type.model_validate(str(identifier)) == identifier


def test_new_ids_are_unique() -> None:
    assert CaseId.new() != CaseId.new()


@pytest.mark.parametrize(
    "value",
    [
        "target_00000000000000000000000000000000",
        "case_not-hex",
        "case_1234",
        "CASE_00000000000000000000000000000000",
    ],
)
def test_case_id_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValidationError):
        CaseId.model_validate(value)


def test_opaque_ids_validate_inside_pydantic_models() -> None:
    class CaseReference(BaseModel):
        case_id: CaseId

    case_id = CaseId.new()

    reference = CaseReference.model_validate({"case_id": str(case_id)})

    assert reference.case_id == case_id
    assert reference.model_dump(mode="json") == {"case_id": str(case_id)}


def test_stable_source_id_is_canonical_and_sensitive_to_values() -> None:
    first = stable_source_id("event_log", {"record_id": 42, "channel": "Application"})
    reordered = stable_source_id("event_log", {"channel": "Application", "record_id": 42})
    changed = stable_source_id("event_log", {"channel": "Application", "record_id": 43})

    assert first == reordered
    assert first.startswith("src_")
    assert changed != first
