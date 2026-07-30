from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId


def valid_evidence() -> dict[str, object]:
    return {
        "schema_version": 1,
        "evidence_id": str(EvidenceId.new()),
        "case_id": str(CaseId.new()),
        "statement_kind": "observed_fact",
        "observed_at": "2026-07-30T18:00:00Z",
        "captured_at": "2026-07-30T18:00:01Z",
        "source": {
            "type": "windows_event_log",
            "source_id": "src_" + ("a" * 64),
            "locator": {"channel": "Application", "record_id": 42},
        },
        "collector": {
            "id": "application.event_log",
            "version": 1,
            "execution_id": str(ExecutionId.new()),
        },
        "summary": "The target recorded an application error.",
        "facts": [{"name": "event_id", "value": 1000}],
        "extraction": {
            "confidence": 0.99,
            "parser": "application_error",
            "parser_version": 1,
        },
        "limitations": ["The event does not prove why the process failed."],
        "sensitivity": "system_metadata",
    }


def test_evidence_record_validates_complete_provenance() -> None:
    evidence = EvidenceRecord.model_validate(valid_evidence())

    assert evidence.statement_kind is StatementKind.OBSERVED_FACT
    assert evidence.observed_at == datetime(2026, 7, 30, 18, 0, tzinfo=UTC)
    assert evidence.sensitivity is Sensitivity.SYSTEM_METADATA


@pytest.mark.parametrize("statement_kind", ["root_cause", "diagnosis", "repair"])
def test_evidence_rejects_diagnostic_statement_kinds(statement_kind: str) -> None:
    data = valid_evidence()
    data["statement_kind"] = statement_kind

    with pytest.raises(ValidationError):
        EvidenceRecord.model_validate(data)


@pytest.mark.parametrize("missing_field", ["source", "collector", "extraction", "captured_at"])
def test_evidence_rejects_missing_provenance(missing_field: str) -> None:
    data = valid_evidence()
    del data[missing_field]

    with pytest.raises(ValidationError):
        EvidenceRecord.model_validate(data)


def test_extraction_confidence_is_bounded() -> None:
    data = valid_evidence()
    extraction = data["extraction"]
    assert isinstance(extraction, dict)
    extraction["confidence"] = 1.01

    with pytest.raises(ValidationError):
        EvidenceRecord.model_validate(data)


def test_evidence_models_forbid_unknown_fields() -> None:
    data = valid_evidence()
    data["root_cause"] = "driver"

    with pytest.raises(ValidationError):
        EvidenceRecord.model_validate(data)


def test_evidence_json_schema_contains_no_diagnostic_statement_kind() -> None:
    schema_text = str(EvidenceRecord.model_json_schema())

    assert "root_cause" not in schema_text
    assert "diagnosis" not in schema_text


def test_evidence_components_are_immutable() -> None:
    source = EvidenceSource(
        type="windows_event_log",
        source_id="src_" + ("b" * 64),
        locator={"channel": "System"},
    )
    collector = CollectorReference(
        id="core.event_log",
        version=1,
        execution_id=ExecutionId.new(),
    )
    fact = EvidenceFact(name="event_id", value=7031)
    extraction = Extraction(confidence=1.0, parser="service_event", parser_version=1)

    with pytest.raises(ValidationError):
        source.type = "changed"
    assert collector.version == 1
    assert fact.value == 7031
    assert extraction.confidence == 1.0
