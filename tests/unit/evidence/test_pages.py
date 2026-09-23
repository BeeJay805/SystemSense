from datetime import UTC, datetime
from pathlib import Path

from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue
from systemsense.evidence.pages import attention_pages, fact_pages
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.storage.sqlite_store import SQLiteStore


def test_attention_pages_keep_persisted_fact_unit_with_value(tmp_path: Path) -> None:
    observed_at = datetime(2026, 9, 23, 12, tzinfo=UTC)
    case_id = CaseId.new()
    evidence_id = EvidenceId.new()
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at,
        source=EvidenceSource(type="test.fixture", source_id="src_" + "a" * 64, locator={}),
        collector=CollectorReference(id="disk.health", version=1, execution_id=ExecutionId.new()),
        summary="Disk latency",
        facts=(EvidenceFact(name="disk_latency", value=820, unit="ms"),),
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    context = EvidenceContext(
        evidence_id=evidence_id,
        observed_at=observed_at,
        captured_at=observed_at,
        probe_id="disk.health",
        summary=record.summary,
        status=EvidenceContextStatus.OBSERVED,
    )
    with SQLiteStore(tmp_path / "facts.db") as store:
        store.create_case(
            case_id=str(case_id),
            kind="incident",
            symptom="disk stalls",
            created_at=observed_at.isoformat(),
        )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=record.source.source_id,
                record_json=record.model_dump_json(),
                observed_at=observed_at.isoformat(),
                captured_at=observed_at.isoformat(),
            )
        pages = attention_pages(store, (context,))

    assert pages[0].facts == {"disk_latency": {"value": 820, "unit": "ms"}}


def test_attention_pages_preserve_all_array_items_beyond_old_prefix_limit() -> None:
    processes: list[JsonValue] = [
        {"pid": i, "name": f"process-{i}", "metadata": "x" * 120} for i in range(128)
    ]
    pages = list(fact_pages({"processes": processes}))
    assert len(pages) > 1
    recovered = {key: value for page in pages for key, value in page.items()}
    assert recovered["processes.127"] == processes[-1]
    assert len(recovered) == 128


def test_attention_pages_do_not_clip_numeric_values() -> None:
    value: dict[str, JsonValue] = {"memory": {"bytes": 18446744073709551615, "missing": None}}
    assert list(fact_pages(value)) == [value]


def test_attention_pages_preserve_large_scalar_that_fits_context_bound() -> None:
    detail = "x" * 3000

    pages = list(fact_pages({"event": {"rendered_message": detail}}))

    recovered = {key: value for page in pages for key, value in page.items()}
    assert recovered["event.rendered_message"] == detail


def test_attention_pages_do_not_overwrite_long_or_unsafe_source_paths() -> None:
    shared = "segment" * 20
    first_name = f"{shared} first/value"
    second_name = f"{shared} second:value"
    values: dict[str, JsonValue] = {
        "root": {
            first_name: "a" * 1800,
            second_name: "b" * 1800,
        }
    }

    pages = list(fact_pages(values))

    recovered = {key: value for page in pages for key, value in page.items()}
    assert len(recovered) == 2
    assert len(set(recovered)) == 2
    wrappers = list(recovered.values())
    values_found: set[str] = set()
    paths_found: set[str] = set()
    for wrapper in wrappers:
        assert isinstance(wrapper, dict)
        wrapped_value = wrapper.get("value")
        source_path = wrapper.get("source_path")
        assert isinstance(wrapped_value, str)
        assert isinstance(source_path, str)
        values_found.add(wrapped_value)
        paths_found.add(source_path)
    assert values_found == {"a" * 1800, "b" * 1800}
    assert paths_found == {
        f'root.["{first_name}"]',
        f'root.["{second_name}"]',
    }
