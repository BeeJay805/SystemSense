import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from systemsense.application.service import ApplicationService
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, stable_source_id
from systemsense.evidence.retrieval import EvidenceRetrievalQuery, EvidenceRetriever
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator


def test_report_preserves_bounded_structured_evidence_provenance(tmp_path: Path) -> None:
    database = tmp_path / "report.db"
    passive_case_id = CaseId(root=f"case_{'1' * 32}")
    evidence_id = EvidenceId(root=f"ev_{'2' * 32}")
    source_id = f"src_{'a' * 64}"
    coverage_source_id = f"src_{'b' * 64}"
    coverage_evidence_id = EvidenceId(root=f"ev_{'4' * 32}")
    coverage_execution_id = ExecutionId(root=f"exec_{'5' * 32}")
    observed_at = datetime.now(UTC)
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=passive_case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at,
        source=EvidenceSource(
            type="test.fixture",
            source_id=source_id,
            locator={"private_locator": "must-not-reach-report"},
        ),
        collector=CollectorReference(
            id="core.system",
            version=1,
            execution_id=ExecutionId(root=f"exec_{'3' * 32}"),
        ),
        summary="bounded provenance fixture",
        facts=(
            EvidenceFact(
                name="rows",
                value=[
                    {"owner": f"fixture-{index}.exe", "pid": index + 100, "payload": "x" * 180}
                    for index in range(40)
                ],
            ),
        ),
        extraction=Extraction(confidence=1.0, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )

    with SQLiteStore(database) as store:
        store.create_case(
            case_id=str(passive_case_id),
            kind="passive",
            symptom="passive fixture",
            created_at=observed_at.isoformat(),
        )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(passive_case_id),
                evidence_id=str(evidence_id),
                source_id=source_id,
                record_json=record.model_dump_json(),
                observed_at=observed_at.isoformat(),
                captured_at=observed_at.isoformat(),
            )
        state = investigator(store).create(objective="new incident", budget_ms=2_000)
        assessed = EvidenceContext(
            evidence_id=evidence_id,
            observed_at=observed_at,
            captured_at=observed_at,
            probe_id="core.system",
            summary="bounded provenance fixture",
            facts={"rows.39": {"owner": "fixture-39.exe", "pid": 139, "payload": "x" * 180}},
            status=EvidenceContextStatus.OBSERVED,
            limitations=("Historical observation; other facts omitted from this excerpt.",),
        )
        state = investigator(store).repository.save(
            state.model_copy(update={"assessed_context": (assessed,)}),
            expected_version=state.state_version,
            event="assessed",
            detail="Saved the exact admitted evidence excerpt.",
        )
        coverage = CoverageRecord(
            evidence_id=coverage_evidence_id,
            case_id=state.case_id,
            category="core",
            status=CoverageStatus.FAILED,
            captured_at=observed_at,
            reason="synthetic collector failure",
            execution_id=coverage_execution_id,
        )
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(coverage_execution_id),
                case_id=str(state.case_id),
                probe_id="core.snapshot",
                probe_version=1,
                status="failed",
                parameters_json="{}",
                started_at=observed_at.isoformat(),
                finished_at=observed_at.isoformat(),
                state_version=0,
            )
            transaction.insert_evidence(
                case_id=str(state.case_id),
                evidence_id=str(coverage_evidence_id),
                source_id=coverage_source_id,
                record_json=coverage.model_dump_json(),
                observed_at=observed_at.isoformat(),
                captured_at=observed_at.isoformat(),
                execution_id=str(coverage_execution_id),
            )

    service = ApplicationService(database, factory=investigator)
    try:
        report = service.get_case(str(state.case_id))
        exported = service.export_case(str(state.case_id))
    finally:
        service.close()

    report_items = cast("list[dict[str, object]]", report["evidence"])
    evidence = next(item for item in report_items if item["evidence_id"] == str(evidence_id))
    assert evidence["case_id"] == str(passive_case_id)
    assert evidence["source_id"] == source_id
    assert evidence["source_type"] == "test.fixture"
    assert evidence["statement_kind"] == "observed_fact"
    assert evidence["collector_id"] == "core.system"
    assert evidence["category"] == "core.system"
    assert evidence["execution_id"] == f"exec_{'3' * 32}"
    assert evidence["historical"] is True
    assert evidence["facts"] == assessed.facts
    assert evidence["fact_view"] == "exact_assessed_excerpt"
    assert evidence["limitations"] == list(assessed.limitations)
    assert "locator" not in evidence
    assert "private_locator" not in str(evidence)
    coverage_evidence = next(
        item for item in report_items if item["evidence_id"] == str(coverage_evidence_id)
    )
    assert coverage_evidence["probe_id"] == "core.snapshot"
    assert coverage_evidence["execution_id"] == str(coverage_execution_id)
    assert coverage_evidence["source_id"] == coverage_source_id
    assert coverage_evidence["source_type"] == "systemsense.coverage"
    coverage_items = cast("list[dict[str, object]]", report["coverage"])
    core_coverage = next(item for item in coverage_items if item["probe_id"] == "core.snapshot")
    assert core_coverage["evidence_id"] == str(coverage_evidence_id)
    assert core_coverage["captured_at"] == observed_at.isoformat()
    assert core_coverage["reason"] == "synthetic collector failure"
    assert core_coverage["source_id"] == coverage_source_id
    exported_case = cast("dict[str, object]", exported["case"])
    assert exported_case["evidence"] == report_items


def test_report_hydrates_a_scoped_assessed_citation_omitted_by_packet_limit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "cited-assessed.db"
    target_id = EvidenceId(root=f"ev_{'f' * 32}")

    with SQLiteStore(database) as store:
        app = investigator(store)
        state = app.create(objective="Which process owns port 18765?", budget_ms=2_000)
        observed_at = state.incident_end + timedelta(minutes=10)
        evidence_ids = (
            *(EvidenceId(root=f"ev_{index:032x}") for index in range(48)),
            target_id,
        )
        for index, evidence_id in enumerate(evidence_ids):
            record = EvidenceRecord(
                evidence_id=evidence_id,
                case_id=state.case_id,
                statement_kind=StatementKind.OBSERVED_FACT,
                observed_at=observed_at,
                captured_at=observed_at,
                source=EvidenceSource(
                    type="test.fixture",
                    source_id=f"src_{index:064x}",
                    locator={},
                ),
                collector=CollectorReference(
                    id="core.system",
                    version=1,
                    execution_id=ExecutionId(root=f"exec_{index:032x}"),
                ),
                summary=f"bounded record {index}",
                facts=(EvidenceFact(name="value", value=index),),
                extraction=Extraction(confidence=1.0, parser="test.fixture", parser_version=1),
                sensitivity=Sensitivity.SYSTEM_METADATA,
            )
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=str(state.case_id),
                    evidence_id=str(evidence_id),
                    source_id=record.source.source_id,
                    record_json=record.model_dump_json(),
                    observed_at=observed_at.isoformat(),
                    captured_at=observed_at.isoformat(),
                )
        assessed = EvidenceContext(
            evidence_id=target_id,
            observed_at=observed_at,
            captured_at=observed_at,
            probe_id="core.system",
            summary="decisive exact excerpt",
            facts={"value": 48},
            status=EvidenceContextStatus.OBSERVED,
        )
        hypothesis = Hypothesis(
            hypothesis_id="candidate",
            statement="The exact observation is relevant.",
            status=HypothesisStatus.SUPPORTED,
            supporting_evidence_ids=(target_id,),
        )
        state = app.repository.save(
            state.model_copy(update={"assessed_context": (assessed,), "hypotheses": (hypothesis,)}),
            expected_version=state.state_version,
            event="assessed",
            detail="Saved exact cited excerpt.",
        )

    service = ApplicationService(database, factory=investigator)
    try:
        report = service.get_case(str(state.case_id))
        exported = service.export_case(str(state.case_id))
    finally:
        service.close()

    retrieval = cast("dict[str, object]", report["retrieval"])
    assert retrieval["omitted_evidence_count"] == 1
    report_items = cast("list[dict[str, object]]", report["evidence"])
    cited = next(item for item in report_items if item["evidence_id"] == str(target_id))
    assert cited["facts"] == assessed.facts
    assert cited["fact_view"] == "exact_assessed_excerpt"
    assert cited["case_id"] == str(state.case_id)
    assert cited["source_id"] == f"src_{48:064x}"
    assert cited["source_type"] == "test.fixture"
    assert cited["collector_id"] == "core.system"
    assert cited["category"] == "core.system"
    assert cited["execution_id"] == f"exec_{48:032x}"
    assert datetime.fromisoformat(cast("str", cited["observed_at"])) == observed_at
    assert any(
        "outside the incident window" in limitation
        for limitation in cast("list[str]", cited["limitations"])
    )
    assert cast("dict[str, object]", exported["case"])["evidence"] == report_items


def test_report_does_not_hydrate_assessed_citations_outside_case_or_time_scope(
    tmp_path: Path,
) -> None:
    database = tmp_path / "citation-scope.db"
    forbidden_marker = "forbidden-out-of-scope-assessed-fact-7f46a0"
    old_id = EvidenceId(root=f"ev_{'a' * 32}")
    unselected_id = EvidenceId(root=f"ev_{'b' * 32}")
    unselected_case = CaseId(root=f"case_{'c' * 32}")

    with SQLiteStore(database) as store:
        app = investigator(store)
        state = app.create(objective="Review cited observations", budget_ms=2_000)
        old_time = state.incident_start.replace(year=state.incident_start.year - 1)
        store.create_case(
            case_id=str(unselected_case),
            kind="passive",
            symptom="not opted into this investigation",
            created_at=state.created_at.isoformat(),
        )
        records = (
            (old_id, state.case_id, old_time, 1),
            (unselected_id, unselected_case, state.created_at, 2),
        )
        for evidence_id, case_id, observed_at, value in records:
            record = EvidenceRecord(
                evidence_id=evidence_id,
                case_id=case_id,
                statement_kind=StatementKind.OBSERVED_FACT,
                observed_at=observed_at,
                captured_at=observed_at,
                source=EvidenceSource(
                    type="test.fixture",
                    source_id=f"src_{value:064x}",
                    locator={},
                ),
                collector=CollectorReference(
                    id="core.system",
                    version=1,
                    execution_id=ExecutionId(root=f"exec_{value:032x}"),
                ),
                summary="out-of-scope cited record",
                facts=(EvidenceFact(name="value", value=value),),
                extraction=Extraction(confidence=1.0, parser="test.fixture", parser_version=1),
                sensitivity=Sensitivity.SYSTEM_METADATA,
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
        assessed = tuple(
            EvidenceContext(
                evidence_id=evidence_id,
                observed_at=observed_at,
                captured_at=observed_at,
                probe_id="core.system",
                summary="out-of-scope assessed excerpt",
                facts={"value": value, "forbidden_marker": forbidden_marker},
                status=EvidenceContextStatus.OBSERVED,
            )
            for evidence_id, _case_id, observed_at, value in records
        )
        state = app.repository.save(
            state.model_copy(
                update={
                    "assessed_context": assessed,
                    "hypotheses": (
                        Hypothesis(
                            hypothesis_id="candidate",
                            statement="Out-of-scope citations must not be hydrated.",
                            status=HypothesisStatus.UNRESOLVED,
                            supporting_evidence_ids=(old_id, unselected_id),
                        ),
                    ),
                }
            ),
            expected_version=state.state_version,
            event="assessed",
            detail="Stored deliberately out-of-scope assessed excerpts.",
        )

    service = ApplicationService(database, factory=investigator)
    try:
        report = service.get_case(str(state.case_id))
        exported = service.export_case(str(state.case_id))
    finally:
        service.close()

    report_ids = {
        cast("str", item["evidence_id"])
        for item in cast("list[dict[str, object]]", report["evidence"])
    }
    assert str(old_id) not in report_ids
    assert str(unselected_id) not in report_ids
    assert "assessed_context" not in report
    assert "assessed_context" not in cast("dict[str, object]", exported["case"])
    assert forbidden_marker not in json.dumps(report, sort_keys=True)
    assert forbidden_marker not in json.dumps(exported, sort_keys=True)


def test_late_current_coverage_card_preserves_incident_window_limitation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "late-coverage.db"
    with SQLiteStore(database) as store:
        app = investigator(store)
        state = app.create(objective="Review late core collection", budget_ms=2_000)
        late = state.incident_end + timedelta(minutes=10)
        evidence_id = EvidenceId.new()
        execution_id = ExecutionId.new()
        coverage = CoverageRecord(
            evidence_id=evidence_id,
            case_id=state.case_id,
            category="core",
            status=CoverageStatus.COVERED,
            captured_at=late,
            reason="Core snapshot covered.",
            execution_id=execution_id,
        )
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(state.case_id),
                probe_id="core.snapshot",
                probe_version=1,
                status="ok",
                parameters_json="{}",
                started_at=late.isoformat(),
                finished_at=late.isoformat(),
                state_version=state.state_version,
            )
            transaction.insert_evidence(
                case_id=str(state.case_id),
                evidence_id=str(evidence_id),
                source_id=stable_source_id("test.fixture", {"late": True}),
                record_json=coverage.model_dump_json(),
                captured_at=late.isoformat(),
                execution_id=str(execution_id),
            )

    service = ApplicationService(database, factory=investigator)
    try:
        report = service.get_case(str(state.case_id))
    finally:
        service.close()

    coverage_items = cast("list[dict[str, object]]", report["coverage"])
    core = next(item for item in coverage_items if item["probe_id"] == "core.snapshot")
    assert core["status"] == "ok"
    assert any(
        "outside the incident window" in limitation
        for limitation in cast("list[str]", core["limitations"])
    )


def test_retrieval_uses_one_snapshot_when_writer_commits_between_count_and_select(
    tmp_path: Path,
) -> None:
    database = tmp_path / "snapshot.db"
    case_id = CaseId(root=f"case_{'6' * 32}")
    evidence_id = EvidenceId(root=f"ev_{'7' * 32}")
    observed_at = datetime.now(UTC)
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=observed_at,
        source=EvidenceSource(type="test.fixture", source_id=f"src_{'c' * 64}", locator={}),
        collector=CollectorReference(
            id="core.system",
            version=1,
            execution_id=ExecutionId(root=f"exec_{'8' * 32}"),
        ),
        summary="concurrent evidence",
        extraction=Extraction(confidence=1.0, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )

    with SQLiteStore(database) as reader, SQLiteStore(database) as writer:
        reader.create_case(
            case_id=str(case_id),
            kind="general",
            symptom="snapshot fixture",
            created_at=observed_at.isoformat(),
        )

        class _RaceRetriever(EvidenceRetriever):
            inserted = False

            def _count(self, clauses: list[str], parameters: list[str]) -> int:
                count = super()._count(clauses, parameters)
                if not self.inserted:
                    with writer.transaction() as transaction:
                        transaction.insert_evidence(
                            case_id=str(case_id),
                            evidence_id=str(evidence_id),
                            source_id=record.source.source_id,
                            record_json=record.model_dump_json(),
                            observed_at=observed_at.isoformat(),
                            captured_at=observed_at.isoformat(),
                        )
                    self.inserted = True
                return count

        first = _RaceRetriever(reader).retrieve(EvidenceRetrievalQuery(current_case_id=case_id))
        second = EvidenceRetriever(reader).retrieve(EvidenceRetrievalQuery(current_case_id=case_id))

    assert first.evidence == ()
    assert first.omitted_evidence_count == 0
    assert [item.evidence_id for item in second.evidence] == [evidence_id]
    assert second.omitted_evidence_count == 0
