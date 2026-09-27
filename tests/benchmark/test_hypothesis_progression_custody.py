"""A linked historical rival survives a later bounded packet omission."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindowBasis
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
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus
from systemsense.storage.sqlite_store import SQLiteStore


def _historical_record(
    store: SQLiteStore,
    now: datetime,
    *,
    mismatch: Literal["evidence_id", "case_id", "source_id"] | None = None,
) -> tuple[CaseId, EvidenceRecord]:
    historical_case_id = CaseId.new()
    store.create_case(
        case_id=str(historical_case_id),
        kind=CaseKind.PASSIVE.value,
        symptom="Prior observation",
        created_at=now.isoformat(),
        status=CaseStatus.COMPLETE.value,
        time_window_start=now.isoformat(),
        time_window_end=now.isoformat(),
        time_window_basis=CaseTimeWindowBasis.UNKNOWN.value,
    )
    source_id = stable_source_id("fixture.history", {"case_id": str(historical_case_id)})
    evidence = EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=historical_case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=now,
        captured_at=now,
        source=EvidenceSource(
            type="fixture.history", source_id=source_id, locator={"record": "prior"}
        ),
        collector=CollectorReference(
            id="fixture.history", version=1, execution_id=ExecutionId.new()
        ),
        summary="Prior observed fact",
        facts=(EvidenceFact(name="history_marker", value=1),),
        extraction=Extraction(confidence=1, parser="fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    stored = evidence
    if mismatch == "evidence_id":
        stored = evidence.model_copy(update={"evidence_id": EvidenceId.new()})
    elif mismatch == "case_id":
        stored = evidence.model_copy(update={"case_id": CaseId.new()})
    elif mismatch == "source_id":
        changed_source = evidence.source.model_copy(
            update={"source_id": stable_source_id("fixture.history", {"record": "other"})}
        )
        stored = evidence.model_copy(update={"source": changed_source})
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(historical_case_id),
            evidence_id=str(evidence.evidence_id),
            source_id=source_id,
            record_json=stored.model_dump_json(),
            observed_at=now.isoformat(),
            captured_at=now.isoformat(),
            execution_id=str(evidence.collector.execution_id),
            dedupe_key=f"fixture:{historical_case_id}",
            time_basis="source_observed",
            time_quality="exact",
        )
    return historical_case_id, evidence


def _rival(evidence: EvidenceRecord) -> Hypothesis:
    return Hypothesis(
        hypothesis_id="h_prior",
        statement="The prior observation remains a possible explanation.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(evidence.evidence_id,),
    )


def test_custodied_historical_rival_survives_second_unshown_turn(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    with SQLiteStore(tmp_path / "history.db") as store:
        historical_case_id, evidence = _historical_record(store, now)
        app = default_investigator(store)
        state = app.create(objective="intermittent slowdown", budget_ms=2_000)
        assert historical_case_id in state.historical_case_ids
        rival = _rival(evidence)
        presented = EvidenceContext(
            evidence_id=evidence.evidence_id,
            observed_at=now,
            captured_at=now,
            probe_id="fixture.history",
            summary=evidence.summary,
            facts={"history_marker": 1},
            status=EvidenceContextStatus.OBSERVED,
            case_scope="historical",
        )
        state = state.model_copy(update={"hypotheses": (rival,)})
        first = app._progress_advisory_hypotheses(  # pyright: ignore[reportPrivateUsage]
            state, (), (presented,)
        )
        assert first.hypotheses == (rival,)

        # Synchronous reasoning replaces assessed_context with only its current
        # bounded packet. The durable source and case link still exist.
        later = state.model_copy(update={"hypotheses": first.hypotheses, "assessed_context": ()})
        second = app._progress_advisory_hypotheses(  # pyright: ignore[reportPrivateUsage]
            later, (), ()
        )
        assert second.hypotheses == (rival,)
        assert second.unshown_citation_ids == (evidence.evidence_id,)


def test_unrelated_historical_case_cannot_supply_citation(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    with SQLiteStore(tmp_path / "unrelated.db") as store:
        app = default_investigator(store)
        state = app.create(objective="intermittent slowdown", budget_ms=2_000)
        historical_case_id, evidence = _historical_record(store, now)
        assert historical_case_id not in state.historical_case_ids
        result = app._progress_advisory_hypotheses(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"hypotheses": (_rival(evidence),)}), (), ()
        )
        assert result.hypotheses == ()
        assert result.unavailable_citation_ids == (evidence.evidence_id,)


@pytest.mark.parametrize("mismatch", ("evidence_id", "case_id", "source_id"))
def test_mismatched_stored_record_cannot_supply_citation(
    tmp_path: Path, mismatch: Literal["evidence_id", "case_id", "source_id"]
) -> None:
    now = datetime.now(UTC)
    with SQLiteStore(tmp_path / f"mismatch-{mismatch}.db") as store:
        historical_case_id, evidence = _historical_record(store, now, mismatch=mismatch)
        app = default_investigator(store)
        state = app.create(objective="intermittent slowdown", budget_ms=2_000)
        assert historical_case_id in state.historical_case_ids
        result = app._progress_advisory_hypotheses(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"hypotheses": (_rival(evidence),)}), (), ()
        )
        assert result.hypotheses == ()
        assert result.unavailable_citation_ids == (evidence.evidence_id,)
