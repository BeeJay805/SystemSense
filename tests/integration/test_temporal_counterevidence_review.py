"""Independent review regressions for request identity and unknown source time."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import (
    _persist_evidence,  # pyright: ignore[reportPrivateUsage]
    investigator,
)


@pytest.mark.parametrize("variant", ["malformed", "missing", "overlap", "touching"])
def test_distinct_or_unknown_request_window_cannot_contest_claim(
    tmp_path: Path, variant: str
) -> None:
    start = datetime(2026, 9, 29, 20, 44, 5, tzinfo=UTC)
    with SQLiteStore(tmp_path / "review.db") as store:
        app = investigator(store)
        state = app.create(objective="Investigate this exact health GET timing out.")
        records: list[EvidenceRecord] = []
        for index in range(2):
            offset = 2 if variant == "touching" else 1
            facts: dict[str, JsonValue] = {
                "target_handle": "127.0.0.1:61147",
                "action": "GET /health/" + "a" * 32,
                "outcome": "timeout" if index == 0 else "http_200_nonce_match",
                "request_started_at_utc": (start + timedelta(seconds=index * offset)).isoformat(),
                "request_finished_at_utc": (
                    start + timedelta(seconds=2 + index * offset)
                ).isoformat(),
            }
            if index == 1 and variant == "malformed":
                facts["request_started_at_utc"] = "invalid-source-time"
            if index == 1 and variant == "missing":
                facts.pop("request_started_at_utc")
            records.append(
                _persist_evidence(
                    store,
                    case_id=state.case_id,
                    facts=facts,
                    captured_at=start + timedelta(seconds=4 + index),
                    sequence=index + 1,
                )
            )
        context = tuple(
            EvidenceContext(
                evidence_id=record.evidence_id,
                observed_at=record.observed_at,
                captured_at=record.captured_at,
                probe_id=record.collector.id,
                summary=record.summary,
                facts={fact.name: fact.value for fact in record.facts},
                status=EvidenceContextStatus.OBSERVED,
                case_scope="current_case",
                incident_relevant=True,
            )
            for record in records
        )
        hypothesis = Hypothesis(
            hypothesis_id="exact_request_failed",
            statement="The exact GET in the claimed window did not complete successfully.",
            status=HypothesisStatus.UNRESOLVED,
            contradicting_evidence_ids=(records[1].evidence_id,),
        ).model_copy(
            update={
                "claim_window_evidence_id": (
                    records[0].evidence_id if variant in {"overlap", "touching"} else None
                )
            }
        )
        progression = app._progress_advisory_hypotheses(  # pyright: ignore[reportPrivateUsage]
            state, (hypothesis,), context
        )
        repository = InvestigationRepository(store)
        repository.save(
            state.model_copy(update={"hypotheses": progression.hypotheses}),
            expected_version=state.state_version,
            event="review_counterevidence",
            detail="Preserve exact request identity and unknown source-time limits.",
        )
        saved = repository.load(str(state.case_id)).hypotheses
        assert all(records[1].evidence_id not in h.contradicting_evidence_ids for h in saved)
        assert all(h.status is not HypothesisStatus.CONTESTED for h in saved)
