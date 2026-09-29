"""A later recovery must not disprove the cause of an earlier failed request."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import (
    _persist_evidence,  # pyright: ignore[reportPrivateUsage]
    investigator,
)


@pytest.mark.parametrize("claim_window", ["initial", "replay", "unspecified"])
def test_saved_counterevidence_respects_the_claimed_get_window(
    tmp_path: Path, claim_window: str
) -> None:
    """Only the replay-scoped claim can be contested by the successful replay.

    The observations contain no evaluator mechanism or hidden failure label.
    Both rivals deliberately have identical prose: policy must use the declared
    observation identity and actual source windows, never keywords in a claim.
    """
    start = datetime(2026, 9, 29, 20, 44, 5, tzinfo=UTC)
    with SQLiteStore(tmp_path / "counterevidence.db") as store:
        app = investigator(store)
        state = app.create(objective="Investigate this exact health GET timing out.")
        records = tuple(
            _persist_evidence(
                store,
                case_id=state.case_id,
                facts={
                    "target_handle": "127.0.0.1:61147",
                    "action": "GET /health/" + "a" * 32,
                    "outcome": outcome,
                    "request_started_at_utc": window_start.isoformat(),
                    "request_finished_at_utc": window_end.isoformat(),
                },
                captured_at=window_end,
                sequence=index,
            )
            for index, outcome, window_start, window_end in (
                (1, "timeout", start, start + timedelta(seconds=2)),
                (
                    2,
                    "http_200_nonce_match",
                    start + timedelta(seconds=6),
                    start + timedelta(seconds=6, milliseconds=5),
                ),
            )
        )
        initial, replay = records
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
            hypothesis_id="request_did_not_complete",
            statement="The exact GET in the claimed window did not complete successfully.",
            status=HypothesisStatus.UNRESOLVED,
            contradicting_evidence_ids=(replay.evidence_id,),
        ).model_copy(
            update={
                "claim_window_evidence_id": {
                    "initial": initial.evidence_id,
                    "replay": replay.evidence_id,
                    "unspecified": None,
                }[claim_window]
            }
        )
        progression = app._progress_advisory_hypotheses(  # pyright: ignore[reportPrivateUsage]
            state, (hypothesis,), context
        )
        repository = InvestigationRepository(store)
        repository.save(
            state.model_copy(update={"hypotheses": progression.hypotheses}),
            expected_version=state.state_version,
            event="counterevidence_reviewed",
            detail="Review the source windows before saving advisory contradictions.",
        )
        saved = repository.load(str(state.case_id)).hypotheses
        if claim_window == "replay":
            assert len(saved) == 1
            assert saved[0].contradicting_evidence_ids == (replay.evidence_id,)
            assert saved[0].status is HypothesisStatus.CONTESTED
        else:
            # Rejection or retained noncausal context are both safe. Persisting a
            # contested earlier/unspecified claim based on later recovery is not.
            assert all(replay.evidence_id not in h.contradicting_evidence_ids for h in saved)
            assert all(h.status is not HypothesisStatus.CONTESTED for h in saved)
