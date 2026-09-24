"""Only custody-verified diagnostic terminals may become branch progress."""

import sqlite3
import time
from datetime import timedelta
from pathlib import Path

import pytest
from test_diagnostic_intents import (
    _persist,  # pyright: ignore[reportPrivateUsage]
    _question,  # pyright: ignore[reportPrivateUsage]
    _state,  # pyright: ignore[reportPrivateUsage]
)

from systemsense.domain.probes import MeasurementWindow
from systemsense.domain.time import utc_now
from systemsense.storage.diagnostic_intents import DiagnosticIntentRepository
from systemsense.storage.diagnostic_progress import DiagnosticProgressRepository
from systemsense.storage.sqlite_store import SQLiteStore


def test_projection_is_idempotent_across_reopen_and_unknown_is_not_progress(
    tmp_path: Path,
) -> None:
    path = tmp_path / "case.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        source = _persist(store, state, association="authenticating")
        intents = DiagnosticIntentRepository(store)
        progress = DiagnosticProgressRepository(store)
        with store.transaction():
            admission = intents.admit_question(
                _question(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi.question",
                parameters={},
            )
            intents.claim_dispatch(admission.admission_id)
            intents.interrupt(admission.admission_id, reason="dispatch_outcome_unknown")
            first = progress.project_terminal(admission.admission_id)
            assert progress.project_terminal(admission.admission_id) == first
        assert first.event.dead_end
        assert not first.event.diagnostic_progress
        assert first.event.prediction_matched_hypothesis_ids == ()
        assert progress.readback(admission.admission_id) == first
        assert progress.for_case(state.case_id) == (first,)
    with SQLiteStore(path) as store:
        assert DiagnosticProgressRepository(store).readback(admission.admission_id) == first


def test_projection_requires_terminal_and_caller_transaction(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state, association="associating")
        intents = DiagnosticIntentRepository(store)
        progress = DiagnosticProgressRepository(store)
        with store.transaction():
            admission = intents.admit_question(
                _question(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi.question",
                parameters={},
            )
        with pytest.raises(ValueError, match="transaction"):
            progress.project_terminal(admission.admission_id)
        with pytest.raises(ValueError, match="terminal"), store.transaction():
            progress.project_terminal(admission.admission_id)
        assert progress.for_case(state.case_id) == ()


def test_legacy_intent_cannot_be_projected_as_live_question(tmp_path: Path) -> None:
    from test_diagnostic_intents import _intent  # pyright: ignore[reportPrivateUsage]

    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        source = _persist(store, state)
        intents = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = intents.admit(
                _intent(state),
                expected_state_version=state.state_version,
                source_evidence_id=source.evidence_id,
                plan_instance_id="plan.wifi",
                parameters={},
            )
            intents.interrupt(admission.admission_id, reason="not_run")
        with pytest.raises(ValueError, match="versioned question"), store.transaction():
            DiagnosticProgressRepository(store).project_terminal(admission.admission_id)


@pytest.mark.parametrize(
    ("association", "matched", "disfavored"),
    [
        ("connected", "wlan.associated", "wlan.disconnected"),
        ("disconnected", "wlan.disconnected", "wlan.associated"),
    ],
)
def test_projection_distinguishes_only_cited_association_state(
    tmp_path: Path, association: str, matched: str, disfavored: str
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        baseline = _persist(store, state, association="associating")
        now = utc_now()
        question = _question(state)
        question = question.model_copy(
            update={
                "scope": question.scope.model_copy(
                    update={
                        "window": MeasurementWindow(
                            start=now + timedelta(milliseconds=20),
                            end=now + timedelta(seconds=5),
                        )
                    }
                )
            }
        )
        intents = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = intents.admit_question(
                question,
                expected_state_version=state.state_version,
                source_evidence_id=baseline.evidence_id,
                plan_instance_id="plan.wifi.question",
                parameters={},
            )
            claim = intents.claim_dispatch(admission.admission_id)
        time.sleep(0.04)
        followup = _persist(
            store,
            state,
            plan="plan.wifi.question",
            association=association,
            claim_id=claim.claim_id,
        )
        with store.transaction():
            intents.link_execution(admission.admission_id, str(followup.collector.execution_id))
            terminal = intents.evaluate(admission.admission_id)
            projected = DiagnosticProgressRepository(store).project_terminal(admission.admission_id)
        assert terminal.evaluation is not None
        assert terminal.evaluation.observed is (association == "connected")
        assert projected.event.diagnostic_progress
        assert not projected.event.dead_end
        assert projected.event.evidence_ids == (followup.evidence_id,)
        assert projected.event.prediction_matched_hypothesis_ids == (matched,)
        assert projected.event.prediction_disfavored_hypothesis_ids == (disfavored,)
        assert DiagnosticProgressRepository(store).readback(admission.admission_id) == projected
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute(
                "UPDATE diagnostic_progress SET record_json='{}' WHERE admission_id=?",
                (admission.admission_id,),
            )
        store.connection.execute(
            "UPDATE evidence SET record_json='{}' WHERE evidence_id=?", (str(followup.evidence_id),)
        )
        with pytest.raises(ValueError):
            DiagnosticProgressRepository(store).readback(admission.admission_id)


def test_projection_revalidates_source_custody_after_the_fact(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        state = _state(store)
        baseline = _persist(store, state, association="authenticating")
        intents = DiagnosticIntentRepository(store)
        progress = DiagnosticProgressRepository(store)
        with store.transaction():
            admission = intents.admit_question(
                _question(state),
                expected_state_version=state.state_version,
                source_evidence_id=baseline.evidence_id,
                plan_instance_id="plan.wifi.question",
                parameters={},
            )
            intents.claim_dispatch(admission.admission_id)
            intents.interrupt(admission.admission_id, reason="dispatch_outcome_unknown")
            progress.project_terminal(admission.admission_id)
        store.connection.execute(
            "UPDATE evidence SET record_json='{}' WHERE evidence_id=?", (str(baseline.evidence_id),)
        )
        with pytest.raises(ValueError):
            progress.readback(admission.admission_id)
        with pytest.raises(ValueError):
            progress.for_case(state.case_id)


def test_recovery_projects_terminal_without_redispatch(tmp_path: Path) -> None:
    path = tmp_path / "case.db"
    with SQLiteStore(path) as store:
        state = _state(store)
        baseline = _persist(store, state, association="associating")
        intents = DiagnosticIntentRepository(store)
        with store.transaction():
            admission = intents.admit_question(
                _question(state),
                expected_state_version=state.state_version,
                source_evidence_id=baseline.evidence_id,
                plan_instance_id="plan.wifi.question",
                parameters={},
            )
            claim = intents.claim_dispatch(admission.admission_id)
            intents.interrupt(admission.admission_id, reason="dispatch_outcome_unknown")
    with SQLiteStore(path) as store:
        progress = DiagnosticProgressRepository(store)
        with store.transaction():
            recovered = progress.project_unprojected(state.case_id)
            assert len(recovered) == 1
            assert progress.project_unprojected(state.case_id) == ()
        assert not recovered[0].event.diagnostic_progress
        assert DiagnosticIntentRepository(store).dispatch_claim(admission.admission_id) == claim
        assert progress.for_case(state.case_id) == recovered
