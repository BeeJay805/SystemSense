"""A retained advisory keeps its frozen evidence-generation boundary visible."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from systemsense.application.investigation_state import InvestigationOutcome
from systemsense.application.service import ApplicationService
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_independent_deep_collection import (
    _proposal,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator, probe_definition


def _freshness(report: dict[str, object]) -> dict[str, object]:
    return cast("dict[str, object]", report["summary_freshness"])


def test_deadline_retains_generation_seven_advice_after_generation_nine_observations(
    tmp_path: Path,
) -> None:
    database = tmp_path / "late-advice.db"
    definitions = tuple(probe_definition(f"sample{i}") for i in range(8))
    with SQLiteStore(database) as store:
        app = investigator(store, definitions=definitions)
        state = app.create(objective="Synthetic performance issue", budget_ms=20_000)
        for definition in definitions[:6]:
            state = app._collect(  # pyright: ignore[reportPrivateUsage]
                state, (_proposal(definition.manifest.probe_id),), None, baseline=True
            )
        reviewed_generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        assert reviewed_generation == 7
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(
                update={
                    "summary": "Advisory explanation: device and display checks are pending.",
                    "summary_source": "advisory_async",
                    "summary_reviewed_evidence_generation": reviewed_generation,
                }
            ),
            "saved_advice",
            "Synthetic recorded-response basis before two more observations.",
        )
        for definition in definitions[6:]:
            state = app._collect(  # pyright: ignore[reportPrivateUsage]
                state, (_proposal(definition.manifest.probe_id),), None, baseline=True
            )
        final = app._finish(  # pyright: ignore[reportPrivateUsage]
            state, InvestigationOutcome.BUDGET_EXHAUSTED, "Case deadline reached."
        )
        assert final.summary.endswith("checks are pending.")
        assert final.summary_reviewed_evidence_generation == 7

    service = ApplicationService(database, factory=investigator)
    try:
        report = service.get_case(str(final.case_id))
        assert _freshness(report) == {
            "status": "stale",
            "source": "advisory_async",
            "reviewed_generation": 7,
            "current_generation": 9,
            "scope": "case_evidence_generation_match_only",
        }
        assert report["summary"] == final.summary
    finally:
        service.close()

    # An old checkpoint has no trustworthy summary provenance after migration.
    with SQLiteStore(database) as store, store.transaction():
        row = store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?",
            (str(final.case_id),),
        ).fetchone()
        assert row is not None
        legacy = json.loads(str(row[0]))
        legacy["schema_version"] = 7
        legacy.pop("summary_source")
        legacy.pop("summary_reviewed_evidence_generation")
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
            (json.dumps(legacy), str(final.case_id)),
        )

    reopened = ApplicationService(database, factory=investigator)
    try:
        report = reopened.get_case(str(final.case_id))
        assert _freshness(report)["status"] == "unknown"
        assert _freshness(report)["source"] is None
        assert _freshness(report)["current_generation"] == 9
    finally:
        reopened.close()


def test_freshness_marks_new_review_current_but_not_comprehensive(tmp_path: Path) -> None:
    database = tmp_path / "current-advice.db"
    with SQLiteStore(database) as store:
        app = investigator(store)
        state = app.create(objective="Synthetic issue", budget_ms=2000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        state = app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(
                update={
                    "summary": "Advisory explanation: latest selected context reviewed.",
                    "summary_source": "advisory_async",
                    "summary_reviewed_evidence_generation": generation,
                }
            ),
            "saved_advice",
            "Synthetic review basis matches the persisted case generation.",
        )
        case_id = str(state.case_id)

    service = ApplicationService(database, factory=investigator)
    try:
        report = service.get_case(case_id)
        assert _freshness(report)["status"] == "current"
        assert _freshness(report)["scope"] == "case_evidence_generation_match_only"
    finally:
        service.close()
