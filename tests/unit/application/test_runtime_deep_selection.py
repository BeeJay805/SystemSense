"""Deep selection returns to the same bounded fast turn without a probe replay."""

from __future__ import annotations

import threading
from pathlib import Path

from systemsense.application import runtime as runtime_module
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.runtime import FrontierDeepFollowupSelection, PersistedProbeResult
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition


def test_deep_offer_returns_same_parent_for_another_fast_turn(tmp_path: Path) -> None:
    selection_type = getattr(runtime_module, "FrontierDeepFollowupSelection", None)
    assert selection_type is not None, "runtime has no typed deep follow-up selection"
    owner_thread = threading.get_ident()
    selected: list[PersistedProbeResult] = []
    owner_calls: list[int] = []

    with SQLiteStore(tmp_path / "deep-selection.db") as store:
        app = investigator(store, definitions=(probe_definition("core"),))
        queued = app.create(objective="Investigate a slow host", budget_ms=10_000)
        running = app._save(  # pyright: ignore[reportPrivateUsage]
            queued.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "test_started",
            "One registered baseline probe",
        )
        proposal = ProbeProposal(
            probe_id="core.snapshot",
            purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
            priority=1.0,
            estimated_cost_ms=1,
            resource_class=ResourceClass.CPU,
            dedupe_key="baseline:core.snapshot",
        )
        opened = app._opened(running, (proposal,))  # pyright: ignore[reportPrivateUsage]

        def choose(
            parent: PersistedProbeResult, _worker_store: SQLiteStore
        ) -> FrontierDeepFollowupSelection | None:
            selected.append(parent)
            if len(selected) == 1:
                return selection_type(question_id="question_1", item_id="item_1")
            return None

        def start_deep(
            parent: PersistedProbeResult, selection: FrontierDeepFollowupSelection
        ) -> bool:
            owner_calls.append(threading.get_ident())
            assert parent == selected[0]
            assert selection.item_id == "item_1"
            return True

        app.runtime.execute_plan(
            opened,
            followup_capabilities=app.capabilities,
            async_offer_followup=choose,
            on_frontier_deep_selection=start_deep,
        )

        assert len(selected) == 2
        assert selected[0] == selected[1]
        assert owner_calls == [owner_thread]
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=?", (str(queued.case_id),)
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM collection_followup_admissions WHERE case_id=?",
            (str(queued.case_id),),
        ).fetchone() == (0,)
