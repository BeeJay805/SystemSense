"""A focused evidence delivery can resume fast attention during an active plan."""

from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path

from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.runtime import FrontierFocusDeliverySelection, PersistedProbeResult
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal
from systemsense.domain.time import utc_now
from systemsense.orchestration.probes import ProbeObservation
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition


def test_focused_delivery_returns_parent_before_unrelated_probe_finishes(tmp_path: Path) -> None:
    owner_thread = threading.get_ident()
    slow_started = threading.Event()
    slow_release = threading.Event()
    slow_finished = threading.Event()
    second_turn_before_slow_finished = threading.Event()
    selected: list[PersistedProbeResult] = []
    owner_calls: list[int] = []

    def slow_probe(_parameters: dict[str, object]) -> ProbeObservation:
        slow_started.set()
        assert slow_release.wait(3)
        slow_finished.set()
        now = utc_now()
        return ProbeObservation(
            summary="Slow unrelated probe completed",
            facts={"slow_completed": True},
            observed_at=now,
            captured_at=now,
        )

    slow = probe_definition("slow")
    slow = replace(slow, handler=slow_probe)
    with SQLiteStore(tmp_path / "focus-selection.db") as store:
        app = investigator(store, definitions=(probe_definition("core"), slow))
        queued = app.create(objective="Investigate a slow host", budget_ms=10_000)
        running = app._save(  # pyright: ignore[reportPrivateUsage]
            queued.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "test_started",
            "Two registered baseline probes",
        )
        proposals = tuple(
            ProbeProposal(
                probe_id=probe_id,
                purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
                priority=1.0,
                estimated_cost_ms=1,
                resource_class=ResourceClass.CPU,
                dedupe_key=f"baseline:{probe_id}",
            )
            for probe_id in ("core.snapshot", "slow.snapshot")
        )
        opened = app._opened(running, proposals)  # pyright: ignore[reportPrivateUsage]

        def choose(
            parent: PersistedProbeResult, _worker_store: SQLiteStore
        ) -> FrontierFocusDeliverySelection | None:
            if parent.probe_id != "core.snapshot":
                return None
            selected.append(parent)
            if len(selected) == 1:
                assert slow_started.wait(1)
                return FrontierFocusDeliverySelection(item_id="item_1", evidence_id="ev_1")
            if not slow_finished.is_set():
                second_turn_before_slow_finished.set()
            slow_release.set()
            return None

        def deliver(
            parent: PersistedProbeResult, selection: FrontierFocusDeliverySelection
        ) -> bool:
            owner_calls.append(threading.get_ident())
            assert parent == selected[0]
            assert selection.item_id == "item_1"
            assert selection.evidence_id == "ev_1"
            assert not slow_finished.is_set()
            return True

        try:
            app.runtime.execute_plan(
                opened,
                followup_capabilities=app.capabilities,
                async_offer_followup=choose,
                on_frontier_focus_selection=deliver,
            )
        finally:
            slow_release.set()

        assert len(selected) == 2
        assert selected[0] == selected[1]
        assert second_turn_before_slow_finished.is_set()
        assert owner_calls == [owner_thread]


def test_rejected_focused_delivery_does_not_requeue_parent(tmp_path: Path) -> None:
    selected: list[PersistedProbeResult] = []
    with SQLiteStore(tmp_path / "focus-rejected.db") as store:
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

        def choose(
            parent: PersistedProbeResult, _worker_store: SQLiteStore
        ) -> FrontierFocusDeliverySelection:
            selected.append(parent)
            return FrontierFocusDeliverySelection(item_id="item_1", evidence_id="ev_1")

        app.runtime.execute_plan(
            app._opened(running, (proposal,)),  # pyright: ignore[reportPrivateUsage]
            followup_capabilities=app.capabilities,
            async_offer_followup=choose,
            on_frontier_focus_selection=lambda _parent, _selection: False,
        )
        assert len(selected) == 1
