"""A retrieval can update the active plan before an unrelated probe completes."""

from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.time import utc_now
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.orchestration.probes import ProbeObservation
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.search_frontier import (
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition
from tests.unit.evidence.test_retrieval import _insert_record  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("stale_generation", [False, True])
def test_owner_delivers_retrieval_and_reranks_while_slow_probe_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stale_generation: bool
) -> None:
    slow_started = threading.Event()
    slow_release = threading.Event()
    slow_finished = threading.Event()
    saw_focused_turn = threading.Event()
    evidence_id = EvidenceId(root="ev_11111111111111111111111111111111")
    item_ids: list[str] = []
    offer_errors: list[str] = []
    calls = 0

    def slow_probe(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        slow_started.set()
        assert slow_release.wait(5)
        slow_finished.set()
        now = utc_now()
        return ProbeObservation(
            summary="Unrelated slow probe completed",
            facts={"completed": True},
            observed_at=now,
            captured_at=now,
        )

    def offer(
        self: Investigator,
        state: Any,
        parent: Any,
        worker: Any,
        worker_store: SQLiteStore,
        cancel_event: Any,
        parent_gap_codes: Any,
        catalog_cursor_holder: Any,
        catalog_metadata_stats: Any,
    ) -> tuple[bool, None, tuple[str, EvidenceId] | None]:
        del self, cancel_event, parent_gap_codes, catalog_cursor_holder, catalog_metadata_stats
        nonlocal calls
        if parent.probe_id != "core.snapshot":
            return False, None, None
        calls += 1
        if calls == 1:
            assert slow_started.wait(5)
            try:
                generation = (
                    EvidenceRetriever(worker_store)
                    .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
                    .case_evidence_generation
                )
                versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
                frontier = SearchFrontierRepository(worker_store)
                item = frontier.upsert_item(
                    state.case_id,
                    FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
                    versions,
                )
                frontier.claim_ready(item.item_id, versions)
                frontier.transition(
                    item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "retrieving"
                )
                frontier.transition(
                    item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
                )
                item_ids.append(item.item_id)
                if stale_generation:
                    now = utc_now()
                    _insert_record(
                        worker_store,
                        case_id=str(state.case_id),
                        evidence_id="ev_22222222222222222222222222222222",
                        collector_id="fixture.stored",
                        summary="A newer unrelated observation",
                        observed_at=now,
                        captured_at=now,
                    )
                    slow_release.set()
                return True, None, (item.item_id, evidence_id)
            except ValueError as error:
                offer_errors.append(str(error))
                raise
        assert evidence_id in state.fast_catalog_selected_ids
        focused = worker.context(str(state.case_id), state=state)
        assert tuple(item.evidence_id for item in focused) == (evidence_id,)
        assert not slow_finished.is_set()
        saw_focused_turn.set()
        slow_release.set()
        return True, None, None

    original_context = Investigator.context

    def selected_context(self: Investigator, case_id: str, *, state: Any = None) -> tuple[Any, ...]:
        packet = original_context(self, case_id, state=state)
        return (
            packet
            if state is None
            else tuple(
                item for item in packet if item.evidence_id in state.fast_catalog_selected_ids
            )
        )

    monkeypatch.setattr(Investigator, "context", selected_context)
    monkeypatch.setattr(Investigator, "_offer_streaming_mixed_frontier", offer)
    slow = replace(probe_definition("slow"), handler=slow_probe)
    with SQLiteStore(tmp_path / "streaming-focus.db") as store:
        app = investigator(store, definitions=(probe_definition("core"), slow))
        app.frontier_ranker = cast(Any, object())
        queued = app.create(objective="Investigate a slow host", budget_ms=10_000)
        running = app._save(  # pyright: ignore[reportPrivateUsage]
            queued.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "test_started",
            "Two registered baseline probes",
        )
        now = utc_now()
        _insert_record(
            store,
            case_id=str(queued.case_id),
            evidence_id=str(evidence_id),
            collector_id="fixture.stored",
            summary="A stored fact worth retrieving",
            observed_at=now,
            captured_at=now,
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
        try:
            result = app._collect(running, proposals, None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        finally:
            slow_release.set()

        assert item_ids
        terminal = SearchFrontierRepository(store).readback(item_ids[0]).status
        if stale_generation:
            assert not saw_focused_turn.is_set(), offer_errors
            assert calls == 1
            assert evidence_id not in result.fast_catalog_selected_ids
            assert terminal is FrontierStatus.FAILED
        else:
            assert saw_focused_turn.is_set(), offer_errors
            assert calls == 2
            assert evidence_id in result.fast_catalog_selected_ids
            assert terminal is FrontierStatus.SATISFIED
            receipts = SearchFrontierRepository(store).focus_delivery_receipts(queued.case_id)
            assert len(receipts) == 1
            assert receipts[0].item_id == item_ids[0]
            assert receipts[0].evidence_id == evidence_id


def test_focus_receipt_survives_interruption_before_case_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence_id = EvidenceId(root="ev_33333333333333333333333333333333")
    with SQLiteStore(tmp_path / "focus-crash.db") as store:
        app = investigator(store, definitions=(probe_definition("core"),))
        queued = app.create(objective="Investigate a slow host", budget_ms=10_000)
        running = app._save(  # pyright: ignore[reportPrivateUsage]
            queued.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "test_started",
            "Simulated owner epoch",
        )
        now = utc_now()
        _insert_record(
            store,
            case_id=str(running.case_id),
            evidence_id=str(evidence_id),
            collector_id="fixture.stored",
            summary="A selected fact that must not disappear silently",
            observed_at=now,
            captured_at=now,
        )
        generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=running.case_id, limit=1))
            .case_evidence_generation
        )
        versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
        frontier = SearchFrontierRepository(store)
        item = frontier.upsert_item(
            running.case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
            versions,
        )
        frontier.claim_ready(item.item_id, versions)
        frontier.transition(
            item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "retrieving"
        )
        frontier.transition(
            item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
        )
        with store.transaction():
            frontier.commit_focus_delivery_in_transaction(
                item.item_id,
                running.case_id,
                evidence_id,
                epoch_state_version=running.state_version,
                evidence_generation=generation,
            )
        # Process dies here, before the owner can checkpoint fast_catalog_selected_ids.
        assert app.repository.load(str(running.case_id)).fast_catalog_selected_ids == ()
        app.repository.save(
            running.model_copy(update={"status": InvestigationStatus.QUEUED}),
            expected_version=running.state_version,
            event="test_requeue_after_crash",
            detail="Application service recovered exclusive owner lease",
        )

        def stop_after_recovery(*_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("stop after recovery")

        monkeypatch.setattr(app, "_collect", stop_after_recovery)
        with pytest.raises(RuntimeError, match="stop after recovery"):
            app._run(str(running.case_id))  # pyright: ignore[reportPrivateUsage]
        recovered = app.repository.load(str(running.case_id))
        assert any(
            item.item_id in warning and str(evidence_id) in warning
            for warning in recovered.warnings
        )
        assert recovered.fast_catalog_selected_ids == ()


def test_focus_delivery_transition_and_receipt_roll_back_together(tmp_path: Path) -> None:
    evidence_id = EvidenceId(root="ev_44444444444444444444444444444444")
    with SQLiteStore(tmp_path / "focus-rollback.db") as store:
        app = investigator(store, definitions=(probe_definition("core"),))
        queued = app.create(objective="Investigate a slow host", budget_ms=10_000)
        now = utc_now()
        _insert_record(
            store,
            case_id=str(queued.case_id),
            evidence_id=str(evidence_id),
            collector_id="fixture.stored",
            summary="Evidence before aborted owner transaction",
            observed_at=now,
            captured_at=now,
        )
        generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=queued.case_id, limit=1))
            .case_evidence_generation
        )
        versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
        frontier = SearchFrontierRepository(store)
        item = frontier.upsert_item(
            queued.case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
            versions,
        )
        frontier.claim_ready(item.item_id, versions)
        frontier.transition(
            item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "retrieving"
        )
        frontier.transition(
            item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
        )
        with pytest.raises(ValueError, match="focus delivery item binding changed"):
            with store.transaction():
                frontier.commit_focus_delivery_in_transaction(
                    item.item_id,
                    queued.case_id,
                    evidence_id,
                    epoch_state_version=queued.state_version + 1,
                    evidence_generation=generation,
                )
        assert frontier.readback(item.item_id).status is FrontierStatus.RUNNING
        with pytest.raises(RuntimeError, match="simulated interruption"):
            with store.transaction():
                frontier.commit_focus_delivery_in_transaction(
                    item.item_id,
                    queued.case_id,
                    evidence_id,
                    epoch_state_version=queued.state_version,
                    evidence_generation=generation,
                )
                raise RuntimeError("simulated interruption")
        assert frontier.readback(item.item_id).status is FrontierStatus.RUNNING
        assert frontier.focus_delivery_receipts(queued.case_id) == ()


def test_completed_plan_does_not_report_evicted_focus_as_crash_gap(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "focus-eviction.db") as store:
        app = investigator(store, definitions=(probe_definition("core"),))
        queued = app.create(objective="Investigate a slow host", budget_ms=10_000)
        running = app._save(  # pyright: ignore[reportPrivateUsage]
            queued.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "test_started",
            "Simulated owner epoch",
        )
        evidence_ids = tuple(EvidenceId(root=f"ev_{index:032x}") for index in range(16, 25))
        for evidence_id in evidence_ids:
            now = utc_now()
            _insert_record(
                store,
                case_id=str(running.case_id),
                evidence_id=str(evidence_id),
                collector_id="fixture.stored",
                summary=f"Focus source {evidence_id}",
                observed_at=now,
                captured_at=now,
            )
        generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=running.case_id, limit=1))
            .case_evidence_generation
        )
        versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
        frontier = SearchFrontierRepository(store)
        for evidence_id in evidence_ids:
            item = frontier.upsert_item(
                running.case_id,
                FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
                versions,
            )
            frontier.claim_ready(item.item_id, versions)
            frontier.transition(
                item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "retrieving"
            )
            frontier.transition(
                item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
            )
            with store.transaction():
                frontier.commit_focus_delivery_in_transaction(
                    item.item_id,
                    running.case_id,
                    evidence_id,
                    epoch_state_version=running.state_version,
                    evidence_generation=generation,
                )
        assert len(frontier.focus_delivery_receipts(running.case_id)) == 9
        checkpoint = app._save(  # pyright: ignore[reportPrivateUsage]
            running.model_copy(update={"fast_catalog_selected_ids": evidence_ids[-8:]}),
            "baseline_collected",
            "Finished plan after nine focused deliveries",
        )
        assert evidence_ids[0] not in checkpoint.fast_catalog_selected_ids
        recovered = app._recover_uncheckpointed_focus_receipts(  # pyright: ignore[reportPrivateUsage]
            app.repository.load(str(running.case_id))
        )
        assert not any("Unresolved focus delivery gap" in warning for warning in recovered.warnings)


def test_streaming_retrieval_excludes_delivered_id_across_parent_generations(
    tmp_path: Path,
) -> None:
    """A second parent must see fresh stored evidence, not repeat the first focus."""
    old_id = EvidenceId(root="ev_55555555555555555555555555555555")
    late_id = EvidenceId(root="ev_66666666666666666666666666666666")
    with SQLiteStore(tmp_path / "cross-parent-focus.db") as store:
        app = investigator(store, definitions=(probe_definition("core"),))
        state = app.create(objective="Investigate a slow host", budget_ms=10_000)
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=str(old_id),
            collector_id="fixture.first_parent",
            summary="First parent's already delivered observation",
            observed_at=utc_now(),
        )
        frontier = SearchFrontierRepository(store)
        first_generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        first_versions = RelevantVersionsV1(objective=1, evidence=first_generation, graph=1)
        first = frontier.upsert_item(
            state.case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=old_id),
            first_versions,
        )
        frontier.claim_ready(first.item_id, first_versions)
        frontier.transition(
            first.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "retrieving"
        )
        frontier.transition(
            first.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
        )
        with store.transaction():
            frontier.commit_focus_delivery_in_transaction(
                first.item_id,
                state.case_id,
                old_id,
                epoch_state_version=state.state_version,
                evidence_generation=first_generation,
            )
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=str(late_id),
            collector_id="fixture.second_parent",
            summary="New observation from the later parent",
            observed_at=utc_now(),
        )
        second_generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        assert second_generation > first_generation
        second_versions = RelevantVersionsV1(objective=1, evidence=second_generation, graph=1)
        repeated = frontier.upsert_item(
            state.case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=old_id),
            second_versions,
        )
        late = frontier.upsert_item(
            state.case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=late_id),
            second_versions,
        )
        filtered = app._streaming_rankable_items(  # pyright: ignore[reportPrivateUsage]
            state, frontier, store, (repeated, late)
        )
        assert tuple(item.item_id for item in filtered) == (late.item_id,)
        requested = state.model_copy(update={"requested_evidence_ids": (old_id,)})
        explicit = app._streaming_rankable_items(  # pyright: ignore[reportPrivateUsage]
            requested, frontier, store, (repeated, late)
        )
        assert tuple(item.item_id for item in explicit) == (repeated.item_id, late.item_id)
        excluded = app._streaming_delivered_retrieval_ids(  # pyright: ignore[reportPrivateUsage]
            requested, frontier, store
        )
        assert old_id not in excluded


def test_streaming_retrieval_does_not_trust_changed_delivered_record(tmp_path: Path) -> None:
    evidence_id = EvidenceId(root="ev_77777777777777777777777777777777")
    with SQLiteStore(tmp_path / "changed-focus.db") as store:
        app = investigator(store, definitions=(probe_definition("core"),))
        state = app.create(objective="Investigate a slow host", budget_ms=10_000)
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=str(evidence_id),
            collector_id="fixture.first_parent",
            summary="Original stored record",
            observed_at=utc_now(),
        )
        generation = (
            EvidenceRetriever(store)
            .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
            .case_evidence_generation
        )
        versions = RelevantVersionsV1(objective=1, evidence=generation, graph=1)
        frontier = SearchFrontierRepository(store)
        item = frontier.upsert_item(
            state.case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
            versions,
        )
        frontier.claim_ready(item.item_id, versions)
        frontier.transition(
            item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "retrieving"
        )
        frontier.transition(
            item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
        )
        with store.transaction():
            frontier.commit_focus_delivery_in_transaction(
                item.item_id,
                state.case_id,
                evidence_id,
                epoch_state_version=state.state_version,
                evidence_generation=generation,
            )
        with store.transaction():
            store.connection.execute(
                "UPDATE evidence SET record_json=? WHERE case_id=? AND evidence_id=?",
                ('{"changed":true}', str(state.case_id), str(evidence_id)),
            )
        with pytest.raises(ValueError, match="focus delivery receipt binding mismatch"):
            app._streaming_rankable_items(  # pyright: ignore[reportPrivateUsage]
                state, frontier, store, (item,)
            )
