"""Only an accepted async deep proposal selected into a real run earns origin custody."""

import json
import sqlite3
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from systemsense.application.deep_proposal_origin import DeepProposalOriginV1
from systemsense.application.deep_worker import (
    DeepMailboxRepository,
    FrozenDeepTaskV1,
    freeze_deep_task,
)
from systemsense.application.investigation_state import InvestigationState
from systemsense.application.investigator import Investigator
from systemsense.decision.contracts import (
    DiagnosticPurpose,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.decision.frontier_ranker import MixedFrontierRanker
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import MeasurementWindow, ProbeInvocation, ProbeManifest
from systemsense.domain.time import utc_now
from systemsense.orchestration.probes import ProbeObservation
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse, ReasoningStatus
from systemsense.storage.deep_proposal_execution_links import DeepProposalExecutionRepository
from systemsense.storage.search_frontier import SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition


def _proposal(probe_id: str) -> ProbeProposal:
    return ProbeProposal(
        probe_id=probe_id,
        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
        priority=1,
        estimated_cost_ms=1,
        resource_class=ResourceClass.CPU,
        dedupe_key=f"deep:{probe_id}",
    )


class _Deep:
    identity = ProviderIdentity(provider_id="fixture-deep", provider_version="1", role="reasoning")

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        return ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=ReasoningStatus.UNRESOLVED,
            summary="The next registered probe could distinguish the explanations.",
            distinguishing_probes=(_proposal("devices.snapshot"),),
        )


def _accepted_case(
    store: SQLiteStore, *, fail_devices: bool = False
) -> tuple[Investigator, InvestigationState]:
    devices = probe_definition("devices")
    if fail_devices:

        def fail(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            raise RuntimeError("synthetic transient collector failure")

        devices = replace(devices, handler=fail)
    app = investigator(
        store,
        reasoning=_Deep(),
        definitions=(probe_definition("core"), devices),
    )
    app.frontier_ranker = MixedFrontierRanker(
        ranker=None,
        provider=ProviderIdentity(
            provider_id="fixture-fast", provider_version="1", role="fast_decision"
        ),
        model_weight_sha256="a" * 64,
    )
    state = app.create(objective="A device issue needs another check", budget_ms=5000)
    state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
    state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
        state, app.context(str(state.case_id), state=state)
    )
    assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
    state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
    return app, state


def _links(store: SQLiteStore, state: InvestigationState) -> list[tuple[str, str, str]]:
    return store.connection.execute(
        "SELECT request_sha256,probe_id,execution_id FROM deep_proposal_execution_links "
        "WHERE case_id=?",
        (str(state.case_id),),
    ).fetchall()


def test_completed_deep_request_is_retired_before_next_request_is_frozen(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "completed-before-review.db") as store:
        app, state = _accepted_case(store)
        selected = state.pending_distinguishing_probes
        state = app._collect(state, selected, None)  # pyright: ignore[reportPrivateUsage]
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state)
        # The event-frontier collection path can retain the accepted request
        # until the next main-loop retirement. A review must not freeze it as
        # still pending after its linked execution has already finished.
        state = state.model_copy(update={"pending_distinguishing_probes": selected})
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        task = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
        assert task is not None
        assert "devices.snapshot" in task.request.completed_probe_ids
        assert "devices.snapshot" not in task.request.pending_probe_ids
        assert not state.pending_distinguishing_probes


@pytest.mark.parametrize(
    "during_collection,reserved", [(False, False), (True, True), (False, True)]
)
def test_new_review_preserves_unfinished_deep_requests(
    tmp_path: Path, during_collection: bool, reserved: bool
) -> None:
    with SQLiteStore(tmp_path / "unfinished-before-review.db") as store:
        app, state = _accepted_case(store)
        selected = state.pending_distinguishing_probes
        if reserved:
            state = state.model_copy(update={"pending_probe_ids": ("devices.snapshot",)})
        app._defer_reasoning_checkpoint = during_collection  # pyright: ignore[reportPrivateUsage]
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        task = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
        assert task is not None
        assert task.request.pending_probe_ids == ("devices.snapshot",)
        assert state.pending_distinguishing_probes == selected


def test_new_review_keeps_a_requested_retry_after_transient_collection_failure(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "retry-before-review.db") as store:
        app, state = _accepted_case(store, fail_devices=True)
        selected = state.pending_distinguishing_probes
        state = app._collect(state, selected, None)  # pyright: ignore[reportPrivateUsage]
        assert store.connection.execute(
            "SELECT status FROM probe_executions WHERE probe_id='devices.snapshot'"
        ).fetchone() == ("failed",)
        state = state.model_copy(update={"pending_distinguishing_probes": selected})
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        task = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
        assert task is not None
        assert "devices.snapshot" not in task.request.completed_probe_ids
        assert task.request.pending_probe_ids == ("devices.snapshot",)
        assert state.pending_distinguishing_probes == selected


def test_accepted_async_proposal_links_only_its_selected_registered_execution(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "deep-origin.db") as store:
        app, state = _accepted_case(store)
        assert [item.probe_id for item in state.pending_distinguishing_probes] == [
            "devices.snapshot"
        ]
        assert store.connection.execute(
            "SELECT status FROM deep_mailbox WHERE case_id=?", (str(state.case_id),)
        ).fetchone() == ("applied",)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, state.pending_distinguishing_probes, None
        )
        executions = store.connection.execute(
            "SELECT execution_id,probe_id,status FROM probe_executions WHERE case_id=? "
            "ORDER BY probe_id",
            (str(state.case_id),),
        ).fetchall()
        assert [row[1] for row in executions] == ["core.snapshot", "devices.snapshot"]
        assert [row[2] for row in executions] == ["ok", "ok"]
        linked = _links(store, state)
        request_sha = store.connection.execute(
            "SELECT request_sha256 FROM deep_mailbox WHERE case_id=? AND status='applied'",
            (str(state.case_id),),
        ).fetchone()[0]
        assert linked == [(request_sha, "devices.snapshot", executions[1][0])]


def test_origin_survives_checkpoint_reload_and_typed_eligibility(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "reloaded.db") as store:
        app, state = _accepted_case(store)
        state = app.repository.load(str(state.case_id))
        proposed, gaps = app._typed_evidence_proposals(state)  # pyright: ignore[reportPrivateUsage]
        assert not gaps
        selected = app._eligible(proposed, state, 1000)  # pyright: ignore[reportPrivateUsage]
        assert [item.probe_id for item in selected] == ["devices.snapshot"]
        state = app._collect(state, selected, None)  # pyright: ignore[reportPrivateUsage]
        assert [item[1] for item in _links(store, state)] == ["devices.snapshot"]


def test_coalescing_requires_exact_applied_origin_and_registered_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "coalescing-gate.db") as store:
        app, state = _accepted_case(store)
        selected = state.pending_distinguishing_probes
        assert app._coalesce_accepted_deep_probe_batch(state, selected)  # pyright: ignore[reportPrivateUsage]
        reconstructed = tuple(
            ProbeProposal.model_validate(item.model_dump(mode="json")) for item in selected
        )
        assert not app._coalesce_accepted_deep_probe_batch(state, reconstructed)  # pyright: ignore[reportPrivateUsage]
        assert not app._coalesce_accepted_deep_probe_batch(  # pyright: ignore[reportPrivateUsage]
            state, (*selected, _proposal("core.snapshot"))
        )
        origin = state.pending_deep_proposal_origins[0]
        wrong_origin = DeepProposalOriginV1.model_validate(
            {**origin.model_dump(mode="json"), "request_sha256": "f" * 64}
        )
        assert not app._coalesce_accepted_deep_probe_batch(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"pending_deep_proposal_origins": (wrong_origin,)}), selected
        )
        original_capabilities = app._case_capabilities  # pyright: ignore[reportPrivateUsage]

        def costlier_capabilities(current: InvestigationState) -> tuple[ProbeCapability, ...]:
            return tuple(
                item.model_copy(update={"cost_ms": 1_000})
                if item.probe_id == "devices.snapshot"
                else item
                for item in original_capabilities(current)
            )

        monkeypatch.setattr(
            app,
            "_case_capabilities",
            costlier_capabilities,
        )
        assert app._coalesce_accepted_deep_probe_batch(state, selected)  # pyright: ignore[reportPrivateUsage]
        remaining_ms = app._remaining_ms  # pyright: ignore[reportPrivateUsage]
        budget_remaining = 1_000

        def fixed_remaining(_state: InvestigationState) -> int:
            return budget_remaining

        monkeypatch.setattr(app, "_remaining_ms", fixed_remaining)
        assert app._coalesce_accepted_deep_probe_batch(state, selected)  # pyright: ignore[reportPrivateUsage]
        budget_remaining = 999
        assert not app._coalesce_accepted_deep_probe_batch(state, selected)  # pyright: ignore[reportPrivateUsage]
        monkeypatch.setattr(app, "_remaining_ms", remaining_ms)
        # A different rejected task in the same case cannot confer authority
        # on an otherwise still-pending proposal.
        applied_task = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
        assert applied_task is not None
        rejected_task = freeze_deep_task(
            applied_task.request.model_copy(update={"objective": "A separate rejected review"}),
            applied_task.presented_read_set,
            provider_identity=applied_task.provider_identity,
            hypothesis_revision=applied_task.hypothesis_revision,
        )
        mailbox = DeepMailboxRepository(store)
        assert mailbox.admit(rejected_task)
        assert mailbox.finish(rejected_task, "rejected", reason="test rejection")
        app._last_deep_admission = rejected_task  # pyright: ignore[reportPrivateUsage]
        assert not app._coalesce_accepted_deep_probe_batch(state, selected)  # pyright: ignore[reportPrivateUsage]
        app._last_deep_admission = applied_task  # pyright: ignore[reportPrivateUsage]
        monkeypatch.setattr(app, "_case_capabilities", original_capabilities)
        original_manifest = app.runtime.probe_manifest

        def changed_manifest(probe_id: str) -> ProbeManifest | None:
            manifest = original_manifest(probe_id)
            return None if manifest is None else manifest.model_copy(update={"version": 2})

        monkeypatch.setattr(
            app.runtime,
            "probe_manifest",
            changed_manifest,
        )
        assert not app._coalesce_accepted_deep_probe_batch(state, selected)  # pyright: ignore[reportPrivateUsage]


def test_exact_plan_instance_receipt_uses_runtime_instance_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "custom-instance.db") as store:
        app, state = _accepted_case(store)
        ordinary_opened = app._opened  # pyright: ignore[reportPrivateUsage]

        def custom_opened(
            current: InvestigationState, proposals: tuple[ProbeProposal, ...]
        ) -> object:
            opened = ordinary_opened(current, proposals)
            plan = opened.plan.model_copy(
                update={
                    "probes": tuple(
                        item.model_copy(update={"instance_id": f"instance:{index}"})
                        for index, item in enumerate(opened.plan.probes)
                    )
                }
            )
            return opened.model_copy(update={"plan": plan})

        monkeypatch.setattr(app, "_opened", custom_opened)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, state.pending_distinguishing_probes, None
        )
        assert store.connection.execute(
            "SELECT plan_instance_id FROM deep_proposal_execution_links WHERE case_id=?",
            (str(state.case_id),),
        ).fetchall() == [("instance:0",)]


def test_reconstructed_same_id_proposal_has_no_deep_origin(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "reconstructed.db") as store:
        app, state = _accepted_case(store)
        reconstructed = tuple(
            ProbeProposal.model_validate(item.model_dump(mode="json"))
            for item in state.pending_distinguishing_probes
        )
        assert reconstructed == state.pending_distinguishing_probes
        assert reconstructed[0] is not state.pending_distinguishing_probes[0]
        state = app._collect(state, reconstructed, None)  # pyright: ignore[reportPrivateUsage]
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state) == []


def test_duplicate_plan_instance_is_rejected_before_origin_or_execution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "duplicate-instance.db") as store:
        app, state = _accepted_case(store)
        same_proposal = state.pending_distinguishing_probes[0]
        with pytest.raises(ValueError, match="plan instance IDs must be unique"):
            app._collect(state, (same_proposal, same_proposal), None)  # pyright: ignore[reportPrivateUsage]
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id='devices.snapshot'",
            (str(state.case_id),),
        ).fetchone() == (0,)
        assert _links(store, state) == []


def test_concurrent_probe_completes_before_deep_apply_without_deep_origin(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "concurrent.db") as store:
        app = investigator(
            store,
            reasoning=_Deep(),
            definitions=(probe_definition("core"), probe_definition("devices")),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="A device issue needs another check", budget_ms=5000)
        state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state,
            app.context(str(state.case_id), state=state),
            concurrent_proposals=(_proposal("devices.snapshot"),),
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state) == []


def test_partial_deep_batch_links_only_selected_probe(tmp_path: Path) -> None:
    class TwoChecks(_Deep):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return (
                super()
                .investigate(request)
                .model_copy(
                    update={
                        "distinguishing_probes": (
                            _proposal("devices.snapshot"),
                            _proposal("storage.snapshot"),
                        )
                    }
                )
            )

    with SQLiteStore(tmp_path / "partial.db") as store:
        app = investigator(
            store,
            reasoning=TwoChecks(),
            definitions=(
                probe_definition("core"),
                probe_definition("devices"),
                probe_definition("storage"),
            ),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="An issue needs two more checks", budget_ms=5000)
        state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        selected = state.pending_distinguishing_probes[:1]
        state = app._collect(state, selected, None)  # pyright: ignore[reportPrivateUsage]
        assert [item.probe_id for item in state.pending_distinguishing_probes] == [
            "storage.snapshot"
        ]
        assert [item.probe_id for item in state.pending_deep_proposal_origins] == [
            "storage.snapshot"
        ]
        assert [item[1] for item in _links(store, state)] == ["devices.snapshot"]


@pytest.mark.parametrize("alteration", ["target", "window"])
def test_exact_origin_readback_rejects_added_target_or_window(
    tmp_path: Path, alteration: str
) -> None:
    with SQLiteStore(tmp_path / f"selector-{alteration}.db") as store:
        app, state = _accepted_case(store)
        origin = state.pending_deep_proposal_origins[0]
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, state.pending_distinguishing_probes, None
        )
        execution_id, selected_version = store.connection.execute(
            "SELECT execution_id,state_version FROM probe_executions "
            "WHERE case_id=? AND probe_id='devices.snapshot'",
            (str(state.case_id),),
        ).fetchone()
        now = utc_now()
        invocation = ProbeInvocation(
            probe_id="devices.snapshot",
            probe_version=1,
            observable="devices.snapshot",
            target_handle="invented-target" if alteration == "target" else None,
            window=(
                MeasurementWindow(start=now, end=now + timedelta(seconds=1))
                if alteration == "window"
                else None
            ),
            parameters={},
        )
        manifest = app.runtime.probe_manifest("devices.snapshot")
        assert manifest is not None
        with store.transaction(), pytest.raises(ValueError, match="gained a selector"):
            DeepProposalExecutionRepository(store).link_observed_execution_in_transaction(
                origin=origin,
                selected_state_version=int(selected_version),
                plan_instance_id="devices.snapshot",
                execution_id=execution_id,
                invocation=invocation,
                manifest=manifest,
            )


@pytest.mark.parametrize("provided_plan_id", ["other-registered-plan", ""])
def test_origin_write_rejects_wrong_or_empty_plan_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provided_plan_id: str
) -> None:
    with SQLiteStore(tmp_path / "wrong-plan.db") as store:
        app, state = _accepted_case(store)
        link = DeepProposalExecutionRepository.link_observed_execution_in_transaction

        def wrong_plan_link(
            self: DeepProposalExecutionRepository,
            *,
            origin: DeepProposalOriginV1,
            selected_state_version: int,
            plan_instance_id: str,
            execution_id: str,
            invocation: ProbeInvocation,
            manifest: ProbeManifest,
        ) -> None:
            link(
                self,
                origin=origin,
                selected_state_version=selected_state_version,
                plan_instance_id=provided_plan_id,
                execution_id=execution_id,
                invocation=invocation,
                manifest=manifest,
            )

        monkeypatch.setattr(
            DeepProposalExecutionRepository,
            "link_observed_execution_in_transaction",
            wrong_plan_link,
        )
        with pytest.warns(RuntimeWarning, match="Deep proposal execution origin unavailable"):
            state = app._collect(  # pyright: ignore[reportPrivateUsage]
                state, state.pending_distinguishing_probes, None
            )
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state) == []


def test_coincident_probe_after_explicit_deep_cancellation_has_no_origin(tmp_path: Path) -> None:
    class CancellingDeep:
        identity = _Deep.identity

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return ReasoningResponse(
                schema_version=2,
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The pending check is no longer requested.",
                cancelled_probe_ids=("devices.snapshot",),
            )

    with SQLiteStore(tmp_path / "cancelled.db") as store:
        app, state = _accepted_case(store)
        app.frontier_ranker = None
        app.reasoning = CancellingDeep()
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert not state.pending_distinguishing_probes
        assert not state.pending_deep_proposal_origins
        state = app._collect(state, (_proposal("devices.snapshot"),), None)  # pyright: ignore[reportPrivateUsage]
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state) == []


def test_same_id_synchronous_advice_overwrite_clears_async_origin(tmp_path: Path) -> None:
    class OverwritingDeep:
        identity = _Deep.identity

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            replacement = _proposal("devices.snapshot").model_copy(
                update={"dedupe_key": "replacement:devices.snapshot"}
            )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="A new advisory suggests the same registered check.",
                distinguishing_probes=(replacement,),
            )

    with SQLiteStore(tmp_path / "overwrite.db") as store:
        app, state = _accepted_case(store)
        app.frontier_ranker = None
        app.reasoning = OverwritingDeep()
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert [item.dedupe_key for item in state.pending_distinguishing_probes] == [
            "replacement:devices.snapshot"
        ]
        assert state.pending_deep_proposal_origins == ()
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, state.pending_distinguishing_probes, None
        )
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state) == []


def test_degraded_async_result_cannot_mint_origin(tmp_path: Path) -> None:
    class DegradedDeep(_Deep):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return super().investigate(request).model_copy(update={"degraded": True})

    with SQLiteStore(tmp_path / "degraded.db") as store:
        app = investigator(
            store,
            reasoning=DegradedDeep(),
            definitions=(probe_definition("core"), probe_definition("devices")),
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="A device issue needs another check", budget_ms=5000)
        state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        state, _ = app._reason(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state)
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert state.pending_deep_proposal_origins == ()
        assert store.connection.execute(
            "SELECT status FROM deep_mailbox WHERE case_id=?", (str(state.case_id),)
        ).fetchone() == ("rejected",)
        state = app._collect(state, (_proposal("devices.snapshot"),), None)  # pyright: ignore[reportPrivateUsage]
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state) == []


@pytest.mark.parametrize("tamper", ["request_sha256", "manifest_sha256", "probe_version"])
def test_forged_or_changed_origin_never_links_real_execution(tmp_path: Path, tamper: str) -> None:
    with SQLiteStore(tmp_path / f"tamper-{tamper}.db") as store:
        app, state = _accepted_case(store)
        origin = state.pending_deep_proposal_origins[0]
        altered = origin.model_copy(update={tamper: 2 if tamper == "probe_version" else "b" * 64})
        state = state.model_copy(update={"pending_deep_proposal_origins": (altered,)})
        with pytest.warns(RuntimeWarning, match="Deep proposal execution origin unavailable"):
            state = app._collect(  # pyright: ignore[reportPrivateUsage]
                state, state.pending_distinguishing_probes, None
            )
        assert "devices.snapshot" in state.completed_probe_ids
        assert _links(store, state) == []


def test_provenance_insert_failure_does_not_suppress_collected_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_link(*_args: object, **_kwargs: object) -> None:
        raise sqlite3.IntegrityError("injected origin receipt failure")

    with SQLiteStore(tmp_path / "receipt-failure.db") as store:
        app, state = _accepted_case(store)
        monkeypatch.setattr(
            DeepProposalExecutionRepository,
            "link_observed_execution_in_transaction",
            fail_link,
        )
        with pytest.warns(RuntimeWarning, match="Deep proposal execution origin unavailable"):
            state = app._collect(  # pyright: ignore[reportPrivateUsage]
                state, state.pending_distinguishing_probes, None
            )
        assert "devices.snapshot" in state.completed_probe_ids
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM evidence AS e JOIN probe_executions AS x "
                "ON x.execution_id=e.execution_id WHERE e.case_id=? "
                "AND x.probe_id='devices.snapshot'",
                (str(state.case_id),),
            ).fetchone()[0]
            >= 1
        )
        assert _links(store, state) == []


def test_downstream_persistence_failure_rolls_back_execution_and_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_after_link(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("injected downstream persistence failure")

    with SQLiteStore(tmp_path / "rollback.db") as store:
        app, state = _accepted_case(store)
        monkeypatch.setattr(SearchFrontierRepository, "append_result_event", fail_after_link)
        with pytest.raises(RuntimeError, match="downstream persistence failure"):
            app._collect(state, state.pending_distinguishing_probes, None)  # pyright: ignore[reportPrivateUsage]
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id='devices.snapshot'",
            (str(state.case_id),),
        ).fetchone() == (0,)
        assert _links(store, state) == []


def test_legacy_checkpoint_has_no_inferred_deep_origin(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    with SQLiteStore(database) as store:
        state = investigator(store).create(objective="A device issue needs checking")
        payload = state.model_dump(mode="json", exclude={"pending_deep_proposal_origins"})
        payload["schema_version"] = 6
        restored = InvestigationState.model_validate(payload)
        assert restored.pending_deep_proposal_origins == ()
        with store.transaction():
            store.connection.execute(
                "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
                (json.dumps(payload), str(state.case_id)),
            )
    # Reconstruct the previous schema on this disposable DB, then exercise the
    # additive migration and old checkpoint readback together.
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER deep_proposal_execution_links_no_update")
        connection.execute("DROP TRIGGER deep_proposal_execution_links_no_delete")
        connection.execute("DROP TABLE deep_proposal_execution_links")
        connection.execute("DROP TABLE json_copy_operations")
        connection.execute("PRAGMA user_version=37")
    with SQLiteStore(database) as upgraded:
        loaded = investigator(upgraded).repository.load(str(state.case_id))
        assert loaded.schema_version == 6
        assert loaded.pending_deep_proposal_origins == ()
        assert (
            upgraded.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='deep_proposal_execution_links'"
            ).fetchone()
            is not None
        )


def test_frozen_mailbox_validator_recomputes_source_request_digest(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "digest.db") as store:
        _, state = _accepted_case(store)
        stored = store.connection.execute(
            "SELECT task_json FROM deep_mailbox WHERE case_id=? AND status='applied'",
            (str(state.case_id),),
        ).fetchone()[0]
        task = json.loads(stored)
        task["request"]["objective"] = "Different symptom after admission"
        with pytest.raises(ValueError, match="frozen_reasoning_request_digest_mismatch"):
            FrozenDeepTaskV1.model_validate(task)
