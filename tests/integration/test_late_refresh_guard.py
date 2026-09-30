from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

import systemsense.application.investigator as investigator_module
from systemsense.application.deep_worker import DeepWorkerResultV1
from systemsense.application.investigation_state import InvestigationState
from systemsense.application.late_refresh_guard import (
    accepted_late_review_baseline,
    should_refresh_late_review,
)
from systemsense.decision.contracts import (
    DiagnosticPurpose,
    FastSignal,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.knowledge.windows_errors import reference_for_text
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import (
    EvidenceDetailRequest,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.storage.sqlite_store import SQLiteStore

_CASE = CaseId(root="case_0123456789abcdef0123456789abcdef")


def _evidence(
    evidence_id: str,
    probe_id: str,
    *,
    status: EvidenceContextStatus = EvidenceContextStatus.OBSERVED,
    facts: dict[str, JsonValue] | None = None,
    limitations: tuple[str, ...] = (),
) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=EvidenceId(root=evidence_id),
        observed_at=datetime(2026, 9, 30, 9, 31, 13, 457611, tzinfo=UTC),
        captured_at=datetime(2026, 9, 30, 9, 31, 13, 524481, tzinfo=UTC),
        probe_id=probe_id,
        summary=f"Saved {probe_id} observation",
        facts={} if facts is None else facts,
        status=status,
        case_scope="current_case",
        incident_relevant=True,
        limitations=limitations,
    )


def _request(
    *,
    context: tuple[EvidenceContext, ...] | None = None,
    **updates: object,
) -> ReasoningRequest:
    evidence_context = context or (
        _evidence(
            "ev_11111111111111111111111111111111",
            "application.target_pressure",
            facts={"target_pressure": {"cpu_logical_cores": 0.98}},
            limitations=(
                "Graph packet omitted 345 of 409 grounded relationships because "
                "the model edge limit is 64.",
            ),
        ),
        _evidence(
            "ev_22222222222222222222222222222222",
            "application.snapshot.coverage",
            status=EvidenceContextStatus.UNAVAILABLE,
            limitations=("access denied",),
        ),
    )
    base: dict[str, object] = {
        "schema_version": 7,
        "case_id": _CASE,
        "state_version": 13,
        "correlation_id": "reasoning:test:13",
        "deadline_at": "2026-09-30T09:32:30.800851Z",
        "objective": "Is target.exe using a core?",
        "observer_context": (
            "Case brief coverage: Candidate evidence contexts omitted by case brief bounds: 1.",
        ),
        "evidence_ids": tuple(item.evidence_id for item in evidence_context),
        "evidence_context": evidence_context,
        "available_probes": (
            ProbeCapability(
                probe_id="application.snapshot",
                description="Collect an application process snapshot.",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        "budget_ms": 60_000,
        "max_probes": 2,
    }
    base.update(updates)
    return ReasoningRequest.model_validate(base)


def _response(
    request: ReasoningRequest,
    **updates: object,
) -> ReasoningResponse:
    base: dict[str, object] = {
        "provider": ProviderIdentity(
            provider_id="test-deep", provider_version="1", role="reasoning"
        ),
        "case_id": request.case_id,
        "state_version": request.state_version,
        "correlation_id": request.correlation_id,
        "deadline_at": request.deadline_at,
        "status": ReasoningStatus.UNRESOLVED,
        "summary": "The cause remains unknown.",
    }
    base.update(updates)
    return ReasoningResponse.model_validate(base).validate_against(request)


def _proposal(probe_id: str) -> ProbeProposal:
    return ProbeProposal(
        probe_id=probe_id,
        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
        priority=0.5,
        estimated_cost_ms=100,
        resource_class=ResourceClass.CPU,
        dedupe_key=probe_id,
    )


def _candidate_with(context: tuple[EvidenceContext, ...], **updates: object) -> ReasoningRequest:
    previous = _request()
    return previous.model_copy(
        update={
            "state_version": 31,
            "correlation_id": "reasoning:test:31",
            "budget_ms": 53_744,
            "evidence_context": context,
            "evidence_ids": tuple(item.evidence_id for item in context),
            **updates,
        }
    )


def test_omitted_storage_catalog_and_bookkeeping_do_not_call_provider_again() -> None:
    previous = _request()
    response = _response(previous)
    candidate = _candidate_with(previous.evidence_context)
    candidate = candidate.model_copy(
        update={
            "evidence_ids": (
                EvidenceId(root="ev_33333333333333333333333333333333"),
                *candidate.evidence_ids,
            ),
            "evidence_catalog": ({"evidence_id": "ev_storage", "summary": "Volumes"},),
            "completed_probe_ids": frozenset({"application.snapshot"}),
            "observer_context": (
                "Case brief coverage: Candidate evidence contexts omitted by case brief bounds: 2.",
            ),
            "evidence_context": (
                candidate.evidence_context[0].model_copy(
                    update={
                        "limitations": (
                            *candidate.evidence_context[0].limitations,
                            "Graph packet omitted 348 of 412 grounded relationships because "
                            "the model edge limit is 64.",
                        )
                    }
                ),
                candidate.evidence_context[1],
            ),
        }
    )
    provider_calls: list[ReasoningRequest] = []
    if should_refresh_late_review(previous, candidate, response):
        provider_calls.append(candidate)
    assert provider_calls == []


def test_new_visible_fact_triggers_review() -> None:
    previous = _request()
    response = _response(previous)
    added = _evidence(
        "ev_33333333333333333333333333333333",
        "application.target_pressure",
        facts={"target_pressure": {"cpu_logical_cores": 0.99}},
    )
    candidate = _candidate_with((*previous.evidence_context, added))
    assert should_refresh_late_review(previous, candidate, response)


def test_real_access_gap_change_triggers_review() -> None:
    previous = _request()
    response = _response(previous)
    changed_gap = previous.evidence_context[1].model_copy(
        update={"limitations": ("coverage unavailable",)}
    )
    candidate = _candidate_with((previous.evidence_context[0], changed_gap))
    assert should_refresh_late_review(previous, candidate, response)


def test_explicit_prior_evidence_probe_and_detail_requests_refresh() -> None:
    asked_id = EvidenceId(root="ev_33333333333333333333333333333333")
    previous = _request().model_copy(update={"evidence_ids": (*_request().evidence_ids, asked_id)})
    requested = _response(previous, requested_evidence_ids=(asked_id,))
    candidate_context = _evidence(str(asked_id), "incident.events", facts={"events": ["sample"]})
    candidate = _candidate_with((*previous.evidence_context, candidate_context))
    candidate = candidate.model_copy(update={"evidence_ids": (*candidate.evidence_ids, asked_id)})
    assert should_refresh_late_review(previous, candidate, requested)

    asked_probe = _response(
        previous,
        distinguishing_probes=(
            {
                "probe_id": "application.snapshot",
                "purpose": "distinguish_hypotheses",
                "priority": 0.5,
                "estimated_cost_ms": 100,
                "resource_class": "cpu",
                "dedupe_key": "application.snapshot",
            },
        ),
    )
    completed_probe = candidate.model_copy(
        update={"completed_probe_ids": frozenset({"application.snapshot"})}
    )
    assert should_refresh_late_review(previous, completed_probe, asked_probe)


def test_reference_and_error_context_changes_are_material() -> None:
    previous = _request()
    response = _response(previous)
    changed_reference = _candidate_with(
        previous.evidence_context,
        reference_context=({"node_id": "kn_disk_latency", "label": "Disk latency"},),
    )
    assert should_refresh_late_review(previous, changed_reference, response)

    error_reference = reference_for_text("Win32 error 5")[0]
    changed_error = _candidate_with(previous.evidence_context, error_references=(error_reference,))
    assert should_refresh_late_review(previous, changed_error, response)


def test_explicit_requested_detail_triggers_only_when_completed() -> None:
    previous = _request()
    response = _response(
        previous,
        requested_details=(
            EvidenceDetailRequest(
                evidence_id=previous.evidence_context[0].evidence_id,
                match_literals=("cpu",),
            ),
        ),
    )
    completed = _candidate_with(
        previous.evidence_context,
        completed_detail_requests=response.requested_details,
    )
    assert should_refresh_late_review(previous, completed, response)


def test_rejected_or_degraded_prior_response_never_suppresses() -> None:
    previous = _request()
    degraded = _response(previous, degraded=True)
    candidate = _candidate_with(previous.evidence_context)
    assert should_refresh_late_review(previous, candidate, degraded)


def test_non_late_normal_review_is_outside_this_gate() -> None:
    previous = _request()
    candidate = _candidate_with(previous.evidence_context)
    # Ordinary `_reason` calls pass no baseline and therefore do not consult
    # this predicate; this confirms only the refresh-specific comparison is quiet.
    assert not should_refresh_late_review(previous, candidate, _response(previous))


def test_investigator_refresh_path_skips_catalog_only_storage_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from systemsense.decision.frontier_ranker import MixedFrontierRanker
    from tests.integration.test_investigator import investigator as build_investigator
    from tests.integration.test_investigator import probe_definition

    class Deep:
        identity = ProviderIdentity(
            provider_id="late-refresh-test", provider_version="1", role="reasoning"
        )

        def __init__(self) -> None:
            self.calls: list[ReasoningRequest] = []

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls.append(request)
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The cause remains unknown.",
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="investigate_current",
                        statement="A current explanation to investigate.",
                        status=HypothesisStatus.UNRESOLVED,
                    ),
                ),
            )

    deep = Deep()
    with SQLiteStore(tmp_path / "late-refresh-caller.db") as store:
        base = build_investigator(
            store,
            definitions=(
                probe_definition("core"),
                probe_definition("storage"),
                probe_definition("network"),
            ),
            reasoning=deep,
        )
        app = investigator_module.Investigator(
            store=store,
            runtime=base.runtime,
            capabilities=base.capabilities,
            decision=base.decision,
            reasoning=deep,
        )
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )

        def references(
            current: InvestigationState, *, hypothesis_briefs: tuple[str, ...] | None = None
        ) -> tuple[dict[str, JsonValue], ...]:
            assert current.case_id is not None
            # A fixed knowledge catalog renders a different packet after the
            # accepted answer changes its hypothesis-derived search terms.
            query = (
                tuple(item.statement for item in current.hypotheses)
                if hypothesis_briefs is None
                else hypothesis_briefs
            )
            assert "An excluded old hypothesis." not in query
            if query:
                return ({"node_id": "new_derived_reference"},)
            return ({"node_id": "original_reference"},)

        monkeypatch.setattr(app, "reference_context", references)
        state = app.create(objective="Is the target process using a core?", budget_ms=10_000)
        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("core.snapshot"),), None, baseline=True
        )
        prior_context = app.context(str(state.case_id), state=state)
        state, _ = app._reason_with_details(  # pyright: ignore[reportPrivateUsage]
            state, prior_context
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert len(deep.calls) == 1
        task = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
        assert task is not None
        completed = store.connection.execute(
            "SELECT status,result_json FROM deep_mailbox WHERE case_id=? AND request_sha256=?",
            (str(state.case_id), task.request_sha256),
        ).fetchone()
        assert completed is not None and completed[0] == "applied"
        result = DeepWorkerResultV1.model_validate_json(str(completed[1]))
        assert result.status == "completed" and result.response is not None
        response = result.response
        mailbox_before = int(
            store.connection.execute(
                "SELECT COUNT(*) FROM deep_mailbox WHERE case_id=?", (str(state.case_id),)
            ).fetchone()[0]
        )
        assert mailbox_before == 1

        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("storage.snapshot"),), None, baseline=True
        )
        captured_candidates: list[ReasoningRequest] = []
        original_guard = investigator_module.should_refresh_late_review

        def record_candidate(
            old: ReasoningRequest,
            candidate: ReasoningRequest,
            accepted: ReasoningResponse,
        ) -> bool:
            captured_candidates.append(candidate)
            return original_guard(old, candidate, accepted)

        monkeypatch.setattr(investigator_module, "should_refresh_late_review", record_candidate)
        state, _ = app._reason_with_details(  # pyright: ignore[reportPrivateUsage]
            state,
            prior_context,
            late_refresh_baseline=(task.request, response),
        )
        assert captured_candidates
        candidate = captured_candidates[0]
        assert all(item.probe_id != "storage.snapshot" for item in candidate.evidence_context)
        assert any(
            entry.get("collector_id") == "storage.snapshot" for entry in candidate.evidence_catalog
        )
        assert len(deep.calls) == 1
        mailbox_after = int(
            store.connection.execute(
                "SELECT COUNT(*) FROM deep_mailbox WHERE case_id=?", (str(state.case_id),)
            ).fetchone()[0]
        )
        assert mailbox_after == mailbox_before

        state = app._collect(  # pyright: ignore[reportPrivateUsage]
            state, (_proposal("network.snapshot"),), None, baseline=True
        )
        network_context = app.context(str(state.case_id), state=state)
        state, _ = app._reason_with_details(  # pyright: ignore[reportPrivateUsage]
            state,
            network_context,
            late_refresh_baseline=(task.request, response),
        )
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        assert len(deep.calls) == 2
        assert any(item.probe_id == "network.snapshot" for item in deep.calls[1].evidence_context)
        assert deep.calls[1].reference_context == ({"node_id": "new_derived_reference"},)


@pytest.mark.parametrize(
    "mailbox_state", ("applied", "rejected", "malformed", "wrong_hash", "degraded")
)
def test_refresh_entry_and_only_valid_applied_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mailbox_state: str
) -> None:
    from systemsense.decision.frontier_ranker import MixedFrontierRanker
    from tests.integration.test_investigator import investigator as build_investigator

    class Deep:
        identity = ProviderIdentity(
            provider_id="entry-test", provider_version="1", role="reasoning"
        )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return _response(request, provider=self.identity)

    with SQLiteStore(tmp_path / "late-entry.db") as store:
        app = build_investigator(store, reasoning=Deep())
        app.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fast", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        state = app.create(objective="Investigate slow network", budget_ms=10_000)
        state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        state, _ = app._reason_with_details(state, app.context(str(state.case_id), state=state))  # pyright: ignore[reportPrivateUsage]
        assert app._deep_lane.wait(1)  # pyright: ignore[reportPrivateUsage]
        state = app._drain_deep(state)  # pyright: ignore[reportPrivateUsage]
        task = app._last_deep_admission  # pyright: ignore[reportPrivateUsage]
        assert task is not None
        row = store.connection.execute(
            "SELECT result_json FROM deep_mailbox WHERE case_id=? AND request_sha256=?",
            (str(state.case_id), task.request_sha256),
        ).fetchone()
        assert row is not None
        result = DeepWorkerResultV1.model_validate_json(str(row[0]))
        assert result.response is not None
        saved_response = result.response
        status = "rejected" if mailbox_state == "rejected" else "applied"
        if mailbox_state == "wrong_hash":
            result = result.model_copy(update={"request_sha256": "b" * 64})
        if mailbox_state == "degraded":
            result = result.model_copy(
                update={"response": saved_response.model_copy(update={"degraded": True})}
            )
        raw = "{" if mailbox_state == "malformed" else result.model_dump_json()
        checked_baseline = accepted_late_review_baseline(
            task.request, task.request_sha256, status, raw
        )
        assert (checked_baseline is not None) == (mailbox_state == "applied")
        state = app._collect(state, (_proposal("network.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        baselines: list[tuple[ReasoningRequest, ReasoningResponse] | None] = []

        def record_review(
            current: InvestigationState,
            context: tuple[EvidenceContext, ...],
            *,
            fast_signals: tuple[FastSignal, ...] = (),
            late_refresh_baseline: tuple[ReasoningRequest, ReasoningResponse] | None = None,
        ) -> tuple[InvestigationState, tuple[ProbeProposal, ...]]:
            assert any(item.probe_id == "network.snapshot" for item in context)
            assert not fast_signals
            baselines.append(late_refresh_baseline)
            return current, ()

        monkeypatch.setattr(app, "_reason_with_details", record_review)
        app._refresh_deep_after_late_evidence(state)  # pyright: ignore[reportPrivateUsage]
        assert len(baselines) == 1
        assert baselines[0] is not None
        assert baselines[0][0] == task.request


def test_available_checks_and_graph_capacity_changes_remain_material() -> None:
    previous = _request()
    response = _response(previous)
    available = (
        *previous.available_probes,
        ProbeCapability(
            probe_id="network.listeners",
            description="Check the bound listener.",
            cost_ms=100,
            resource_class=ResourceClass.CPU,
        ),
    )
    assert should_refresh_late_review(
        previous, previous.model_copy(update={"available_probes": available}), response
    )
    changed_limit = previous.evidence_context[0].model_copy(
        update={
            "limitations": (
                "Graph packet omitted 380 of 409 grounded relationships "
                "because the model edge limit is 32.",
            )
        }
    )
    assert should_refresh_late_review(
        previous, _candidate_with((changed_limit, previous.evidence_context[1])), response
    )


def test_reference_query_uses_only_hypotheses_retained_in_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tests.integration.test_investigator import investigator as build_investigator

    with SQLiteStore(tmp_path / "reference-query.db") as store:
        app = build_investigator(store)
        state = app.create(objective="Investigate application", budget_ms=10_000)
        state = app._collect(state, (_proposal("core.snapshot"),), None, baseline=True)  # pyright: ignore[reportPrivateUsage]
        excluded = Hypothesis(
            hypothesis_id="outside_packet",
            statement="An excluded old hypothesis.",
            status=HypothesisStatus.UNRESOLVED,
            supporting_evidence_ids=(EvidenceId(root="ev_" + "f" * 32),),
        )
        state = state.model_copy(update={"hypotheses": (excluded,)})
        calls: list[tuple[str, ...] | None] = []

        def references(
            current: InvestigationState, *, hypothesis_briefs: tuple[str, ...] | None = None
        ) -> tuple[dict[str, JsonValue], ...]:
            assert current.hypotheses == (excluded,)
            calls.append(hypothesis_briefs)
            return ()

        monkeypatch.setattr(app, "reference_context", references)
        app._reason(state, app.context(str(state.case_id), state=state))  # pyright: ignore[reportPrivateUsage]
        assert calls == [()]
