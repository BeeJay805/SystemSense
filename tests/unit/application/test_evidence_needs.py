"""Advisory evidence needs must retain registry, target and budget boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from systemsense.application.evidence_needs import (
    EvidenceNeedGapReason,
    EvidenceNeedResolution,
    resolve_evidence_needs,
)
from systemsense.application.investigation_state import MeasurementGap
from systemsense.decision.contracts import DiagnosticPurpose, ProbeCapability
from systemsense.domain.probes import MeasurementNeed, MeasurementWindow
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import ExpectedFact, Hypothesis, HypothesisStatus


def _capability(
    probe_id: str,
    *,
    cost_ms: int = 20,
    observable_ids: tuple[str, ...] = (),
    target_handles: tuple[str, ...] = (),
    supports_window: bool = False,
) -> ProbeCapability:
    return ProbeCapability(
        probe_id=probe_id,
        description=f"Read {probe_id} measurement",
        cost_ms=cost_ms,
        resource_class=ResourceClass.CPU,
        observable_ids=observable_ids,
        target_handles=target_handles,
        supports_window=supports_window,
    )


def test_explicit_browser_and_application_controls_stay_feasible() -> None:
    capabilities = (
        _capability("browser.direct_control"),
        _capability("browser.external_control"),
        _capability("application.task_timing"),
        _capability("application.external_control"),
    )
    result = resolve_evidence_needs(
        hypotheses=(),
        explicit_requested_probe_ids=tuple(item.probe_id for item in capabilities),
        capabilities=capabilities,
        remaining_budget_ms=100,
        remaining_slots=4,
    )
    assert tuple(item.probe_id for item in result.proposals) == tuple(
        item.probe_id for item in capabilities
    )
    assert all(item.purpose is DiagnosticPurpose.CHECK_COVERAGE for item in result.proposals)
    assert result.gaps == ()


def test_hypothesis_ids_and_expected_facts_are_deduplicated_without_prose() -> None:
    hypothesis = Hypothesis(
        hypothesis_id="h1",
        statement="The browser may use an unexpected route.",
        status=HypothesisStatus.UNRESOLVED,
        distinguishing_probe_ids=("browser.direct_control", "browser.proxy_settings"),
        expected_facts=(
            ExpectedFact(
                probe_id="browser.direct_control", fact_name="status", expected_value="ok"
            ),
        ),
    )
    result = resolve_evidence_needs(
        hypotheses=(hypothesis,),
        explicit_requested_probe_ids=("browser.proxy_settings",),
        capabilities=(
            _capability("browser.proxy_settings"),
            _capability("browser.direct_control"),
        ),
        remaining_budget_ms=40,
        remaining_slots=2,
    )
    assert tuple(item.probe_id for item in result.proposals) == (
        "browser.proxy_settings",
        "browser.direct_control",
    )
    assert result.proposals[1].purpose is DiagnosticPurpose.DISTINGUISH_HYPOTHESES
    assert result.gaps == ()


def test_status_and_budget_gaps_are_precise() -> None:
    ids = (
        "probe.satisfied",
        "probe.pending",
        "probe.completed",
        "probe.unavailable",
        "probe.unauthorized",
        "probe.ready",
        "probe.too_expensive",
        "probe.not_registered",
    )
    result = resolve_evidence_needs(
        hypotheses=(),
        explicit_requested_probe_ids=ids,
        capabilities=tuple(_capability(item, cost_ms=20) for item in ids[:-1]),
        satisfied_probe_ids=frozenset({"probe.satisfied"}),
        pending_probe_ids=frozenset({"probe.pending"}),
        completed_probe_ids=frozenset({"probe.completed"}),
        unavailable_probe_ids=frozenset({"probe.unavailable"}),
        unauthorized_probe_ids=frozenset({"probe.unauthorized"}),
        remaining_budget_ms=25,
        remaining_slots=1,
    )
    assert tuple(item.probe_id for item in result.proposals) == ("probe.ready",)
    gaps = {item.probe_id: item.reason for item in result.gaps}
    assert gaps == {
        "probe.satisfied": EvidenceNeedGapReason.ALREADY_SATISFIED,
        "probe.pending": EvidenceNeedGapReason.PENDING,
        "probe.completed": EvidenceNeedGapReason.COMPLETED_NOT_RETRYABLE,
        "probe.unavailable": EvidenceNeedGapReason.UNAVAILABLE,
        "probe.unauthorized": EvidenceNeedGapReason.UNAUTHORIZED,
        "probe.too_expensive": EvidenceNeedGapReason.SLOTS_EXHAUSTED,
        "probe.not_registered": EvidenceNeedGapReason.UNREGISTERED,
    }


def test_bound_target_window_and_changed_gap_context() -> None:
    now = datetime.now(UTC)
    window = MeasurementWindow(start=now - timedelta(seconds=5), end=now)
    capability = _capability(
        "application.target_pressure",
        observable_ids=("application.target_pressure",),
        target_handles=("target_a", "target_b"),
        supports_window=True,
    )
    prior_need = MeasurementNeed(
        capability_id=capability.probe_id,
        observable="application.target_pressure",
        target_handle="target_a",
        window=window,
    )
    recorded = MeasurementGap(need=prior_need, reason="Target was unavailable.", recorded_at=now)

    def resolve_bound(bound_need: MeasurementNeed | None = None) -> EvidenceNeedResolution:
        return resolve_evidence_needs(
            hypotheses=(),
            explicit_requested_probe_ids=(capability.probe_id,),
            capabilities=(capability,),
            remaining_budget_ms=20,
            remaining_slots=1,
            recorded_measurement_gaps=(recorded,),
            window_required_probe_ids=frozenset({capability.probe_id}),
            bound_needs={capability.probe_id: bound_need} if bound_need is not None else None,
        )

    assert resolve_bound().gaps[0].reason is EvidenceNeedGapReason.AMBIGUOUS_TARGET
    missing_window = MeasurementNeed(
        capability_id=capability.probe_id,
        observable="application.target_pressure",
        target_handle="target_b",
    )
    assert resolve_bound(missing_window).gaps[0].reason is EvidenceNeedGapReason.MISSING_WINDOW
    new_need = missing_window.model_copy(update={"window": window})
    result = resolve_bound(new_need)
    assert len(result.proposals) == 1
    assert result.proposals[0].measurement_need == new_need
    assert result.gaps == ()
    assert resolve_bound(prior_need).gaps[0].reason is EvidenceNeedGapReason.RECORDED_GAP


def test_pending_cleared_and_retryable_completed_can_be_reconsidered() -> None:
    capability = _capability("browser.direct_control")

    def resolve_pending(pending: bool) -> EvidenceNeedResolution:
        return resolve_evidence_needs(
            hypotheses=(),
            explicit_requested_probe_ids=(capability.probe_id,),
            capabilities=(capability,),
            completed_probe_ids=frozenset({capability.probe_id}),
            retryable_probe_ids=frozenset({capability.probe_id}),
            pending_probe_ids=frozenset({capability.probe_id}) if pending else (),
            remaining_budget_ms=20,
            remaining_slots=1,
        )

    assert resolve_pending(True).gaps[0].reason is EvidenceNeedGapReason.PENDING
    result = resolve_pending(False)
    assert len(result.proposals) == 1
    assert result.proposals[0].purpose is DiagnosticPurpose.REFRESH_EVIDENCE


def test_budget_and_missing_binding_are_reported_without_guessing() -> None:
    generic = _capability("browser.external_control", cost_ms=30)
    unbound = _capability("application.target_pressure", cost_ms=20)
    result = resolve_evidence_needs(
        hypotheses=(),
        explicit_requested_probe_ids=(generic.probe_id, unbound.probe_id),
        capabilities=(generic, unbound),
        remaining_budget_ms=20,
        remaining_slots=2,
        target_required_probe_ids=(unbound.probe_id,),
    )
    assert result.proposals == ()
    assert tuple(item.reason for item in result.gaps) == (
        EvidenceNeedGapReason.BUDGET_EXHAUSTED,
        EvidenceNeedGapReason.MISSING_TARGET,
    )


def test_unregistered_prose_and_invalid_bound_handle_cannot_mint_probe() -> None:
    hypothesis = Hypothesis(
        hypothesis_id="h1",
        statement="Try browser.secret_probe on an arbitrary local process.",
        status=HypothesisStatus.UNRESOLVED,
    )
    capability = _capability(
        "application.target_pressure",
        observable_ids=("application.target_pressure",),
        target_handles=("source_bound_handle",),
    )
    result = resolve_evidence_needs(
        hypotheses=(hypothesis,),
        explicit_requested_probe_ids=(capability.probe_id,),
        capabilities=(capability,),
        remaining_budget_ms=20,
        remaining_slots=1,
        bound_needs={
            capability.probe_id: MeasurementNeed(
                capability_id=capability.probe_id,
                observable="application.target_pressure",
                target_handle="invented_handle",
            )
        },
    )
    assert result.proposals == ()
    assert tuple(item.reason for item in result.gaps) == (EvidenceNeedGapReason.UNAUTHORIZED,)


def test_unsupported_window_is_an_explicit_unavailable_gap() -> None:
    capability = _capability(
        "application.target_pressure",
        observable_ids=("application.target_pressure",),
        target_handles=("source_bound_handle",),
    )
    result = resolve_evidence_needs(
        hypotheses=(),
        explicit_requested_probe_ids=(capability.probe_id,),
        capabilities=(capability,),
        remaining_budget_ms=20,
        remaining_slots=1,
        window_required_probe_ids=(capability.probe_id,),
    )
    assert result.proposals == ()
    assert result.gaps[0].reason is EvidenceNeedGapReason.UNAVAILABLE


def test_maximum_length_registered_id_keeps_target_dedupe_key_bounded() -> None:
    capability = _capability(
        "p" + "a" * 119,
        observable_ids=("application.target_pressure",),
        target_handles=("source_bound_handle",),
    )
    result = resolve_evidence_needs(
        hypotheses=(),
        explicit_requested_probe_ids=(capability.probe_id,),
        capabilities=(capability,),
        remaining_budget_ms=20,
        remaining_slots=1,
    )
    assert len(result.proposals) == 1
    assert len(result.proposals[0].dedupe_key) <= 160
