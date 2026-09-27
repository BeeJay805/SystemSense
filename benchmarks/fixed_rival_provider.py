"""Fixed, label-blind advisory rivals for frozen toy episode evaluation.

This provider only inspects the registered capability IDs in its request. It
does not import evaluator worlds, read case IDs, or declare a supported cause.
"""

from __future__ import annotations

from systemsense.decision.contracts import ProviderIdentity
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)

_NETWORK_RIVALS = (
    (
        "h_browser_proxy_path",
        "The configured proxy path may affect this browser request.",
        ("browser.proxy_settings", "browser.route_attempt", "browser.direct_control"),
    ),
    (
        "h_browser_name_resolution",
        "Name resolution on the affected route may contribute to the browser failure.",
        ("browser.route_attempt", "browser.direct_control", "browser.external_control"),
    ),
)
_APPLICATION_RIVALS = (
    (
        "h_document_storage_path",
        "Storage delay may contribute to the document opening time.",
        ("application.task_timing", "application.storage_latency", "application.external_control"),
    ),
    (
        "h_document_renderer_path",
        "The active renderer may contribute to the document opening time.",
        ("application.task_timing", "application.renderer_mode", "application.external_control"),
    ),
)


class FixedRivalReasoningProvider:
    """Emit the same two unresolved alternatives for every case in a menu family."""

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="fixed-rival-advisory",
            provider_version="1",
            role="reasoning",
        )

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        registered = {item.probe_id for item in request.available_probes}
        network_ids = {probe_id for _, _, ids in _NETWORK_RIVALS for probe_id in ids}
        application_ids = {probe_id for _, _, ids in _APPLICATION_RIVALS for probe_id in ids}
        if network_ids <= registered and not application_ids <= registered:
            rivals = _NETWORK_RIVALS
        elif application_ids <= registered and not network_ids <= registered:
            rivals = _APPLICATION_RIVALS
        else:
            rivals = ()
        hypotheses = tuple(
            Hypothesis(
                hypothesis_id=hypothesis_id,
                statement=statement,
                status=HypothesisStatus.UNRESOLVED,
                distinguishing_probe_ids=probe_ids,
            )
            for hypothesis_id, statement, probe_ids in rivals
        )
        response = ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=(
                ReasoningStatus.UNRESOLVED
                if hypotheses
                else ReasoningStatus.INSUFFICIENT_OBSERVABILITY
            ),
            summary=(
                "Two registered paths remain advisory; request measurements before any cause claim."
                if hypotheses
                else "The registered menu lacks the fixed rival measurements."
            ),
            hypotheses=hypotheses,
        )
        return response.validate_against(request)
