"""Deterministic keyword/trait routing used as a measured fallback."""

from __future__ import annotations

import re

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
)


class KeywordBaselineDecisionProvider:
    """Route only to the probes already present in the typed request catalog."""

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="keyword-baseline",
            provider_version="1",
            role="fast_decision",
        )

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        terms = set(re.findall(r"[a-z0-9]+", request.symptom.casefold()))
        selected: list[ProbeProposal] = []
        total_cost = 0
        for capability in sorted(
            request.available_probes,
            key=lambda item: (
                int(item.probe_id in request.retryable_probe_ids),
                -int(item.common),
                -item.baseline_priority,
                item.probe_id,
            ),
        ):
            if capability.probe_id in request.completed_probe_ids:
                continue
            matched = bool(capability.keywords & terms) or bool(
                capability.target_traits & request.target_traits
            )
            if not capability.common and not matched:
                continue
            if capability.probe_id in request.fresh_probe_ids:
                continue
            if total_cost + capability.cost_ms > request.budget_ms:
                continue
            selected.append(
                ProbeProposal(
                    probe_id=capability.probe_id,
                    purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
                    priority=capability.baseline_priority,
                    estimated_cost_ms=capability.cost_ms,
                    resource_class=capability.resource_class,
                    dedupe_key=f"{capability.probe_id}:current",
                    permission_class=capability.permission_class,
                    safety_class=capability.safety_class,
                )
            )
            total_cost += capability.cost_ms
            if len(selected) == request.max_probes:
                break

        response = DecisionResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            proposals=tuple(selected),
            requires_reasoning=False,
        )
        return response.validate_against(request)
