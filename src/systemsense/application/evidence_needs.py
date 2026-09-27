"""Resolve typed evidence requests into bounded, advisory read-only proposals.

The caller supplies case-local capabilities and source-bound measurement needs.
This module never interprets symptom or hypothesis prose as a selector. The
investigator must still admit every proposal through its own eligibility gate.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping, Sequence
from enum import StrEnum

from systemsense.application.investigation_state import MeasurementGap
from systemsense.decision.contracts import (
    DiagnosticPurpose,
    PermissionClass,
    ProbeCapability,
    ProbeProposal,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.probes import MeasurementNeed, SafetyClass
from systemsense.reasoning.contracts import Hypothesis


class EvidenceNeedGapReason(StrEnum):
    UNREGISTERED = "unregistered"
    ALREADY_SATISFIED = "already_satisfied"
    PENDING = "pending"
    COMPLETED_NOT_RETRYABLE = "completed_not_retryable"
    UNAVAILABLE = "unavailable"
    UNAUTHORIZED = "unauthorized"
    SLOTS_EXHAUSTED = "slots_exhausted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    MISSING_TARGET = "missing_target"
    AMBIGUOUS_TARGET = "ambiguous_target"
    MISSING_OBSERVABLE = "missing_observable"
    AMBIGUOUS_OBSERVABLE = "ambiguous_observable"
    MISSING_WINDOW = "missing_window"
    RECORDED_GAP = "recorded_gap"


class EvidenceNeedGap(FrozenModel):
    probe_id: str
    reason: EvidenceNeedGapReason


class EvidenceNeedResolution(FrozenModel):
    proposals: tuple[ProbeProposal, ...]
    gaps: tuple[EvidenceNeedGap, ...]


def _measurement_need(
    capability: ProbeCapability,
    bound_need: MeasurementNeed | None,
    *,
    target_required: bool,
    window_required: bool,
) -> tuple[MeasurementNeed | None, EvidenceNeedGapReason | None]:
    if not capability.target_handles:
        if bound_need is not None:
            return None, EvidenceNeedGapReason.UNAUTHORIZED
        if target_required:
            return None, EvidenceNeedGapReason.MISSING_TARGET
        if window_required:
            return None, EvidenceNeedGapReason.UNAVAILABLE
        return None, None

    if window_required and not capability.supports_window:
        return None, EvidenceNeedGapReason.UNAVAILABLE

    if bound_need is not None:
        if (
            bound_need.capability_id != capability.probe_id
            or bound_need.target_handle not in capability.target_handles
            or bound_need.observable not in capability.observable_ids
            or (bound_need.window is not None and not capability.supports_window)
        ):
            return None, EvidenceNeedGapReason.UNAUTHORIZED
        need = bound_need
    else:
        if len(capability.target_handles) != 1:
            return None, EvidenceNeedGapReason.AMBIGUOUS_TARGET
        if not capability.observable_ids:
            return None, EvidenceNeedGapReason.MISSING_OBSERVABLE
        if len(capability.observable_ids) != 1:
            return None, EvidenceNeedGapReason.AMBIGUOUS_OBSERVABLE
        need = MeasurementNeed(
            capability_id=capability.probe_id,
            observable=capability.observable_ids[0],
            target_handle=capability.target_handles[0],
        )
    if window_required and need.window is None:
        return None, EvidenceNeedGapReason.MISSING_WINDOW
    return need, None


def _dedupe_key(probe_id: str, need: MeasurementNeed | None) -> str:
    if need is None:
        return f"evidence-need:{probe_id}"
    payload = json.dumps(need.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return f"evidence-need:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def resolve_evidence_needs(
    *,
    hypotheses: Sequence[Hypothesis],
    explicit_requested_probe_ids: Sequence[str],
    capabilities: Sequence[ProbeCapability],
    remaining_budget_ms: int,
    remaining_slots: int,
    completed_probe_ids: Collection[str] = (),
    satisfied_probe_ids: Collection[str] = (),
    pending_probe_ids: Collection[str] = (),
    retryable_probe_ids: Collection[str] = (),
    unavailable_probe_ids: Collection[str] = (),
    unauthorized_probe_ids: Collection[str] = (),
    recorded_measurement_gaps: Sequence[MeasurementGap] = (),
    bound_needs: Mapping[str, MeasurementNeed] | None = None,
    target_required_probe_ids: Collection[str] = (),
    window_required_probe_ids: Collection[str] = (),
) -> EvidenceNeedResolution:
    """Resolve only explicit IDs and typed hypothesis IDs against local registrations.

    ``bound_needs`` must come from a trusted case-local target/window binding.
    This function checks it against the supplied capability, then returns
    proposals for the investigator's final registry/permission/budget admission.
    """
    if remaining_budget_ms < 0 or remaining_slots < 0:
        raise ValueError("remaining budget and slots must be nonnegative")
    known = {item.probe_id: item for item in capabilities}
    if len(known) != len(capabilities):
        raise ValueError("capabilities must have unique probe IDs")

    requested: dict[str, DiagnosticPurpose] = {}
    for probe_id in explicit_requested_probe_ids:
        requested.setdefault(probe_id, DiagnosticPurpose.CHECK_COVERAGE)
    for hypothesis in hypotheses:
        for probe_id in hypothesis.distinguishing_probe_ids:
            requested.setdefault(probe_id, DiagnosticPurpose.DISTINGUISH_HYPOTHESES)
        for fact in hypothesis.expected_facts:
            requested.setdefault(fact.probe_id, DiagnosticPurpose.DISTINGUISH_HYPOTHESES)

    completed = set(completed_probe_ids)
    satisfied = set(satisfied_probe_ids)
    pending = set(pending_probe_ids)
    retryable = set(retryable_probe_ids)
    unavailable = set(unavailable_probe_ids)
    unauthorized = set(unauthorized_probe_ids)
    target_required = set(target_required_probe_ids)
    window_required = set(window_required_probe_ids)
    needs = bound_needs or {}
    recorded = tuple(item.need for item in recorded_measurement_gaps)
    proposals: list[ProbeProposal] = []
    gaps: list[EvidenceNeedGap] = []

    for probe_id, purpose in requested.items():
        capability = known.get(probe_id)
        reason: EvidenceNeedGapReason | None = None
        if capability is None:
            reason = EvidenceNeedGapReason.UNREGISTERED
        elif probe_id in satisfied:
            reason = EvidenceNeedGapReason.ALREADY_SATISFIED
        elif probe_id in pending:
            reason = EvidenceNeedGapReason.PENDING
        elif probe_id in completed and probe_id not in retryable:
            reason = EvidenceNeedGapReason.COMPLETED_NOT_RETRYABLE
        elif probe_id in unavailable:
            reason = EvidenceNeedGapReason.UNAVAILABLE
        elif (
            probe_id in unauthorized
            or capability.permission_class is not PermissionClass.READ_ONLY
            or capability.safety_class not in {SafetyClass.R0, SafetyClass.R1}
            or capability.target_state_effect != "none"
            or capability.outbound_network
        ):
            reason = EvidenceNeedGapReason.UNAUTHORIZED
        else:
            need, reason = _measurement_need(
                capability,
                needs.get(probe_id),
                target_required=probe_id in target_required,
                window_required=probe_id in window_required,
            )
            if reason is None and need is not None and need in recorded:
                reason = EvidenceNeedGapReason.RECORDED_GAP
            if reason is None and len(proposals) >= remaining_slots:
                reason = EvidenceNeedGapReason.SLOTS_EXHAUSTED
            if reason is None and capability.cost_ms > remaining_budget_ms:
                reason = EvidenceNeedGapReason.BUDGET_EXHAUSTED
            if reason is None:
                proposals.append(
                    ProbeProposal(
                        schema_version=2 if need is not None else 1,
                        probe_id=probe_id,
                        purpose=(
                            DiagnosticPurpose.REFRESH_EVIDENCE if probe_id in completed else purpose
                        ),
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key=_dedupe_key(probe_id, need),
                        permission_class=capability.permission_class,
                        safety_class=capability.safety_class,
                        measurement_need=need,
                    )
                )
                remaining_budget_ms -= capability.cost_ms
        if reason is not None:
            gaps.append(EvidenceNeedGap(probe_id=probe_id, reason=reason))
    return EvidenceNeedResolution(proposals=tuple(proposals), gaps=tuple(gaps))
