"""Read-only admission gate before a controlled PDF pilot is attempted.

This evaluates host metadata and names the next qualification step. It does not
authenticate a guest, restore a snapshot, operate a viewer, or authorize an episode.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from uuid import UUID

from benchmarks.vm_qualification_readiness import QualificationReadiness

_MAX_HOST_AGE = timedelta(minutes=5)
_GUEST_GATES = (
    "clean_reset_unverified",
    "guest_login_unverified",
    "independent_oracle_unverified",
)
_DEFERRED_READINESS = set(_GUEST_GATES) | {
    "guest_additions_unverified",
    "guest_additions_version_mismatch",
    "guest_not_running",
}


@dataclass(frozen=True, slots=True)
class PdfPilotGate:
    schema_version: Literal[1]
    classification: Literal["pdf_pilot_host_gate_only"]
    vm_uuid: UUID
    expected_snapshot_uuid: UUID
    host_ready_for_guest_qualification: bool
    can_begin_episode: Literal[False]
    next_step: Literal[
        "refresh_host_readback",
        "resolve_host_configuration",
        "authenticate_guest_control",
    ]
    blockers: tuple[str, ...]


def assess_pdf_pilot_gate(
    readiness: QualificationReadiness,
    expected_vm_uuid: UUID,
    expected_snapshot_uuid: UUID,
    *,
    now: datetime,
) -> PdfPilotGate:
    """Bind a fresh, isolated, powered-off clone to its intended snapshot.

    A matching host readback permits only an attempt to qualify guest control.
    Even a caller-mutated readiness claim cannot stand in for authenticated
    login, full-state reset readback, or an independent PDF visual oracle.
    """

    blockers: set[str] = set(_GUEST_GATES)
    blockers.update(set(readiness.blockers) - _DEFERRED_READINESS)
    if (
        readiness.schema_version != 1
        or readiness.classification != "read_only_host_readiness"
        or readiness.can_begin_episode is not False
    ):
        blockers.add("host_readiness_claim_invalid")
    if (
        now.utcoffset() != timedelta(0)
        or readiness.observed_at.utcoffset() != timedelta(0)
        or readiness.observed_at > now
    ):
        blockers.add("host_readback_time_invalid")
    elif now - readiness.observed_at > _MAX_HOST_AGE:
        blockers.add("host_readback_stale")
    if readiness.vm_uuid != expected_vm_uuid:
        blockers.add("vm_identity_mismatch")
    if readiness.snapshot_count < 1 or readiness.current_snapshot_uuid != expected_snapshot_uuid:
        blockers.add("expected_snapshot_not_current")
    if readiness.state != "poweroff":
        blockers.add("vm_not_powered_off")
    if not readiness.network_cable_states or len(
        {i for i, _ in readiness.network_cable_states}
    ) != len(readiness.network_cable_states):
        blockers.add("network_state_unverified")
    if any(state != "off" for _, state in readiness.network_cable_states):
        blockers.add("network_adapter_connected")

    host_blockers = blockers - set(_GUEST_GATES)
    host_ready = not host_blockers
    if "host_readback_stale" in blockers or "host_readback_time_invalid" in blockers:
        next_step = "refresh_host_readback"
    elif host_blockers:
        next_step = "resolve_host_configuration"
    else:
        next_step = "authenticate_guest_control"
    return PdfPilotGate(
        schema_version=1,
        classification="pdf_pilot_host_gate_only",
        vm_uuid=expected_vm_uuid,
        expected_snapshot_uuid=expected_snapshot_uuid,
        host_ready_for_guest_qualification=host_ready,
        can_begin_episode=False,
        next_step=next_step,
        blockers=tuple(sorted(blockers)),
    )
