"""Catalog-owned binding of advisory probe choices to typed measurement needs."""

from __future__ import annotations

from systemsense.decision.contracts import ProbeCapability
from systemsense.domain.probes import MeasurementNeed


def catalog_bound_measurement_need(capability: ProbeCapability) -> MeasurementNeed | None:
    """Return one admitted target, never a selector inferred from model text."""
    if len(capability.target_handles) != 1 or len(capability.observable_ids) != 1:
        return None
    return MeasurementNeed(
        capability_id=capability.probe_id,
        observable=capability.observable_ids[0],
        target_handle=capability.target_handles[0],
    )
