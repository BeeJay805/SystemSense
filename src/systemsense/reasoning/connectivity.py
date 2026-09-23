"""Conservative stage assessment of the passive Windows connectivity snapshot.

These rules describe configuration and WLAN state. They do not run active tests,
attribute adapter IP data to a WLAN GUID, or establish a root cause.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta

from pydantic import ValidationError

from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.platform.windows.connectivity import ConnectivitySnapshot
from systemsense.platform.windows.deep_collectors import ComponentStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus, ReasoningRequest

_MAX_AGE = timedelta(minutes=5)
_FUTURE_SKEW = timedelta(seconds=5)
_NON_CONNECTED_STATES = frozenset(
    {"not_ready", "disconnected", "disconnecting", "associating", "discovering", "authenticating"}
)


def assess_connectivity(
    request: ReasoningRequest, *, now: datetime
) -> tuple[tuple[Hypothesis, ...], tuple[str, ...]]:
    """Return only grounded, unresolved stage hypotheses from the latest fresh snapshot."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    candidates: list[tuple[EvidenceContext, ConnectivitySnapshot]] = []
    notes: list[str] = []
    for context in request.evidence_context:
        if context.probe_id not in {"network", "network.connectivity"}:
            continue
        raw = context.facts.get("connectivity")
        if not isinstance(raw, dict):
            continue
        if context.status not in {EvidenceContextStatus.OBSERVED, EvidenceContextStatus.PARTIAL}:
            continue
        if any(
            marker in limitation.casefold()
            for limitation in context.limitations
            for marker in (
                "historical observation",
                "outside the incident window",
                "source_clock_after_capture",
            )
        ):
            notes.append("A network snapshot is historical or outside the incident window.")
            continue
        try:
            snapshot = ConnectivitySnapshot.model_validate(raw)
        except ValidationError:
            notes.append(
                "A compact network snapshot was invalid or incomplete; no stage was inferred."
            )
            continue
        if (
            snapshot.captured_at != context.observed_at
            or context.captured_at < context.observed_at
            or not _fresh(context.captured_at, now)
            or not _fresh(context.observed_at, now)
        ):
            notes.append("A network snapshot has mismatched or stale source timing.")
            continue
        candidates.append((context, snapshot))
    if not candidates:
        return (), tuple(dict.fromkeys(notes))[:4]

    context, snapshot = max(candidates, key=lambda item: item[0].observed_at)
    evidence_ids = (context.evidence_id,)
    hypotheses: list[Hypothesis] = []

    def add(hypothesis_id: str, statement: str) -> None:
        hypotheses.append(
            Hypothesis(
                hypothesis_id=hypothesis_id,
                statement=statement,
                status=HypothesisStatus.UNRESOLVED,
                supporting_evidence_ids=evidence_ids,
            )
        )

    wifi_fresh = _component_fresh(snapshot.wifi_observed_at, snapshot.captured_at, now)
    address_fresh = _component_fresh(snapshot.addresses_observed_at, snapshot.captured_at, now)
    route_fresh = _component_fresh(snapshot.routes_observed_at, snapshot.captured_at, now)
    proxy_fresh = _component_fresh(snapshot.proxy_observed_at, snapshot.captured_at, now)
    events_fresh = _component_fresh(snapshot.wlan_events_observed_at, snapshot.captured_at, now)

    if any(
        status is not ComponentStatus.AVAILABLE
        for status in (
            snapshot.wifi_status,
            snapshot.addresses_status,
            snapshot.routes_status,
            snapshot.proxy_status,
            snapshot.wlan_events_status,
        )
    ) or not all((wifi_fresh, address_fresh, route_fresh, proxy_fresh, events_fresh)):
        add(
            "h_connectivity_coverage_gap",
            "At least one connectivity source was partial, unavailable, or stale. Its "
            "missing facts cannot be treated as a normal observation.",
        )

    if wifi_fresh and snapshot.wifi_status in {
        ComponentStatus.AVAILABLE,
        ComponentStatus.PARTIAL,
    }:
        if any(item.association_state == "authenticating" for item in snapshot.wifi_interfaces):
            add(
                "h_wifi_authentication_stage",
                "A WLAN interface was in the authenticating stage when observed; this is not "
                "a confirmed authentication failure or an identified cause.",
            )
        if (
            snapshot.wifi_status is ComponentStatus.AVAILABLE
            and snapshot.omitted_wifi_count == 0
            and snapshot.wifi_interfaces
            and all(
                item.association_state in _NON_CONNECTED_STATES for item in snapshot.wifi_interfaces
            )
        ):
            add(
                "h_wifi_association_incomplete",
                "No observed WLAN interface was connected at the WLAN source time. This "
                "does not exclude another adapter or prove the symptom's cause.",
            )

    if events_fresh and snapshot.wlan_events_status in {
        ComponentStatus.AVAILABLE,
        ComponentStatus.PARTIAL,
    }:
        valid_failures = [
            event
            for event in snapshot.recent_failures
            if event.event_id in {8002, 11006}
            and snapshot.wlan_events_observed_at - timedelta(hours=1)
            <= event.observed_at
            <= snapshot.wlan_events_observed_at
        ]
        if valid_failures:
            latest = max(valid_failures, key=lambda event: event.observed_at)
            code = (
                f" The recorded reason code was {latest.reason_code}, without interpretation."
                if latest.reason_code is not None
                else " No reason code was recorded."
            )
            add(
                "h_recent_wlan_failure_recorded",
                f"A WLAN failure event was recorded at {latest.observed_at.isoformat()} "
                "within the preceding hour; a later successful association may supersede it."
                + code,
            )

    if address_fresh and snapshot.addresses_status in {
        ComponentStatus.AVAILABLE,
        ComponentStatus.PARTIAL,
    }:
        if (
            snapshot.addresses_status is ComponentStatus.AVAILABLE
            and snapshot.omitted_adapter_count == 0
            and snapshot.adapters
            and all(adapter.ip_addresses_complete for adapter in snapshot.adapters)
            and not any(
                _usable_ipv4(address)
                for adapter in snapshot.adapters
                for address in adapter.ip_addresses
            )
        ):
            add(
                "h_host_ipv4_address_missing",
                "No usable host IPv4 address was observed on the reported IP-enabled adapters. "
                "The snapshot does not map these adapter rows to a specific WLAN interface.",
            )
        if (
            snapshot.addresses_status is ComponentStatus.AVAILABLE
            and snapshot.omitted_adapter_count == 0
            and snapshot.adapters
            and all(adapter.dns_servers_complete for adapter in snapshot.adapters)
            and not any(adapter.dns_servers for adapter in snapshot.adapters)
        ):
            add(
                "h_dns_configuration_missing",
                "No DNS server was configured on the reported IP-enabled adapters. This is "
                "configuration evidence, not a DNS-resolution test or a proven symptom cause.",
            )
        elif any(adapter.dns_servers for adapter in snapshot.adapters):
            add(
                "h_dns_resolution_unverified",
                "A DNS server is configured on at least one reported adapter, but name "
                "resolution and server reachability have not been tested.",
            )

    if route_fresh and snapshot.routes_status in {
        ComponentStatus.AVAILABLE,
        ComponentStatus.PARTIAL,
    }:
        if (
            snapshot.routes_status is ComponentStatus.AVAILABLE
            and snapshot.omitted_route_count == 0
            and not snapshot.default_routes
        ):
            add(
                "h_ipv4_default_route_missing",
                "No IPv4 default route was observed in the host route table. IPv6 routing, "
                "gateway reachability, and the affected application's path remain untested.",
            )
        elif snapshot.default_routes:
            add(
                "h_external_path_unverified",
                "An IPv4 default route is configured, but its gateway, upstream path, and "
                "external destination reachability have not been tested.",
            )

    if (
        proxy_fresh
        and snapshot.proxy_status in {ComponentStatus.AVAILABLE, ComponentStatus.PARTIAL}
        and snapshot.proxy is not None
        and (snapshot.proxy.manual_enabled is True or snapshot.proxy.auto_configured is True)
    ):
        add(
            "h_wininet_proxy_configured",
            "A WinINet proxy mode was configured for the user. Whether the affected application "
            "uses it, whether it works, and any WinHTTP setting remain untested.",
        )

    notes.extend(
        (
            "Snapshot source times (UTC): WLAN "
            f"{snapshot.wifi_observed_at.isoformat()}, IP/DNS "
            f"{snapshot.addresses_observed_at.isoformat()}, route "
            f"{snapshot.routes_observed_at.isoformat()}, proxy "
            f"{snapshot.proxy_observed_at.isoformat()}, WLAN events "
            f"{snapshot.wlan_events_observed_at.isoformat()}.",
            "Coverage: WLAN "
            f"{snapshot.wifi_status.value}, IP/DNS {snapshot.addresses_status.value}, "
            f"IPv4 routes {snapshot.routes_status.value}, WinINet proxy "
            f"{snapshot.proxy_status.value}, WLAN events {snapshot.wlan_events_status.value}.",
            "Passive configuration does not test DNS resolution, gateway reachability, "
            "upstream connectivity, or affected-application proxy behavior.",
        )
    )
    return tuple(hypotheses), tuple(dict.fromkeys(notes))[:8]


def _fresh(observed_at: datetime, now: datetime) -> bool:
    return -_FUTURE_SKEW <= now - observed_at <= _MAX_AGE


def _component_fresh(observed_at: datetime, captured_at: datetime, now: datetime) -> bool:
    return observed_at <= captured_at and _fresh(observed_at, now)


def _usable_ipv4(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return isinstance(parsed, ipaddress.IPv4Address) and not (
        parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified
    )
