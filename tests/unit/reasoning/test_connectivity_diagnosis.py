"""Passive connectivity facts support stages, never a proven internet diagnosis."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

from systemsense.decision.contracts import ProbeCapability, ResourceClass
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.platform.windows.connectivity import ConnectivitySnapshot, connectivity_preview
from systemsense.reasoning.contracts import HypothesisStatus, ReasoningRequest, ReasoningStatus
from systemsense.reasoning.deterministic import DeterministicReasoningProvider

NOW = datetime.now(UTC)
SOURCE_ID = "src_" + "a" * 64


def _snapshot(**changes: object) -> dict[str, JsonValue]:
    base: dict[str, JsonValue] = {
        "source_id": SOURCE_ID,
        "captured_at": NOW.isoformat(),
        "wifi_observed_at": NOW.isoformat(),
        "wifi_status": "available",
        "wifi_interfaces": [],
        "omitted_wifi_count": 0,
        "addresses_observed_at": NOW.isoformat(),
        "addresses_status": "available",
        "adapters": [],
        "omitted_adapter_count": 0,
        "routes_observed_at": NOW.isoformat(),
        "routes_status": "available",
        "default_routes": [],
        "omitted_route_count": 0,
        "proxy_observed_at": NOW.isoformat(),
        "proxy_status": "available",
        "proxy": {"manual_enabled": False, "auto_configured": False},
        "wlan_events_observed_at": NOW.isoformat(),
        "wlan_events_status": "available",
        "recent_failures": [],
        "omitted_failure_count": 0,
        "status": "available",
        "limitations": [],
    }
    return {**base, **cast(dict[str, JsonValue], changes)}


def _context(
    snapshot: dict[str, JsonValue],
    *,
    observed_at: datetime = NOW,
    captured_at: datetime | None = None,
) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=observed_at,
        captured_at=captured_at or observed_at,
        probe_id="network",
        summary="Observed passive connectivity configuration",
        facts={"connectivity": snapshot},
        status=EvidenceContextStatus.OBSERVED,
    )


def _request(*contexts: EvidenceContext) -> ReasoningRequest:
    return ReasoningRequest(
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="connectivity_diagnosis",
        deadline_at=NOW + timedelta(minutes=1),
        objective="Wi-Fi says connected but the internet does not work",
        evidence_ids=tuple(item.evidence_id for item in contexts),
        evidence_context=contexts,
        available_probes=(
            ProbeCapability(
                probe_id="network.connectivity",
                description="Passive connectivity facts",
                cost_ms=1800,
                resource_class=ResourceClass.NETWORK,
            ),
        ),
        budget_ms=2000,
        max_probes=1,
    )


def test_disconnected_wlan_yields_association_stage_not_dns_or_final_cause() -> None:
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "disconnected",
                }
            ],
            addresses_status="unsupported",
            routes_status="unsupported",
        )
    )
    request = _request(context)

    response = DeterministicReasoningProvider().investigate(request)

    ids = {item.hypothesis_id for item in response.hypotheses}
    assert "h_wifi_association_incomplete" in ids
    assert "h_dns_configuration_missing" not in ids
    assert "h_ipv4_default_route_missing" not in ids
    assert "h_connectivity_coverage_gap" in ids
    assert response.status is ReasoningStatus.UNRESOLVED
    assert all(item.status is HypothesisStatus.UNRESOLVED for item in response.hypotheses)
    assert response.validate_against(request) == response


def test_source_observation_can_precede_parent_capture_without_losing_diagnosis() -> None:
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "disconnected",
                }
            ]
        ),
        captured_at=NOW + timedelta(milliseconds=23),
    )

    response = DeterministicReasoningProvider().investigate(_request(context))

    assert "h_wifi_association_incomplete" in {item.hypothesis_id for item in response.hypotheses}


def test_parent_capture_before_source_observation_is_rejected() -> None:
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "disconnected",
                }
            ]
        ),
        captured_at=NOW - timedelta(milliseconds=1),
    )

    response = DeterministicReasoningProvider().investigate(_request(context))

    assert "h_wifi_association_incomplete" not in {
        item.hypothesis_id for item in response.hypotheses
    }


def test_bounded_preview_does_not_turn_omitted_interfaces_into_absence_proof() -> None:
    full = ConnectivitySnapshot.model_validate(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": f"{{wifi-{index}}}",
                    "description": "Wireless adapter",
                    "association_state": "disconnected",
                }
                for index in range(3)
            ],
            proxy={"manual_enabled": True, "manual_server": "proxy.example:8080"},
        )
    )
    compact = connectivity_preview(full)
    response = DeterministicReasoningProvider().investigate(_request(_context(compact)))

    ids = {item.hypothesis_id for item in response.hypotheses}
    assert "h_wifi_association_incomplete" not in ids
    assert "h_wininet_proxy_configured" in ids


def test_connected_wlan_with_no_ipv4_and_route_reports_host_stage_gaps() -> None:
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "connected",
                }
            ],
            adapters=[
                {
                    "interface_index": 4,
                    "description": "Network adapter",
                    "ip_addresses": cast(list[str], []),
                    "default_gateways": cast(list[str], []),
                    "dns_servers": cast(list[str], []),
                }
            ],
        )
    )
    response = DeterministicReasoningProvider().investigate(_request(context))

    by_id = {item.hypothesis_id: item for item in response.hypotheses}
    assert "h_host_ipv4_address_missing" in by_id
    assert "h_ipv4_default_route_missing" in by_id
    assert "h_dns_configuration_missing" in by_id
    assert "h_wifi_association_incomplete" not in by_id
    assert "host" in by_id["h_host_ipv4_address_missing"].statement.casefold()
    assert "wifi adapter" not in by_id["h_host_ipv4_address_missing"].statement.casefold()
    assert by_id["h_ipv4_default_route_missing"].supporting_evidence_ids == (context.evidence_id,)


def test_exact_wifi_path_exposes_missing_ipv4_even_when_ethernet_has_it() -> None:
    wifi_guid = "{00000000-0000-0000-0000-000000000001}"
    ethernet_guid = "{00000000-0000-0000-0000-000000000002}"
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": wifi_guid,
                    "description": "Wi-Fi",
                    "association_state": "connected",
                }
            ],
            wifi_paths=[
                {
                    "interface_guid": wifi_guid,
                    "association_state": "connected",
                    "adapter_status": "matched",
                    "interface_index": 4,
                    "address_status": "absent",
                    "ipv4_default_route_status": "absent",
                    "failure_status": "none_recorded",
                    "failure_count": 0,
                }
            ],
            adapters=[
                {
                    "interface_index": 4,
                    "interface_guid": wifi_guid,
                    "description": "Wi-Fi",
                    "ip_addresses": cast(list[str], []),
                },
                {
                    "interface_index": 5,
                    "interface_guid": ethernet_guid,
                    "description": "Ethernet",
                    "ip_addresses": ["192.0.2.2"],
                },
            ],
            default_routes=[
                {
                    "destination": "0.0.0.0",
                    "prefix_length": 0,
                    "next_hop": "192.0.2.1",
                    "interface_index": 5,
                    "metric": 10,
                }
            ],
        )
    )

    response = DeterministicReasoningProvider().investigate(_request(context))
    by_id = {item.hypothesis_id: item for item in response.hypotheses}

    assert "h_wifi_ipv4_address_missing" in by_id
    assert by_id["h_wifi_ipv4_address_missing"].supporting_evidence_ids == (context.evidence_id,)
    assert "h_host_ipv4_address_missing" not in by_id
    assert by_id["h_wifi_ipv4_address_missing"].status is HypothesisStatus.UNRESOLVED
    assert "does not prove" in by_id["h_wifi_ipv4_address_missing"].statement


def test_incomplete_wifi_path_cannot_support_missing_ipv4_hypothesis() -> None:
    wifi_guid = "{00000000-0000-0000-0000-000000000001}"
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": wifi_guid,
                    "description": "Wi-Fi",
                    "association_state": "connected",
                }
            ],
            wifi_paths=[
                {
                    "interface_guid": wifi_guid,
                    "association_state": "connected",
                    "adapter_status": "incomplete",
                    "interface_index": None,
                    "address_status": "unknown",
                    "ipv4_default_route_status": "unknown",
                    "failure_status": "none_recorded",
                    "failure_count": 0,
                }
            ],
            addresses_status="partial",
            omitted_adapter_count=1,
            adapters=[
                {
                    "interface_index": 5,
                    "description": "Ethernet",
                    "ip_addresses": ["192.0.2.2"],
                }
            ],
        )
    )

    response = DeterministicReasoningProvider().investigate(_request(context))

    assert "h_wifi_ipv4_address_missing" not in {item.hypothesis_id for item in response.hypotheses}


def test_duplicate_adapter_index_cannot_support_wifi_specific_absence() -> None:
    wifi_guid = "{00000000-0000-0000-0000-000000000001}"
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": wifi_guid,
                    "description": "Wi-Fi",
                    "association_state": "connected",
                }
            ],
            wifi_paths=[
                {
                    "interface_guid": wifi_guid,
                    "association_state": "connected",
                    "adapter_status": "matched",
                    "interface_index": 4,
                    "address_status": "absent",
                    "ipv4_default_route_status": "unknown",
                    "failure_status": "none_recorded",
                    "failure_count": 0,
                }
            ],
            adapters=[
                {
                    "interface_index": 4,
                    "interface_guid": wifi_guid,
                    "description": "Wi-Fi",
                    "ip_addresses": cast(list[str], []),
                },
                {
                    "interface_index": 4,
                    "interface_guid": "{00000000-0000-0000-0000-000000000002}",
                    "description": "Other adapter",
                    "ip_addresses": ["192.0.2.2"],
                },
            ],
        )
    )

    response = DeterministicReasoningProvider().investigate(_request(context))

    assert "h_wifi_ipv4_address_missing" not in {item.hypothesis_id for item in response.hypotheses}


def test_inconsistent_wifi_path_address_status_cannot_support_absence() -> None:
    wifi_guid = "{00000000-0000-0000-0000-000000000001}"
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": wifi_guid,
                    "description": "Wi-Fi",
                    "association_state": "connected",
                }
            ],
            wifi_paths=[
                {
                    "interface_guid": wifi_guid,
                    "association_state": "connected",
                    "adapter_status": "matched",
                    "interface_index": 4,
                    "address_status": "present",
                    "ipv4_default_route_status": "unknown",
                    "failure_status": "none_recorded",
                    "failure_count": 0,
                }
            ],
            adapters=[
                {
                    "interface_index": 4,
                    "interface_guid": wifi_guid,
                    "description": "Wi-Fi",
                    "ip_addresses": cast(list[str], []),
                }
            ],
        )
    )

    response = DeterministicReasoningProvider().investigate(_request(context))

    assert "h_wifi_ipv4_address_missing" not in {item.hypothesis_id for item in response.hypotheses}


def test_incomplete_adapter_address_lists_cannot_prove_missing_ip_or_dns() -> None:
    context = _context(
        _snapshot(
            adapters=[
                {
                    "interface_index": 4,
                    "description": "Network adapter",
                    "ip_addresses": cast(list[str], []),
                    "ip_addresses_complete": False,
                    "dns_servers": cast(list[str], []),
                    "dns_servers_complete": False,
                }
            ]
        )
    )
    response = DeterministicReasoningProvider().investigate(_request(context))
    ids = {item.hypothesis_id for item in response.hypotheses}
    assert "h_host_ipv4_address_missing" not in ids
    assert "h_dns_configuration_missing" not in ids


def test_proxy_dns_and_external_remain_competing_untested_branches() -> None:
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "connected",
                }
            ],
            adapters=[
                {
                    "interface_index": 4,
                    "description": "Network adapter",
                    "ip_addresses": ["192.0.2.2"],
                    "default_gateways": ["192.0.2.1"],
                    "dns_servers": ["192.0.2.53"],
                }
            ],
            default_routes=[
                {
                    "destination": "0.0.0.0",
                    "prefix_length": 0,
                    "next_hop": "192.0.2.1",
                    "interface_index": 4,
                    "metric": 10,
                }
            ],
            proxy={"manual_enabled": True, "manual_server": "proxy.example:8080"},
        )
    )
    response = DeterministicReasoningProvider().investigate(_request(context))

    by_id = {item.hypothesis_id: item for item in response.hypotheses}
    assert "h_wininet_proxy_configured" in by_id
    assert "h_dns_resolution_unverified" in by_id
    assert "h_external_path_unverified" in by_id
    assert all(item.status is HypothesisStatus.UNRESOLVED for item in by_id.values())
    assert "WinHTTP" in by_id["h_wininet_proxy_configured"].statement
    assert "proxy.example" not in str(response)
    assert "h_ipv4_default_route_missing" not in by_id


def test_past_wlan_failure_is_history_not_current_auth_failure() -> None:
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "connected",
                }
            ],
            recent_failures=[
                {
                    "source_id": SOURCE_ID,
                    "observed_at": (NOW - timedelta(minutes=30)).isoformat(),
                    "event_id": 8002,
                    "interface_guid": "{wifi-a}",
                    "reason_code": 123,
                }
            ],
        )
    )
    response = DeterministicReasoningProvider().investigate(_request(context))
    by_id = {item.hypothesis_id: item for item in response.hypotheses}

    assert "h_recent_wlan_failure_recorded" in by_id
    assert "h_wifi_association_incomplete" not in by_id
    assert "h_wifi_authentication_stage" not in by_id
    assert "123" in by_id["h_recent_wlan_failure_recorded"].statement
    assert "current" not in by_id["h_recent_wlan_failure_recorded"].statement.casefold()


def test_authenticating_state_is_a_stage_not_an_authentication_failure() -> None:
    context = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "authenticating",
                }
            ]
        )
    )
    response = DeterministicReasoningProvider().investigate(_request(context))
    by_id = {item.hypothesis_id: item for item in response.hypotheses}

    assert "h_wifi_authentication_stage" in by_id
    assert (
        "not a confirmed authentication failure" in by_id["h_wifi_authentication_stage"].statement
    )
    assert by_id["h_wifi_authentication_stage"].status is HypothesisStatus.UNRESOLVED


def test_stale_or_partial_data_never_yields_negative_absence_claims() -> None:
    old = NOW - timedelta(minutes=30)
    stale = _context(_snapshot(), observed_at=old)
    partial = _context(
        _snapshot(
            wifi_status="partial",
            omitted_wifi_count=1,
            addresses_status="partial",
            omitted_adapter_count=1,
            routes_status="partial",
            omitted_route_count=1,
        )
    )
    stale_response = DeterministicReasoningProvider().investigate(_request(stale))
    partial_response = DeterministicReasoningProvider().investigate(_request(partial))

    forbidden = {
        "h_host_ipv4_address_missing",
        "h_ipv4_default_route_missing",
        "h_dns_configuration_missing",
        "h_wifi_association_incomplete",
    }
    assert not forbidden.intersection(item.hypothesis_id for item in stale_response.hypotheses)
    assert not forbidden.intersection(item.hypothesis_id for item in partial_response.hypotheses)
    assert "h_connectivity_coverage_gap" in {
        item.hypothesis_id for item in partial_response.hypotheses
    }


def test_stale_component_is_ignored_even_when_envelope_is_fresh() -> None:
    context = _context(
        _snapshot(
            routes_observed_at=(NOW - timedelta(minutes=30)).isoformat(),
            addresses_observed_at=(NOW - timedelta(minutes=30)).isoformat(),
            adapters=[
                {
                    "interface_index": 4,
                    "description": "Adapter",
                    "ip_addresses": cast(list[str], []),
                    "dns_servers": cast(list[str], []),
                }
            ],
        )
    )
    response = DeterministicReasoningProvider().investigate(_request(context))
    ids = {item.hypothesis_id for item in response.hypotheses}

    assert "h_ipv4_default_route_missing" not in ids
    assert "h_host_ipv4_address_missing" not in ids
    assert "h_dns_configuration_missing" not in ids
    assert any("Coverage:" in note for note in response.context_notes)
    assert any(NOW.isoformat() in note for note in response.context_notes)


def test_latest_snapshot_supersedes_older_opposite_state() -> None:
    old_at = NOW - timedelta(minutes=2)
    old = _context(
        _snapshot(
            captured_at=old_at.isoformat(),
            wifi_observed_at=old_at.isoformat(),
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "disconnected",
                }
            ],
        ),
        observed_at=old_at,
    )
    current = _context(
        _snapshot(
            wifi_interfaces=[
                {
                    "interface_guid": "{wifi-a}",
                    "description": "Wireless adapter",
                    "association_state": "connected",
                }
            ]
        )
    )
    response = DeterministicReasoningProvider().investigate(_request(old, current))

    assert "h_wifi_association_incomplete" not in {
        item.hypothesis_id for item in response.hypotheses
    }
    assert all(old.evidence_id not in item.supporting_evidence_ids for item in response.hypotheses)


def test_malformed_or_omitted_connectivity_payload_does_not_infer_fault() -> None:
    malformed = _context({"source_id": SOURCE_ID})
    missing = malformed.model_copy(update={"evidence_id": EvidenceId.new(), "facts": {}})
    response = DeterministicReasoningProvider().investigate(_request(malformed, missing))

    assert not any(item.hypothesis_id.startswith("h_wifi") for item in response.hypotheses)
    assert not any(item.hypothesis_id.startswith("h_dns") for item in response.hypotheses)
    assert response.status is ReasoningStatus.UNRESOLVED
