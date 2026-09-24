from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID

from benchmarks.vm_pdf_pilot_gate import assess_pdf_pilot_gate
from benchmarks.vm_qualification_readiness import QualificationReadiness

VM = UUID("82bab24b-e3b2-4b17-9d55-8c9198c53766")
SNAPSHOT = UUID("b32cacf4-2b77-4b8a-be02-b59b1dcd64ff")
NOW = datetime(2026, 9, 24, 6, 50, tzinfo=UTC)


def _readiness() -> QualificationReadiness:
    return QualificationReadiness(
        1,
        "read_only_host_readiness",
        NOW,
        VM,
        "SystemSense-Investigator-Qualification-20260922",
        "poweroff",
        1,
        SNAPSHOT,
        None,
        ((1, "off"),),
        False,
        (
            "clean_reset_unverified",
            "guest_additions_unverified",
            "guest_login_unverified",
            "guest_not_running",
            "independent_oracle_unverified",
        ),
    )


def test_matching_powered_off_clone_exposes_only_qualification_step() -> None:
    report = assess_pdf_pilot_gate(_readiness(), VM, SNAPSHOT, now=NOW)
    assert report.classification == "pdf_pilot_host_gate_only"
    assert report.host_ready_for_guest_qualification
    assert report.next_step == "authenticate_guest_control"
    assert not report.can_begin_episode
    assert report.blockers == (
        "clean_reset_unverified",
        "guest_login_unverified",
        "independent_oracle_unverified",
    )


def test_stale_host_readback_cannot_authorize_guest_qualification() -> None:
    report = assess_pdf_pilot_gate(_readiness(), VM, SNAPSHOT, now=NOW + timedelta(minutes=6))
    assert not report.host_ready_for_guest_qualification
    assert report.next_step == "refresh_host_readback"
    assert "host_readback_stale" in report.blockers


def test_snapshot_or_network_drift_blocks_qualification() -> None:
    readiness = replace(
        _readiness(),
        current_snapshot_uuid=UUID("5ea81cfc-2fa3-4935-867e-b2041c3cddf3"),
        network_cable_states=((1, "on"),),
    )
    report = assess_pdf_pilot_gate(readiness, VM, SNAPSHOT, now=NOW)
    assert not report.host_ready_for_guest_qualification
    assert report.next_step == "resolve_host_configuration"
    assert "expected_snapshot_not_current" in report.blockers
    assert "network_adapter_connected" in report.blockers


def test_missing_guest_proofs_cannot_be_overridden_by_readiness_claim() -> None:
    readiness = replace(_readiness(), can_begin_episode=True, blockers=())  # type: ignore[arg-type]
    report = assess_pdf_pilot_gate(readiness, VM, SNAPSHOT, now=NOW)
    assert not report.can_begin_episode
    assert "host_readiness_claim_invalid" in report.blockers
    assert "guest_login_unverified" in report.blockers
    assert "clean_reset_unverified" in report.blockers
    assert "independent_oracle_unverified" in report.blockers


def test_future_readback_and_unrecognized_host_blocker_fail_closed() -> None:
    readiness = replace(
        _readiness(),
        observed_at=NOW + timedelta(seconds=1),
        blockers=("unexpected_host_condition",),
    )
    report = assess_pdf_pilot_gate(readiness, VM, SNAPSHOT, now=NOW)
    assert not report.host_ready_for_guest_qualification
    assert report.next_step == "refresh_host_readback"
    assert "host_readback_time_invalid" in report.blockers
    assert "unexpected_host_condition" in report.blockers
