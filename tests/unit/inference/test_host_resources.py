"""Resource admission never evicts another workload or hides degraded operation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from systemsense.inference.host_resources import (
    HostAdmissionPolicy,
    HostResourceAdmission,
    HostResourceSnapshot,
    LocalBrainFootprint,
)

GIB = 1024**3
NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


def _snapshot(
    *,
    ram: int = 32,
    vram: int | None = 24,
    observed_at: datetime = NOW,
    active_sessions: int = 0,
    gpu_device_index: int | None = 0,
) -> HostResourceSnapshot:
    return HostResourceSnapshot(
        observed_at=observed_at,
        available_ram_bytes=ram * GIB,
        free_vram_bytes=None if vram is None else vram * GIB,
        gpu_device_index=gpu_device_index,
        active_sessions=active_sessions,
        active_fast_calls=0,
        active_deep_calls=0,
    )


def _fast() -> LocalBrainFootprint:
    return LocalBrainFootprint(
        role="fast",
        model_id="laya-local",
        device="cpu",
        resident=False,
        cold_ram_bytes=5 * GIB,
        cold_vram_bytes=0,
        session_ram_bytes=GIB,
        session_vram_bytes=0,
        footprint_origin="conservative_config",
    )


def _deep() -> LocalBrainFootprint:
    return LocalBrainFootprint(
        role="deep",
        model_id="qwen-local",
        device="cuda",
        gpu_device_index=0,
        resident=False,
        cold_ram_bytes=2 * GIB,
        cold_vram_bytes=16 * GIB,
        session_ram_bytes=GIB,
        session_vram_bytes=2 * GIB,
        footprint_origin="conservative_config",
    )


def test_dual_local_admits_with_explicit_headroom_and_reservation() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy())
    outcome = admission.try_admit(_snapshot(), fast=_fast(), deep=_deep(), now=NOW)

    assert outcome.mode == "dual_local"
    assert outcome.admitted_roles == ("fast", "deep")
    assert outcome.reservation_id is not None
    assert outcome.required_ram_bytes == 9 * GIB
    assert outcome.required_vram_bytes == 18 * GIB
    assert outcome.reasons == ()
    assert admission.active_reservations == 1
    admission.release(outcome.reservation_id)
    assert admission.active_reservations == 0


def test_combined_pressure_degrades_to_deep_only_with_visible_reason() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy())
    outcome = admission.try_admit(_snapshot(ram=12), fast=_fast(), deep=_deep(), now=NOW)

    assert outcome.mode == "deep_local_only"
    assert outcome.admitted_roles == ("deep",)
    assert outcome.required_ram_bytes == 3 * GIB
    assert "dual_ram_headroom" in outcome.reasons
    assert outcome.reservation_id is not None


def test_unknown_vram_falls_back_to_cpu_fast_without_pretending_deep_loaded() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy())
    outcome = admission.try_admit(_snapshot(vram=None), fast=_fast(), deep=_deep(), now=NOW)

    assert outcome.mode == "fast_local_only"
    assert outcome.admitted_roles == ("fast",)
    assert outcome.required_vram_bytes == 0
    assert "deep_vram_unknown" in outcome.reasons


def test_gpu_telemetry_must_match_the_selected_device() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy())
    outcome = admission.try_admit(
        _snapshot(gpu_device_index=1), fast=_fast(), deep=_deep(), now=NOW
    )
    assert outcome.mode == "fast_local_only"
    assert "deep_gpu_device_mismatch" in outcome.reasons


@pytest.mark.parametrize("ram,vram", [(2, 24), (32, 1)])
def test_insufficient_resources_never_overcommit_or_evict(ram: int, vram: int) -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy())
    outcome = admission.try_admit(
        _snapshot(ram=ram, vram=vram), fast=_fast(), deep=_deep(), now=NOW
    )

    if ram == 2:
        assert outcome.mode == "deterministic_fallback"
        assert outcome.reservation_id is None
    else:
        assert outcome.mode == "fast_local_only"
        assert "deep_vram_headroom" in outcome.reasons


def test_stale_or_future_snapshot_fails_closed_before_loading_any_model() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy(max_snapshot_age_ms=1000))
    for observed_at in (NOW - timedelta(seconds=2), NOW + timedelta(milliseconds=100)):
        outcome = admission.try_admit(
            _snapshot(observed_at=observed_at), fast=_fast(), deep=_deep(), now=NOW
        )
        assert outcome.mode == "deterministic_fallback"
        assert outcome.reservation_id is None
        assert "resource_snapshot_stale_or_future" in outcome.reasons
    assert admission.active_reservations == 0


def test_unzoned_clock_input_fails_closed_instead_of_throwing() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy())
    outcome = admission.try_admit(
        _snapshot(), fast=_fast(), deep=_deep(), now=datetime(2026, 9, 23, 12)
    )
    assert outcome.mode == "deterministic_fallback"
    assert outcome.reservation_id is None
    assert "resource_clock_invalid" in outcome.reasons


def test_in_process_session_cap_is_atomic_under_concurrent_admission() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy(max_sessions=1))

    def attempt(_index: int) -> str:
        return admission.try_admit(_snapshot(), fast=_fast(), deep=_deep(), now=NOW).mode

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, range(2)))
    assert sorted(outcomes) == ["deterministic_fallback", "dual_local"]
    assert admission.active_reservations == 1
    assert attempt(2) == "deterministic_fallback"


def test_pending_reservations_are_subtracted_from_snapshot_headroom() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy(max_sessions=2))
    snapshot = _snapshot(ram=13, vram=24)
    first = admission.try_admit(snapshot, fast=_fast(), deep=_deep(), now=NOW)
    second = admission.try_admit(snapshot, fast=_fast(), deep=_deep(), now=NOW)

    assert first.mode == "dual_local"
    assert second.mode == "deterministic_fallback"
    assert "fast_ram_headroom" in second.reasons
    assert "deep_ram_headroom" in second.reasons


def test_external_session_count_and_disabled_degradation_are_explicit() -> None:
    admission = HostResourceAdmission(HostAdmissionPolicy(max_sessions=1))
    external = admission.try_admit(
        _snapshot(active_sessions=1), fast=_fast(), deep=_deep(), now=NOW
    )
    assert external.mode == "deterministic_fallback"
    assert "session_cap" in external.reasons

    no_degradation = HostResourceAdmission(HostAdmissionPolicy(allow_degradation=False))
    outcome = no_degradation.try_admit(_snapshot(vram=None), fast=_fast(), deep=_deep(), now=NOW)
    assert outcome.mode == "deterministic_fallback"
    assert "deep_vram_unknown" in outcome.reasons


def test_footprints_reject_invalid_or_unsupported_memory_claims() -> None:
    with pytest.raises(ValueError):
        LocalBrainFootprint(
            role="fast",
            model_id="laya-local",
            device="cpu",
            resident=False,
            cold_ram_bytes=GIB,
            cold_vram_bytes=GIB,
            session_ram_bytes=GIB,
            session_vram_bytes=0,
            footprint_origin="conservative_config",
        )
    with pytest.raises(ValueError):
        LocalBrainFootprint(
            role="deep",
            model_id="qwen-local",
            device="cuda",
            gpu_device_index=0,
            resident=False,
            cold_ram_bytes=GIB,
            cold_vram_bytes=0,
            session_ram_bytes=GIB,
            session_vram_bytes=0,
            footprint_origin="conservative_config",
        )
    with pytest.raises(ValueError):
        LocalBrainFootprint(
            role="deep",
            model_id="resident-model",
            device="cuda",
            gpu_device_index=0,
            resident=True,
            cold_ram_bytes=0,
            cold_vram_bytes=16 * GIB,
            session_ram_bytes=GIB,
            session_vram_bytes=0,
            footprint_origin="measured",
        )
