"""Offline affected-task oracle contracts; no guest or native action is exercised."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest

from benchmarks.vm_lab_custody import CaptureKind, CaptureReceipt, capture_bytes
from benchmarks.wininet_affected_task import (
    AffectedTaskExpectation,
    AffectedTaskObservation,
    Phase,
    Result,
    Route,
    bind_affected_task,
)
from benchmarks.wininet_route_witness import HostRouteBinding

START = datetime(2026, 9, 24, 12, tzinfo=UTC)
NONCE = "a" * 32
HOST = f"{NONCE}.owned.example.org"
VM = UUID("11111111-2222-3333-4444-555555555555")


def _expectation() -> AffectedTaskExpectation:
    return AffectedTaskExpectation(
        episode_id="proxy-001",
        trial_nonce=NONCE,
        vm_uuid=VM,
        generation_id="generation-clean-001",
        guest_boot_id="boot-001",
        user_sid="S-1-5-21-1-2-3-1001",
        application_id="owned-browser",
        application_sha256="b" * 64,
        application_pid=1234,
        application_created_at=START,
        origin_host=HOST,
        endpoint_sha256="c" * 64,
        oracle_controller_id="oracle-controller",
    )


def _captures(
    root: Path,
    *,
    injected_result: Result = "proxy_failure",
    change_phase: Phase | None = None,
    changes: dict[str, object] | None = None,
) -> tuple[CaptureReceipt, ...]:
    expected = _expectation()
    receipts: list[CaptureReceipt] = []
    sequence: tuple[tuple[Phase, Route, Result], ...] = (
        ("clean", "affected_preconfig", "http_204"),
        ("injected", "affected_preconfig", injected_result),
        ("direct_control", "rig_direct", "http_204"),
        ("after_arm", "affected_preconfig", "http_204"),
        ("after_restore", "affected_preconfig", "http_204"),
    )
    for index, (phase, route, result) in enumerate(sequence):
        observed_at = START + timedelta(seconds=index + 1)
        observation = AffectedTaskObservation(
            schema_version=1,
            episode_id=expected.episode_id,
            trial_nonce=expected.trial_nonce,
            vm_uuid=expected.vm_uuid,
            generation_id=expected.generation_id,
            guest_boot_id=expected.guest_boot_id,
            user_sid=expected.user_sid,
            application_id=expected.application_id
            if route == "affected_preconfig"
            else "rig-control",
            application_sha256=expected.application_sha256
            if route == "affected_preconfig"
            else "d" * 64,
            application_pid=expected.application_pid if route == "affected_preconfig" else 3456,
            application_created_at=expected.application_created_at,
            origin_host=expected.origin_host,
            endpoint_sha256=expected.endpoint_sha256,
            request_id=f"request-{index}",
            phase=phase,
            route=route,
            result=result,
            http_status=502 if result == "proxy_failure" else 204 if result == "http_204" else None,
            observed_at=observed_at,
            elapsed_ms=100,
        )
        if phase == change_phase and changes is not None:
            observation = AffectedTaskObservation.model_validate(
                observation.model_dump(mode="python") | changes
            )
        receipts.append(
            capture_bytes(
                root,
                episode_id=expected.episode_id,
                capture_id=f"task-{phase.replace('_', '-')}-{NONCE}",
                kind=CaptureKind.AFFECTED_TASK,
                controller_id=expected.oracle_controller_id,
                source_observed_at=observation.observed_at,
                collected_at=observed_at,
                data=observation.model_dump_json().encode(),
            )
        )
    return tuple(receipts)


def _controls(
    root: Path,
    *,
    proxy_bytes: bytes | None = None,
) -> tuple[HostRouteBinding, CaptureReceipt, CaptureReceipt, tuple[CaptureReceipt, ...]]:
    expected = _expectation()
    proxy = capture_bytes(
        root,
        episode_id=expected.episode_id,
        capture_id=f"connect-{NONCE}",
        kind=CaptureKind.PROXY_CONNECT,
        controller_id=expected.oracle_controller_id,
        source_observed_at=START + timedelta(seconds=1, milliseconds=500),
        collected_at=START + timedelta(seconds=1, milliseconds=500),
        data=proxy_bytes
        if proxy_bytes is not None
        else f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n".encode(),
    )
    route_origin = capture_bytes(
        root,
        episode_id=expected.episode_id,
        capture_id=f"origin-{NONCE}",
        kind=CaptureKind.ORIGIN_EVENT,
        controller_id=expected.oracle_controller_id,
        source_observed_at=START + timedelta(seconds=2, milliseconds=500),
        collected_at=START + timedelta(seconds=2, milliseconds=500),
        data=f"{HOST}\t204\t{NONCE}\n".encode(),
    )
    origins = tuple(
        capture_bytes(
            root,
            episode_id=expected.episode_id,
            capture_id=f"task-origin-{phase.replace('_', '-')}-{NONCE}",
            kind=CaptureKind.ORIGIN_EVENT,
            controller_id=expected.oracle_controller_id,
            source_observed_at=START + timedelta(seconds=index + 1),
            collected_at=START + timedelta(seconds=index + 1),
            data=f"{HOST}\t204\t{NONCE}\trequest-{index}\n".encode(),
        )
        for phase, index in (
            ("clean", 0),
            ("direct_control", 2),
            ("after_arm", 3),
            ("after_restore", 4),
        )
    )
    route = HostRouteBinding(
        classification="host_route_binding_only",
        episode_id=expected.episode_id,
        trial_nonce=expected.trial_nonce,
        vm_uuid=expected.vm_uuid,
        generation_id=expected.generation_id,
        proxy_capture_digest=proxy.sha256,
        origin_capture_digest=route_origin.sha256,
    )
    return route, proxy, route_origin, origins


def test_five_phase_task_capture_is_host_only_and_never_grants_recovery(tmp_path: Path) -> None:
    receipts = _captures(tmp_path)
    route, proxy, route_origin, origins = _controls(tmp_path)
    bound = bind_affected_task(
        tmp_path,
        _expectation(),
        receipts,
        route_binding=route,
        proxy_receipt=proxy,
        route_origin_receipt=route_origin,
        origin_receipts=origins,
    )
    assert bound.classification == "host_affected_task_only"
    assert bound.complete
    assert bound.diagnostic_accuracy_claim is False
    assert bound.repair_verified is False


def test_missing_affected_application_retry_is_rejected(tmp_path: Path) -> None:
    receipts = _captures(tmp_path)
    route, proxy, route_origin, origins = _controls(tmp_path)
    with pytest.raises(ValueError, match="phase"):
        bind_affected_task(
            tmp_path,
            _expectation(),
            receipts[:-2] + receipts[-1:],
            route_binding=route,
            proxy_receipt=proxy,
            route_origin_receipt=route_origin,
            origin_receipts=origins,
        )


@pytest.mark.parametrize("result", ["dns_error", "tls_error", "timeout", "other_error"])
def test_ambiguous_injected_failure_is_not_admitted(tmp_path: Path, result: Result) -> None:
    receipts = _captures(tmp_path, injected_result=result)
    route, proxy, route_origin, origins = _controls(tmp_path)
    with pytest.raises(ValueError, match="ambiguous"):
        bind_affected_task(
            tmp_path,
            _expectation(),
            receipts,
            route_binding=route,
            proxy_receipt=proxy,
            route_origin_receipt=route_origin,
            origin_receipts=origins,
        )


@pytest.mark.parametrize(
    ("phase", "changes", "message"),
    [
        ("after_arm", {"user_sid": "S-1-5-21-1-2-3-1002"}, "identity"),
        ("after_arm", {"application_pid": 9999}, "process identity"),
        ("after_arm", {"endpoint_sha256": "e" * 64}, "identity"),
        ("after_arm", {"generation_id": "generation-other-001"}, "identity"),
        ("after_arm", {"trial_nonce": "f" * 32}, "identity"),
        ("after_arm", {"request_id": "request-0"}, "replay"),
        ("after_arm", {"observed_at": START + timedelta(seconds=2)}, "order"),
        ("after_arm", {"result": "proxy_failure"}, "ambiguous"),
        ("injected", {"http_status": 204}, "HTTP outcome"),
    ],
)
def test_changed_task_capture_is_rejected(
    tmp_path: Path, phase: Phase, changes: dict[str, object], message: str
) -> None:
    receipts = _captures(tmp_path, change_phase=phase, changes=changes)
    route, proxy, route_origin, origins = _controls(tmp_path)
    with pytest.raises(ValueError, match=message):
        bind_affected_task(
            tmp_path,
            _expectation(),
            receipts,
            route_binding=route,
            proxy_receipt=proxy,
            route_origin_receipt=route_origin,
            origin_receipts=origins,
        )


def test_missing_connect_or_direct_origin_cannot_bind(tmp_path: Path) -> None:
    receipts = _captures(tmp_path)
    route, proxy, route_origin, origins = _controls(tmp_path)
    with pytest.raises(ValueError, match="CONNECT"):
        bind_affected_task(
            tmp_path,
            _expectation(),
            receipts,
            route_binding=route,
            proxy_receipt=route_origin,
            route_origin_receipt=route_origin,
            origin_receipts=origins,
        )
    with pytest.raises(ValueError, match="origin"):
        bind_affected_task(
            tmp_path,
            _expectation(),
            receipts,
            route_binding=route,
            proxy_receipt=proxy,
            route_origin_receipt=route_origin,
            origin_receipts=origins[:-1],
        )


def test_nonmatching_connect_bytes_are_rejected_even_with_matching_digest(tmp_path: Path) -> None:
    receipts = _captures(tmp_path)
    route, proxy, route_origin, origins = _controls(
        tmp_path,
        proxy_bytes=b"CONNECT unrelated.example.org:443 HTTP/1.1\r\n"
        b"Host: unrelated.example.org:443\r\n\r\n",
    )
    with pytest.raises(ValueError, match="target mismatch"):
        bind_affected_task(
            tmp_path,
            _expectation(),
            receipts,
            route_binding=route,
            proxy_receipt=proxy,
            route_origin_receipt=route_origin,
            origin_receipts=origins,
        )


def test_route_binding_from_another_trial_is_rejected(tmp_path: Path) -> None:
    receipts = _captures(tmp_path)
    route, proxy, route_origin, origins = _controls(tmp_path)
    with pytest.raises(ValueError, match="trial mismatch"):
        bind_affected_task(
            tmp_path,
            _expectation(),
            receipts,
            route_binding=replace(route, trial_nonce="f" * 32),
            proxy_receipt=proxy,
            route_origin_receipt=route_origin,
            origin_receipts=origins,
        )
