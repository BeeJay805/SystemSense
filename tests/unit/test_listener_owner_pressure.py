"""A live process identity alone does not prove continued listener ownership."""

import http.client
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import cast

import psutil
import pytest

from systemsense import worker
from systemsense.domain.ids import JsonValue
from systemsense.platform.windows import deep_collectors

NOW = datetime(2026, 9, 29, 12, tzinfo=UTC)
PID = 4242
PORT = 54321
NONCE = "a" * 32

# Worker handlers are exercised directly with all machine interactions substituted.
# pyright: reportPrivateUsage=false


def _sample() -> deep_collectors.TargetPressureSnapshot:
    return deep_collectors.TargetPressureSnapshot(
        target_pid=PID,
        target_creation_time=NOW,
        window_started_at=NOW,
        window_ended_at=NOW + timedelta(seconds=2),
        captured_at=NOW + timedelta(seconds=2),
        status=deep_collectors.TargetPressureStatus.AVAILABLE,
        samples=tuple(
            deep_collectors.TargetPressureSample(
                query_started_at=NOW + timedelta(seconds=index),
                observed_at=NOW + timedelta(seconds=index),
                status=deep_collectors.TargetPressureStatus.AVAILABLE,
                delta_status="baseline" if index == 0 else "measured",
                cpu_percent=None if index == 0 else 25,
            )
            for index in range(3)
        ),
    )


def _run_replay(
    monkeypatch: pytest.MonkeyPatch,
    *,
    before: str = "owned",
    after: str = "owned",
    http_status: int | None = None,
    birth_offset_us: int = 0,
) -> tuple[dict[str, JsonValue], list[int]]:
    current = [NOW]
    queried_pids: list[int] = []

    def state() -> str:
        return before if current[0] == NOW else after

    class LivingProcess:
        def create_time(self) -> float:
            if state() == "reused":
                return (NOW + timedelta(minutes=1)).timestamp()
            return (NOW + timedelta(microseconds=birth_offset_us)).timestamp()

        def net_connections(self, kind: str) -> list[SimpleNamespace]:
            assert kind == "tcp4"
            if state() == "denied":
                raise psutil.AccessDenied(PID)
            if state() == "unsupported":
                raise NotImplementedError
            if state() == "failed":
                raise OSError
            return (
                [
                    SimpleNamespace(
                        status=(
                            psutil.CONN_ESTABLISHED
                            if state() == "established"
                            else psutil.CONN_LISTEN
                        ),
                        laddr=SimpleNamespace(
                            ip=(
                                "0.0.0.0"
                                if state() == "wildcard"
                                else "192.0.2.1"
                                if state() == "other_address"
                                else "127.0.0.1"
                            ),
                            port=PORT + 1 if state() == "other_port" else PORT,
                        ),
                    )
                ]
                if state() not in {"relinquished", "transferred"}
                else []
            )

    class TimeoutConnection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            assert (host, port, timeout) == ("127.0.0.1", PORT, 2)

        def request(self, method: str, path: str) -> None:
            assert (method, path) == ("GET", f"/health/{NONCE}")

        def getresponse(self) -> SimpleNamespace:
            current[0] += timedelta(seconds=2)
            if http_status is None:
                raise TimeoutError

            def read(size: int) -> bytes:
                assert size == 65
                return (NONCE + "\n").encode()

            return SimpleNamespace(status=http_status, read=read)

        def close(self) -> None:
            pass

    def process(pid: int) -> LivingProcess:
        queried_pids.append(pid)
        assert pid == PID
        if state() == "missing":
            raise psutil.NoSuchProcess(PID)
        return LivingProcess()

    def pressure(*, pid: int, creation_time: datetime) -> deep_collectors.TargetPressureSnapshot:
        assert (pid, creation_time) == (PID, NOW)
        return _sample()

    def cpu_count(*, logical: bool) -> int:
        assert logical
        return 4

    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr(worker, "utc_now", lambda: current[0])
    monkeypatch.setattr(worker, "_emit", payloads.append)
    monkeypatch.setattr(psutil, "Process", process)
    monkeypatch.setattr(psutil, "cpu_count", cpu_count)
    monkeypatch.setattr(deep_collectors, "collect_target_pressure", pressure)
    monkeypatch.setattr(http.client, "HTTPConnection", TimeoutConnection)

    worker._listener_owner_pressure(
        {"pid": PID, "creation_time": NOW.isoformat(), "port": PORT, "nonce": NONCE}
    )

    return payloads[0], queried_pids


@pytest.mark.parametrize("after", ["relinquished", "transferred"])
def test_relinquished_port_does_not_attribute_living_process_cpu_to_replay(
    monkeypatch: pytest.MonkeyPatch, after: str
) -> None:
    payload, queried_pids = _run_replay(monkeypatch, after=after)

    facts = cast("dict[str, JsonValue]", payload["facts"])
    coincident = cast("dict[str, JsonValue]", facts["coincident_owner_cpu"])
    assert coincident["status"] == "unavailable"
    assert coincident["peak_logical_cores"] is None
    assert facts["target_pressure"] == _sample().model_dump(mode="json")
    ownership = cast("dict[str, JsonValue]", facts["listener_ownership"])
    assert ownership["status"] == "unverified"
    assert cast("dict[str, JsonValue]", ownership["before_replay"])["status"] == "verified"
    assert cast("dict[str, JsonValue]", ownership["after_replay"])["status"] == "not_owned"
    # The successor is outside this probe's source-bound process authorization.
    assert queried_pids == [PID, PID, PID, PID]
    assert "Substantial" not in str(payload["summary"])
    assert any(
        "not the request's listener" in str(item)
        for item in cast("list[JsonValue]", payload["limitations"])
    )


@pytest.mark.parametrize("boundary", ["before", "after"])
@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("relinquished", "not_owned"),
        ("missing", "unavailable"),
        ("denied", "permission_denied"),
        ("reused", "reused"),
        ("unsupported", "unsupported"),
        ("failed", "failed"),
        ("other_port", "not_owned"),
        ("other_address", "not_owned"),
        ("established", "not_owned"),
    ],
)
def test_unverified_boundary_keeps_replay_and_process_facts_without_owner_attribution(
    monkeypatch: pytest.MonkeyPatch, boundary: str, state: str, expected: str
) -> None:
    payload, _ = _run_replay(
        monkeypatch,
        before=state if boundary == "before" else "owned",
        after=state if boundary == "after" else "owned",
    )
    facts = cast("dict[str, JsonValue]", payload["facts"])
    ownership = cast("dict[str, JsonValue]", facts["listener_ownership"])
    assert ownership["status"] == "unverified"
    check = cast("dict[str, JsonValue]", ownership[f"{boundary}_replay"])
    assert check["status"] == expected
    assert "query_started_at" in check and "observed_at" in check
    coincident = cast("dict[str, JsonValue]", facts["coincident_owner_cpu"])
    assert coincident["status"] == "unavailable"
    assert coincident["sample_count"] == 0
    assert coincident["peak_logical_cores"] is None
    assert coincident["mean_logical_cores"] is None
    assert facts["target_pressure"] == _sample().model_dump(mode="json")
    assert cast("dict[str, JsonValue]", facts["loopback_replay"])["outcome"] == "timeout"


@pytest.mark.parametrize("state", ["owned", "wildcard"])
@pytest.mark.parametrize("birth_offset_us", [0, 1])
def test_verified_boundaries_retain_overlapping_cpu_with_explicit_temporal_limit(
    monkeypatch: pytest.MonkeyPatch, state: str, birth_offset_us: int
) -> None:
    payload, queried_pids = _run_replay(
        monkeypatch, before=state, after=state, birth_offset_us=birth_offset_us
    )
    facts = cast("dict[str, JsonValue]", payload["facts"])
    ownership = cast("dict[str, JsonValue]", facts["listener_ownership"])
    assert ownership["schema_version"] == 1
    assert ownership["status"] == "verified_at_boundaries"
    assert ownership["target_pid"] == PID
    assert ownership["target_creation_time"] == NOW.isoformat()
    assert ownership["target_handle"] == f"127.0.0.1:{PORT}"
    assert queried_pids == [PID, PID, PID, PID]
    coincident = cast("dict[str, JsonValue]", facts["coincident_owner_cpu"])
    assert coincident["status"] == "measured"
    assert coincident["sample_count"] == 2
    assert coincident["peak_logical_cores"] == 1
    assert coincident["mean_logical_cores"] == 1
    assert "source-bound process" in str(payload["summary"])
    assert "do not prove uninterrupted ownership" in str(payload["summary"])
    assert "handler" in str(payload["summary"])


def test_changed_replay_result_survives_missing_ownership(monkeypatch: pytest.MonkeyPatch) -> None:
    payload, _ = _run_replay(monkeypatch, after="transferred", http_status=200)
    facts = cast("dict[str, JsonValue]", payload["facts"])
    assert (
        cast("dict[str, JsonValue]", facts["loopback_replay"])["outcome"] == "http_200_nonce_match"
    )
    assert cast("dict[str, JsonValue]", facts["coincident_owner_cpu"])["status"] == "unavailable"


def test_identity_is_rechecked_after_socket_read_with_a_fresh_process_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    objects_created: list[int] = []

    class ReusedProcess:
        def __init__(self, born: datetime) -> None:
            self.born = born

        def create_time(self) -> float:
            return self.born.timestamp()

        def net_connections(self, kind: str) -> list[SimpleNamespace]:
            assert kind == "tcp4"
            return [
                SimpleNamespace(
                    status=psutil.CONN_LISTEN,
                    laddr=SimpleNamespace(ip="127.0.0.1", port=PORT),
                )
            ]

    def process(pid: int) -> ReusedProcess:
        objects_created.append(pid)
        return ReusedProcess(NOW if len(objects_created) == 1 else NOW + timedelta(minutes=1))

    monkeypatch.setattr(psutil, "Process", process)
    result = worker._listener_owner_at_boundary(pid=PID, creation_time=NOW, port=PORT)

    assert result["status"] == "reused"
    assert objects_created == [PID, PID]
