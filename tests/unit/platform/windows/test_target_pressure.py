from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from systemsense import worker
from systemsense.application.bootstrap import default_capabilities
from systemsense.packs.runtime import TargetPressureParametersV1, default_probe_runner
from systemsense.platform.windows import deep_collectors
from systemsense.worker import REGISTERED_PROBE_IDS

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


class FakeProcess:
    def __init__(self, *, reused_after_read: bool = False) -> None:
        self.reads = 0
        self.identity_reads = 0
        self.reused_after_read = reused_after_read

    def create_time(self) -> float:
        self.identity_reads += 1
        if self.reused_after_read and self.identity_reads == 2:
            return (NOW + timedelta(minutes=1)).timestamp()
        return NOW.timestamp()

    def name(self) -> str:
        return "viewer.exe"

    def cpu_times(self) -> SimpleNamespace:
        self.reads += 1
        return SimpleNamespace(user=float(self.reads), system=0.0)

    def memory_info(self) -> SimpleNamespace:
        return SimpleNamespace(rss=100_000_000)

    def io_counters(self) -> SimpleNamespace:
        return SimpleNamespace(read_bytes=self.reads * 1000, write_bytes=self.reads * 100)


def test_target_pressure_samples_exact_process_without_top32_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    pids: list[int] = []

    def selected(pid: int) -> FakeProcess:
        pids.append(pid)
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter(NOW + timedelta(seconds=offset) for offset in (0, 0, 1, 1, 2, 2, 2))
    sleeps: list[float] = []

    observation = deep_collectors.collect_target_pressure(
        pid=4242,
        creation_time=NOW,
        clock=lambda: next(times),
        sleep=sleeps.append,
    )

    assert pids == [4242, 4242, 4242]
    assert sleeps == [1.0, 1.0]
    assert observation.status == "available"
    assert observation.window_started_at == NOW
    assert observation.window_ended_at == NOW + timedelta(seconds=2)
    assert observation.captured_at == NOW + timedelta(seconds=2)
    assert [sample.delta_status for sample in observation.samples] == [
        "baseline",
        "measured",
        "measured",
    ]
    assert observation.samples[0].cpu_percent is None
    assert observation.samples[0].read_bytes_delta is None
    assert observation.samples[1].cpu_percent is not None
    assert observation.samples[1].read_bytes_delta == 1000
    assert process.identity_reads == 6


def test_target_pressure_discards_values_if_pid_reused_during_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reused(_pid: int) -> FakeProcess:
        return FakeProcess(reused_after_read=True)

    monkeypatch.setattr(deep_collectors.psutil, "Process", reused)
    times = iter((NOW, NOW, NOW))
    observation = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
    )
    assert observation.status == "reused"
    assert len(observation.samples) == 1
    assert observation.samples[0].status == "reused"
    assert observation.samples[0].rss_bytes is None


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (deep_collectors.psutil.NoSuchProcess(4242), "unavailable"),
        (deep_collectors.psutil.AccessDenied(4242), "permission_denied"),
    ],
)
def test_target_pressure_reports_missing_or_denied_process(
    monkeypatch: pytest.MonkeyPatch, error: Exception, status: str
) -> None:
    def unavailable(_pid: int) -> FakeProcess:
        raise error

    monkeypatch.setattr(deep_collectors.psutil, "Process", unavailable)
    times = iter((NOW, NOW, NOW))
    observation = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
    )
    assert observation.status == status
    assert observation.samples[0].status == status
    assert observation.samples[0].cpu_percent is None


def test_target_pressure_probe_is_registered_with_strict_identity_parameters() -> None:
    runner = default_probe_runner()
    manifest = runner.manifest("application.target_pressure")
    assert manifest is not None
    assert manifest.version == 1
    assert manifest.input_model == "TargetPressureParametersV1"
    assert "application.target_pressure" in REGISTERED_PROBE_IDS
    assert "application.target_pressure" not in {
        capability.probe_id for capability in default_capabilities()
    }
    assert TargetPressureParametersV1(pid=4242, creation_time=NOW).creation_time == NOW
    with pytest.raises(ValidationError):
        TargetPressureParametersV1.model_validate(
            {"pid": 4242, "creation_time": NOW.isoformat(), "command": "whoami"}
        )
    with pytest.raises(ValidationError):
        TargetPressureParametersV1.model_validate(
            {"pid": 4242, "creation_time": "2026-09-22T12:00:00"}
        )


def test_target_pressure_retains_partial_sample_when_process_disappears(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    calls = 0

    def selected(_pid: int) -> FakeProcess:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise deep_collectors.psutil.NoSuchProcess(4242)
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter(NOW + timedelta(seconds=offset) for offset in (0, 0, 1, 1, 1))
    sleeps: list[float] = []
    observation = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=sleeps.append
    )
    assert observation.status == "partial"
    assert [sample.status for sample in observation.samples] == ["available", "unavailable"]
    assert observation.samples[0].delta_status == "baseline"
    assert observation.samples[1].rss_bytes is None
    assert sleeps == [1.0]


def test_target_pressure_worker_keeps_source_and_capture_times_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = deep_collectors.TargetPressureSample(
        query_started_at=NOW,
        observed_at=NOW + timedelta(milliseconds=100),
        status=deep_collectors.TargetPressureStatus.UNAVAILABLE,
        delta_status="unavailable",
    )
    observation = deep_collectors.TargetPressureSnapshot(
        target_pid=4242,
        target_creation_time=NOW - timedelta(minutes=2),
        window_started_at=NOW,
        window_ended_at=sample.observed_at,
        captured_at=NOW + timedelta(milliseconds=200),
        samples=(sample,),
        status=deep_collectors.TargetPressureStatus.UNAVAILABLE,
        limitations=("target exited",),
    )
    payloads: list[dict[str, object]] = []

    def collected(**_kwargs: object) -> deep_collectors.TargetPressureSnapshot:
        return observation

    monkeypatch.setattr(deep_collectors, "collect_target_pressure", collected)
    monkeypatch.setattr(worker, "_emit", payloads.append)

    worker._target_pressure(  # pyright: ignore[reportPrivateUsage]
        {"pid": 4242, "creation_time": (NOW - timedelta(minutes=2)).isoformat()}
    )

    payload = payloads[0]
    assert payload["observed_at"] == sample.observed_at.isoformat()
    assert payload["captured_at"] == observation.captured_at.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert payload["limitations"] == ["target exited"]


def test_target_pressure_marks_missing_io_delta_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    class NoIoProcess(FakeProcess):
        def io_counters(self) -> SimpleNamespace:
            raise deep_collectors.psutil.AccessDenied(4242)

    process = NoIoProcess()

    def selected(_pid: int) -> NoIoProcess:
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter(NOW + timedelta(seconds=offset) for offset in (0, 0, 1, 1, 2, 2, 2))
    result = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
    )
    assert result.status == "partial"
    assert result.samples[1].delta_status == "partial"
    assert result.samples[1].cpu_percent is not None
    assert result.samples[1].read_bytes_delta is None


def test_target_pressure_fails_closed_on_clock_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def selected(_pid: int) -> FakeProcess:
        return FakeProcess()

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter((NOW, NOW, NOW - timedelta(seconds=1)))
    with pytest.raises(deep_collectors.TargetPressureClockRollback):
        deep_collectors.collect_target_pressure(
            pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
        )


def test_target_pressure_rejects_reused_pid_before_read(monkeypatch: pytest.MonkeyPatch) -> None:
    class ReusedProcess(FakeProcess):
        def create_time(self) -> float:
            return (NOW + timedelta(minutes=1)).timestamp()

    process = ReusedProcess()

    def selected(_pid: int) -> ReusedProcess:
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter((NOW, NOW, NOW))
    result = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
    )
    assert result.status == "reused"
    assert process.reads == 0
    assert result.samples[0].delta_status == "unavailable"


def test_target_pressure_does_not_label_zero_elapsed_delta_measured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()

    def selected(_pid: int) -> FakeProcess:
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter((NOW,) * 7)
    result = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
    )
    assert result.status == "partial"
    assert result.samples[1].delta_status == "partial"
    assert result.samples[1].cpu_percent is None


def test_target_pressure_worker_emits_no_evidence_on_clock_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads: list[dict[str, object]] = []

    def rollback(**_kwargs: object) -> deep_collectors.TargetPressureSnapshot:
        raise deep_collectors.TargetPressureClockRollback("UTC clock moved backwards")

    monkeypatch.setattr(deep_collectors, "collect_target_pressure", rollback)
    monkeypatch.setattr(worker, "_emit", payloads.append)
    with pytest.raises(deep_collectors.TargetPressureClockRollback):
        worker._target_pressure(  # pyright: ignore[reportPrivateUsage]
            {"pid": 4242, "creation_time": NOW.isoformat()}
        )
    assert payloads == []


def test_target_pressure_marks_io_counter_reset_as_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ResetProcess(FakeProcess):
        def io_counters(self) -> SimpleNamespace:
            read_bytes = 0 if self.reads == 2 else self.reads * 1000
            return SimpleNamespace(read_bytes=read_bytes, write_bytes=self.reads * 100)

    process = ResetProcess()

    def selected(_pid: int) -> ResetProcess:
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter(NOW + timedelta(seconds=offset) for offset in (0, 0, 1, 1, 2, 2, 2))
    result = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
    )
    assert result.status == "partial"
    assert result.samples[1].delta_status == "partial"
    assert result.samples[1].read_bytes_delta is None
    assert result.samples[2].delta_status == "measured"
