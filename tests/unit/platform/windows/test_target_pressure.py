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
    def __init__(self) -> None:
        self.reads = 0
        self.identity_reads = 0

    def create_time(self) -> float:
        self.identity_reads += 1
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

    assert pids == [4242] * 6
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


def test_one_busy_core_is_distinct_from_four_percent_of_total_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()

    def selected(_pid: int) -> FakeProcess:
        return process

    def cpu_count(*, logical: bool) -> int:
        assert logical
        return 24

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    monkeypatch.setattr(deep_collectors.psutil, "cpu_count", cpu_count)
    times = iter(NOW + timedelta(seconds=offset) for offset in (0, 0, 1, 1, 2, 2, 2))
    observation = deep_collectors.collect_target_pressure(
        pid=4242,
        creation_time=NOW,
        clock=lambda: next(times),
        sleep=lambda _seconds: None,
    )
    assert observation.schema_version == 2
    assert observation.logical_cpu_count == 24
    assert observation.samples[0].cpu_logical_cores is None
    for sample in observation.samples[1:]:
        assert sample.cpu_percent == pytest.approx(4.167)
        assert sample.cpu_logical_cores == 1.0


@pytest.mark.parametrize(
    "count,cores,percent",
    [(None, 1.0, 4.167), (24, None, 4.167), (24, 1.0, None), (24, 10.0, 4.167)],
)
def test_version_two_rejects_missing_or_inconsistent_cpu_units(
    count: int | None,
    cores: float | None,
    percent: float | None,
) -> None:
    sample = deep_collectors.TargetPressureSample(
        query_started_at=NOW,
        observed_at=NOW,
        status=deep_collectors.TargetPressureStatus.AVAILABLE,
        delta_status="measured",
        cpu_percent=percent,
        cpu_logical_cores=cores,
    )
    with pytest.raises(ValidationError):
        deep_collectors.TargetPressureSnapshot(
            schema_version=2,
            logical_cpu_count=count,
            target_pid=42,
            target_creation_time=NOW,
            window_started_at=NOW,
            window_ended_at=NOW,
            captured_at=NOW,
            samples=(sample,),
            status=deep_collectors.TargetPressureStatus.AVAILABLE,
        )


@pytest.mark.parametrize("boundary_status", ["reused", "unavailable", "permission_denied"])
def test_target_pressure_discards_values_when_fresh_final_identity_is_unverified(
    monkeypatch: pytest.MonkeyPatch,
    boundary_status: str,
) -> None:
    current_creation = NOW.timestamp()
    counters_read = False
    instances: list[FakeProcess] = []

    class CachedProcess(FakeProcess):
        """Match psutil: create_time caches its first value per Process instance."""

        cached_creation: float | None = None

        def create_time(self) -> float:
            if self.cached_creation is None:
                self.cached_creation = current_creation
            return self.cached_creation

        def io_counters(self) -> SimpleNamespace:
            nonlocal counters_read, current_creation
            result = super().io_counters()
            counters_read = True
            current_creation = (NOW + timedelta(minutes=1)).timestamp()
            return result

    def selected(_pid: int) -> FakeProcess:
        if counters_read and boundary_status == "unavailable":
            raise deep_collectors.psutil.NoSuchProcess(4242)
        if counters_read and boundary_status == "permission_denied":
            raise deep_collectors.psutil.AccessDenied(4242)
        process = CachedProcess()
        instances.append(process)
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter(NOW + timedelta(seconds=offset) for offset in (0, 0, 1, 1, 2, 2, 2))
    observation = deep_collectors.collect_target_pressure(
        pid=4242, creation_time=NOW, clock=lambda: next(times), sleep=lambda _seconds: None
    )
    assert observation.status == boundary_status
    assert len(observation.samples) == 1
    assert observation.samples[0].status == boundary_status
    assert observation.samples[0].rss_bytes is None
    assert observation.samples[0].cpu_percent is None
    assert observation.samples[0].read_bytes_delta is None
    assert instances[0].reads == 1


def test_target_pressure_accepts_one_microsecond_timestamp_rounding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RoundedProcess(FakeProcess):
        def create_time(self) -> float:
            self.identity_reads += 1
            return (NOW + timedelta(microseconds=1)).timestamp()

    process = RoundedProcess()

    def selected(_pid: int) -> RoundedProcess:
        return process

    monkeypatch.setattr(deep_collectors.psutil, "Process", selected)
    times = iter(NOW + timedelta(seconds=offset) for offset in (0, 0, 1, 1, 2, 2, 2))

    observation = deep_collectors.collect_target_pressure(
        pid=4242,
        creation_time=NOW,
        clock=lambda: next(times),
        sleep=lambda _seconds: None,
    )

    assert observation.status == "available"
    assert [sample.delta_status for sample in observation.samples] == [
        "baseline",
        "measured",
        "measured",
    ]


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
    assert manifest.version == 2
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
        if calls == 3:
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
