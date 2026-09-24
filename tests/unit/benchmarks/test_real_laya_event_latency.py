"""Accounting checks for the opt-in real-Laya event latency benchmark."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks import real_laya_event_latency as benchmark
from benchmarks.real_laya_event_latency import (
    run_local_trial,
    summarize_attempts,
)
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.inference.laya_runtime import LayaAttentionResult
from systemsense.storage.sqlite_store import SQLiteStore


def test_misses_remain_in_planned_attempt_denominator() -> None:
    attempts = [
        {"persisted_ns": 10, "admitted_ns": 20, "miss_reason": None},
        {"persisted_ns": 30, "admitted_ns": None, "miss_reason": "provider_degraded"},
        {"persisted_ns": None, "admitted_ns": None, "miss_reason": "parent_not_persisted"},
    ]

    report = summarize_attempts(attempts)

    assert report["planned_attempts"] == 3
    assert report["persisted_events"] == 2
    assert report["admitted_followups"] == 1
    assert report["misses"] == 2
    assert report["miss_reasons"] == {"parent_not_persisted": 1, "provider_degraded": 1}
    assert report["all_attempt_p95_ms"] is None
    assert report["admitted_only_ms"]["count"] == 1


def test_complete_denominator_reports_all_attempt_p95() -> None:
    report = summarize_attempts(
        [
            {"persisted_ns": 10, "admitted_ns": 1_000_010, "miss_reason": None},
            {"persisted_ns": 20, "admitted_ns": 2_000_020, "miss_reason": None},
        ]
    )

    assert report["all_attempt_p95_ms"] == 1.95


def test_gpu_gate_queries_only_the_selected_device(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    def query(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        output = "0\n" if any("--query-gpu=" in part for part in command) else ""
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    def telemetry(**_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(free_vram_bytes=16 * 1024**3)

    def no_processes(_fields: object) -> tuple[()]:
        return ()

    def no_sleep(_seconds: float) -> None:
        pass

    monkeypatch.setattr(
        benchmark,
        "read_host_telemetry",
        telemetry,
    )
    monkeypatch.setattr(benchmark.subprocess, "run", query)
    monkeypatch.setattr(benchmark.psutil, "process_iter", no_processes)
    monkeypatch.setattr(benchmark.time, "sleep", no_sleep)

    assert benchmark._gpu_gate_reason(2) is None  # pyright: ignore[reportPrivateUsage]
    assert len(commands) == 4
    assert all(command[command.index("-i") + 1] == "2" for command in commands)


def test_ambient_gpu_trial_is_explicit_and_still_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    utilization = 28
    free_vram = 16 * 1024**3

    def query(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = (
            f"{utilization}\n"
            if any("--query-gpu=" in part for part in command)
            else "10680, wallpaper64.exe, [N/A]\n"
        )
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    def telemetry(**_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(free_vram_bytes=free_vram)

    def no_processes(_fields: object) -> tuple[()]:
        return ()

    def no_sleep(_seconds: float) -> None:
        pass

    monkeypatch.setattr(benchmark, "read_host_telemetry", telemetry)
    monkeypatch.setattr(benchmark.subprocess, "run", query)
    monkeypatch.setattr(benchmark.psutil, "process_iter", no_processes)
    monkeypatch.setattr(benchmark.time, "sleep", no_sleep)

    assert benchmark._gpu_gate_reason(0) is not None  # pyright: ignore[reportPrivateUsage]
    assert (
        benchmark._gpu_gate_reason(  # pyright: ignore[reportPrivateUsage]
            0, allow_ambient_gpu=True
        )
        is None
    )
    utilization = 70
    assert (
        benchmark._gpu_gate_reason(  # pyright: ignore[reportPrivateUsage]
            0, allow_ambient_gpu=True
        )
        is not None
    )
    assert (
        benchmark._gpu_gate_reason(0, allow_ambient_gpu=True)  # pyright: ignore[reportPrivateUsage]
        == "gpu_utilization"
    )
    utilization = 28
    free_vram = 4 * 1024**3
    assert (
        benchmark._gpu_gate_reason(  # pyright: ignore[reportPrivateUsage]
            0, allow_ambient_gpu=True
        )
        is not None
    )
    assert (
        benchmark._gpu_gate_reason(0, allow_ambient_gpu=True)  # pyright: ignore[reportPrivateUsage]
        == "vram_headroom"
    )


def test_resource_gate_miss_is_not_labeled_admitted() -> None:
    detail = benchmark._attempt_detail(  # pyright: ignore[reportPrivateUsage]
        {
            "persisted_ns": None,
            "admitted_ns": None,
            "miss_reason": "resource_gate_closed",
            "gpu_gate_reason": "gpu_utilization",
        }
    )

    assert detail["outcome"] == "missed"
    assert detail["event_to_admission_ms"] is None
    assert detail["gpu_gate_reason"] == "gpu_utilization"


def test_laya_worker_detection_uses_exact_script_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes = (
        SimpleNamespace(
            pid=11,
            info={"cmdline": ["powershell.exe", "echo laya_worker.py is not running"]},
        ),
        SimpleNamespace(
            pid=12,
            info={"cmdline": ["python.exe", "C:/SystemSense/laya_worker.py"]},
        ),
    )

    def process_iter(_fields: object) -> tuple[SimpleNamespace, ...]:
        return processes

    monkeypatch.setattr(benchmark.psutil, "process_iter", process_iter)

    assert benchmark._laya_worker_processes() == (  # pyright: ignore[reportPrivateUsage]
        {"pid": 12, "ppid": None},
    )


def test_gpu_gate_owns_only_managed_laya_worker_tree() -> None:
    processes: tuple[dict[str, int | None], ...] = (
        {"pid": 10, "ppid": 1},
        {"pid": 11, "ppid": 10},
        {"pid": 12, "ppid": 11},
        {"pid": 99, "ppid": 1},
    )

    assert benchmark._owned_laya_tree_pids(  # pyright: ignore[reportPrivateUsage]
        processes, 10
    ) == frozenset({10, 11, 12})
    assert (
        benchmark._owned_laya_tree_pids(  # pyright: ignore[reportPrivateUsage]
            processes, 55
        )
        == frozenset()
    )


def test_ambient_trial_waits_for_own_recent_gpu_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reasons = iter(("gpu_utilization", "gpu_utilization", None))

    def next_reason(*_args: object, **_kwargs: object) -> str | None:
        return next(reasons)

    def no_sleep(_seconds: float) -> None:
        pass

    monkeypatch.setattr(benchmark, "_gpu_gate_reason", next_reason)
    monkeypatch.setattr(benchmark.time, "sleep", no_sleep)

    reason, waited_ms = benchmark._await_gpu_capacity(  # pyright: ignore[reportPrivateUsage]
        0, owned_laya_pid=42, allow_ambient_gpu=True, max_wait_ms=2000
    )

    assert reason is None
    assert waited_ms >= 0


def test_strict_gpu_trial_does_not_retry_busy_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def busy(*_args: object, **_kwargs: object) -> str:
        nonlocal calls
        calls += 1
        return "gpu_utilization"

    monkeypatch.setattr(benchmark, "_gpu_gate_reason", busy)
    reason, _waited_ms = benchmark._await_gpu_capacity(  # pyright: ignore[reportPrivateUsage]
        0, allow_ambient_gpu=False, max_wait_ms=2000
    )

    assert reason == "gpu_utilization"
    assert calls == 1


def test_ambient_gpu_retry_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def busy(*_args: object, **_kwargs: object) -> str:
        nonlocal calls
        calls += 1
        return "gpu_utilization"

    monkeypatch.setattr(benchmark, "_gpu_gate_reason", busy)
    reason, _waited_ms = benchmark._await_gpu_capacity(  # pyright: ignore[reportPrivateUsage]
        0, allow_ambient_gpu=True, max_wait_ms=0
    )

    assert reason == "gpu_utilization"
    assert calls == 1


def test_local_trial_reaches_durable_followup_without_gpu(tmp_path: Path) -> None:
    class Ranker:
        def attend(
            self,
            *,
            state: dict[str, object],
            evidence: tuple[dict[str, str], ...],
            candidates: tuple[dict[str, str], ...],
            timeout_seconds: float,
        ) -> LayaAttentionResult:
            del state, timeout_seconds
            return LayaAttentionResult(
                ranked_probe_ids=tuple(item["probe_id"] for item in candidates),
                considered_probe_ids=tuple(item["probe_id"] for item in candidates),
                ranked_evidence_ids=tuple(item["evidence_id"] for item in evidence),
                considered_evidence_ids=tuple(item["evidence_id"] for item in evidence),
                ranked_attention_page_ids=tuple(item["page_id"] for item in evidence),
                considered_attention_page_ids=tuple(item["page_id"] for item in evidence),
            )

    with SQLiteStore(tmp_path / "trial.db") as store:
        result = run_local_trial(store, LayaDecisionProvider(ranker=Ranker(), timeout_seconds=1.5))

    assert result.get("harness_error") is None
    assert result["persisted_ns"] < result["inference_started_ns"]
    assert result["inference_started_ns"] <= result["inference_finished_ns"]
    assert result["validation_started_ns"] <= result["validation_finished_ns"]
    assert result["validation_finished_ns"] <= result["admission_started_ns"]
    assert "admitted_ns" in result, result
    assert result["admission_started_ns"] <= result["admitted_ns"]
