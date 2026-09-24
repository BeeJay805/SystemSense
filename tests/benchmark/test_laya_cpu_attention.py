"""The CPU feasibility fixture is bounded and never treated as IT ground truth."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast

import pytest

import benchmarks.laya_cpu_attention as benchmark
from benchmarks.laya_cpu_attention import representative_batch
from systemsense.application.bootstrap import default_capabilities
from systemsense.inference.laya_runtime import (
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
    LayaWorkerPresentation,
)


class _CountingRuntime(LayaSubprocessRuntime):
    def __init__(self, config: LayaRuntimeConfig) -> None:
        super().__init__(config)
        self.calls: list[tuple[dict[str, object], tuple[dict[str, str], ...]]] = []

    def rank(
        self,
        *,
        state: dict[str, object],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
        capture_exact_worker_call: Callable[[dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> tuple[str, ...]:
        assert timeout_seconds > 0
        assert capture_exact_worker_call is None
        self.calls.append((state, candidates))
        self._last_relevance_scores = {item["probe_id"]: 0.5 for item in candidates}
        self._last_token_provenance = {
            "state_truncated": False,
            "instruction_truncated_items": 0,
        }
        return tuple(item["probe_id"] for item in candidates)


class _ProfileConfig:
    def __init__(self, batch_size: int = 4) -> None:
        self.max_candidates_per_batch = batch_size
        self.device = "cpu"
        self.precision = "float32"
        self.threads = 2

    def model_copy(self, *, update: dict[str, object]) -> _ProfileConfig:
        batch_size = update.get("max_candidates_per_batch", self.max_candidates_per_batch)
        assert isinstance(batch_size, int)
        return _ProfileConfig(batch_size)

    def validate_install(self) -> SimpleNamespace:
        return SimpleNamespace(
            model_repository="local-test",
            model_revision="pinned-test",
            weight_sha256="a" * 64,
            package_version="0.3.5",
            torch_version="test",
            transformers_version="test",
        )


class _SweepRuntime:
    sessions: ClassVar[list[_SweepRuntime]] = []

    def __init__(self, config: _ProfileConfig) -> None:
        self.batch_size = config.max_candidates_per_batch
        self.calls: list[str] = []
        self._process: _FakeWorker | None = None
        self.sessions.append(self)

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> SimpleNamespace:
        assert timeout_seconds > 0
        symptom = str(state["symptom"])
        self.calls.append(symptom)
        if self._process is None:
            self._process = _FakeWorker()
        return SimpleNamespace(
            considered_attention_page_ids=tuple(item["page_id"] for item in evidence),
            considered_probe_ids=tuple(item["probe_id"] for item in candidates),
            ranked_probe_ids=tuple(item["probe_id"] for item in candidates),
            attention_notes=(
                "coverage_limited=false",
                "state_truncated_batches=0",
                "instruction_truncated_items=0",
            ),
        )

    def close(self) -> None:
        if self._process is not None:
            self._process.stopped = True
            self._process = None

    def replace_owned_worker(self) -> None:
        self._process = _FakeWorker()


class _FakeWorker:
    def __init__(self) -> None:
        self.stopped = False

    def poll(self) -> int | None:
        return 0 if self.stopped else None

    def wait(self, timeout: float | None = None) -> int:
        assert timeout is not None
        if not self.stopped:
            raise TimeoutError("worker still alive")
        return 0


def _install_fake_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    _SweepRuntime.sessions = []
    monkeypatch.setattr(
        benchmark.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=9 * 1024**3, total=16 * 1024**3),
    )

    def fake_profile(_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            laya=SimpleNamespace(enabled=True, runtime_config=_ProfileConfig),
        )

    monkeypatch.setattr(
        benchmark,
        "load_inference_profile",
        fake_profile,
    )
    monkeypatch.setattr(benchmark, "LayaSubprocessRuntime", _SweepRuntime)


def test_representative_batch_covers_distinct_preview_pages_and_real_probe_catalog() -> None:
    state, evidence, candidates = representative_batch("A game feels slow")

    assert state["coverage_notes"] == (
        "evidence_pages_are_bounded_previews",
        "synthetic_runtime_only",
    )
    assert len(evidence) == 54
    assert len({item["page_id"] for item in evidence}) == 54
    assert len({item["fragment_id"] for item in evidence}) == 54
    assert all(len(item["description"]) <= 650 for item in evidence)
    assert all(
        json.loads(item["description"])["projection"] == "bounded_preview_not_full_page"
        for item in evidence
    )
    assert {item["probe_id"] for item in candidates} == {
        capability.probe_id for capability in default_capabilities()
    }


def test_measure_refuses_to_overwrite_existing_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "report.json"
    output.write_text("preserved", encoding="utf-8")
    monkeypatch.setattr(
        benchmark.psutil, "virtual_memory", lambda: SimpleNamespace(available=9 * 1024**3)
    )
    with pytest.raises(FileExistsError):
        benchmark.measure(tmp_path / "unused-profile.json", output)
    assert output.read_text(encoding="utf-8") == "preserved"


def test_batch_twenty_covers_exact_preview_and_probe_ids_in_four_requests(
    tmp_path: Path,
) -> None:
    runtime = _CountingRuntime(
        LayaRuntimeConfig(
            interpreter_path=tmp_path / "python.exe",
            model_path=tmp_path / "model",
            max_candidates_per_batch=20,
        )
    )
    state, evidence, candidates = representative_batch("PDF pages are slow")

    result = runtime.attend(
        state=state, evidence=evidence, candidates=candidates, timeout_seconds=2
    )

    assert len(runtime.calls) == 4
    assert [len(items) for _state, items in runtime.calls] == [20, 20, 14, 17]
    assert set(result.considered_attention_page_ids) == {item["page_id"] for item in evidence}
    assert set(result.considered_probe_ids) == {item["probe_id"] for item in candidates}
    assert "previews_considered=54_of_54" in result.attention_notes
    assert "coverage_limited=false" in result.attention_notes
    assert "state_truncated_batches=0" in result.attention_notes
    assert "instruction_truncated_items=0" in result.attention_notes


def test_cpu_sweep_counterbalances_batches_and_preserves_write_once_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)
    output = tmp_path / "sweep.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["classification"] == "host_cpu_synthetic_batch_sweep_only"
    assert report["ordinary_laptop_qualified"] is False
    assert report["diagnostic_accuracy_claim"] is False
    assert report["status"] == "complete"
    assert report["batch_orders"] == [[4, 8, 20], [8, 20, 4], [20, 4, 8]]
    runs = cast(list[dict[str, object]], report["runs"])
    assert len(runs) == 18
    assert all(run["status"] == "complete" for run in runs)
    assert all(run["pages_considered"] == 54 and run["probes_considered"] == 17 for run in runs)
    assert all(cast(int, run["peak_owned_process_tree_rss_bytes"]) > 0 for run in runs)
    assert [session.batch_size for session in _SweepRuntime.sessions] == [
        4,
        8,
        20,
        8,
        20,
        4,
        20,
        4,
        8,
    ]
    assert all(len(session.calls) == 2 for session in _SweepRuntime.sessions)
    assert json.loads(output.read_text(encoding="utf-8")) == report
    with pytest.raises(FileExistsError):
        benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)


def test_cpu_sweep_records_deadline_failure_instead_of_omitting_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)
    original_attend = _SweepRuntime.attend

    def deadline_on_warm_twenty(self: _SweepRuntime, **kwargs: Any) -> SimpleNamespace:
        if self.batch_size == 20 and "warm" in str(kwargs["state"]["symptom"]):
            raise LayaRuntimeError("Laya attention deadline expired before full coverage")
        return original_attend(self, **kwargs)

    monkeypatch.setattr(_SweepRuntime, "attend", deadline_on_warm_twenty)
    output = tmp_path / "failed.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["status"] == "interrupted_or_unsafe"
    runs = cast(list[dict[str, object]], report["runs"])
    assert len(runs) == 18
    failed = [run for run in runs if run["status"] == "failed"]
    assert len(failed) == 1
    assert all(run["phase"] == "warm" and run["batch_size"] == 20 for run in failed)
    assert all(run["failure_type"] == "LayaRuntimeError" for run in failed)
    assert sum(run["status"] == "not_run" for run in runs) == 12
    assert json.loads(output.read_text(encoding="utf-8")) == report


def test_cpu_sweep_reserves_durable_progress_before_first_model_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)
    output = tmp_path / "progress.json"
    original_attend = _SweepRuntime.attend
    checked = False

    def check_progress(self: _SweepRuntime, **kwargs: Any) -> SimpleNamespace:
        nonlocal checked
        if not checked:
            progress = json.loads(output.read_text(encoding="utf-8"))
            assert progress["status"] == "in_progress"
            assert progress["runs"] == []
            checked = True
        return original_attend(self, **kwargs)

    monkeypatch.setattr(_SweepRuntime, "attend", check_progress)

    benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert checked


def test_cpu_sweep_preserves_completed_and_interrupted_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)
    output = tmp_path / "interrupted.json"
    original_attend = _SweepRuntime.attend
    calls = 0

    def interrupt_second(self: _SweepRuntime, **kwargs: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        if calls == 2:
            progress = json.loads(output.read_text(encoding="utf-8"))
            assert len(progress["runs"]) == 1
            raise KeyboardInterrupt
        return original_attend(self, **kwargs)

    monkeypatch.setattr(_SweepRuntime, "attend", interrupt_second)

    with pytest.raises(KeyboardInterrupt):
        benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    progress = json.loads(output.read_text(encoding="utf-8"))
    assert progress["status"] == "interrupted_or_unsafe"
    assert len(progress["runs"]) == 18
    assert progress["runs"][0]["status"] == "complete"
    assert progress["runs"][1]["failure_type"] == "KeyboardInterrupt"
    assert all(run["status"] == "not_run" for run in progress["runs"][2:])


def test_cpu_sweep_rejects_duplicate_coverage_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)
    original_attend = _SweepRuntime.attend

    def duplicate_one_page(self: _SweepRuntime, **kwargs: Any) -> SimpleNamespace:
        result = original_attend(self, **kwargs)
        if self.batch_size == 8:
            result.considered_attention_page_ids += (result.considered_attention_page_ids[0],)
        return result

    monkeypatch.setattr(_SweepRuntime, "attend", duplicate_one_page)
    output = tmp_path / "duplicates.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["status"] == "failed"
    runs = cast(list[dict[str, object]], report["runs"])
    duplicate_runs = [run for run in runs if run["batch_size"] == 8 and run["status"] == "failed"]
    assert len(duplicate_runs) == 1
    assert duplicate_runs[0]["failure_type"] == "IncompleteCoverage"
    assert sum(run["status"] == "not_run" for run in runs) == 15


def test_cpu_sweep_stops_after_cold_startup_failure_without_a_warm_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)

    def fail_cold(self: _SweepRuntime, **_kwargs: Any) -> SimpleNamespace:
        raise LayaRuntimeError("Laya cold worker exceeded its request deadline")

    monkeypatch.setattr(_SweepRuntime, "attend", fail_cold)
    output = tmp_path / "cold-failure.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["status"] == "interrupted_or_unsafe"
    runs = cast(list[dict[str, object]], report["runs"])
    assert len(runs) == 18
    assert runs[0]["phase"] == "cold" and runs[0]["failure_type"] == "LayaRuntimeError"
    assert runs[1]["phase"] == "warm" and runs[1]["status"] == "not_run"
    assert all(run["status"] == "not_run" for run in runs[1:])
    assert len(_SweepRuntime.sessions) == 1
    assert json.loads(output.read_text(encoding="utf-8")) == report


@pytest.mark.parametrize(
    ("defect", "failure_type"),
    [
        ("state_truncation", "IncompleteModelInput"),
        ("instruction_truncation", "IncompleteModelInput"),
        ("duplicate_ranked_probe", "InvalidRankedProbeIds"),
    ],
)
def test_cpu_sweep_fails_closed_on_incomplete_or_invalid_model_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
    failure_type: str,
) -> None:
    _install_fake_sweep(monkeypatch)
    original_attend = _SweepRuntime.attend

    def invalid_first_result(self: _SweepRuntime, **kwargs: Any) -> SimpleNamespace:
        result = original_attend(self, **kwargs)
        if defect == "state_truncation":
            result.attention_notes = ("state_truncated_batches=1", "instruction_truncated_items=0")
        elif defect == "instruction_truncation":
            result.attention_notes = ("state_truncated_batches=0", "instruction_truncated_items=1")
        else:
            result.ranked_probe_ids += (result.ranked_probe_ids[0],)
        return result

    monkeypatch.setattr(_SweepRuntime, "attend", invalid_first_result)
    output = tmp_path / f"{defect}.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["status"] == "failed"
    runs = cast(list[dict[str, object]], report["runs"])
    assert runs[0]["failure_type"] == failure_type
    assert all(run["status"] == "not_run" for run in runs[1:])


def test_cpu_sweep_rejects_worker_restart_between_cold_and_warm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)
    original_attend = _SweepRuntime.attend

    def restart_on_warm(self: _SweepRuntime, **kwargs: Any) -> SimpleNamespace:
        if "warm" in str(kwargs["state"]["symptom"]):
            self.replace_owned_worker()
        return original_attend(self, **kwargs)

    monkeypatch.setattr(_SweepRuntime, "attend", restart_on_warm)
    output = tmp_path / "restart.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["status"] == "interrupted_or_unsafe"
    runs = cast(list[dict[str, object]], report["runs"])
    assert runs[0]["status"] == "complete"
    assert runs[1]["failure_type"] == "WorkerIdentityChanged"
    assert all(run["status"] == "not_run" for run in runs[2:])


def test_cpu_sweep_rechecks_ram_before_each_new_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)
    available = 9 * 1024**3

    def memory() -> SimpleNamespace:
        return SimpleNamespace(available=available, total=16 * 1024**3)

    original_close = _SweepRuntime.close

    def drop_ram_after_first(self: _SweepRuntime) -> None:
        nonlocal available
        original_close(self)
        available = 7 * 1024**3

    monkeypatch.setattr(benchmark.psutil, "virtual_memory", memory)
    monkeypatch.setattr(_SweepRuntime, "close", drop_ram_after_first)
    output = tmp_path / "ram-drop.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["status"] == "interrupted_or_unsafe"
    assert report["stop_reason"] == "InsufficientAvailableRam"
    runs = cast(list[dict[str, object]], report["runs"])
    assert runs[0]["status"] == runs[1]["status"] == "complete"
    assert all(run["status"] == "not_run" for run in runs[2:])
    assert len(_SweepRuntime.sessions) == 1


def test_cpu_sweep_stops_on_unverified_worker_teardown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_sweep(monkeypatch)

    def leave_worker_alive(_self: _SweepRuntime) -> None:
        return None

    monkeypatch.setattr(_SweepRuntime, "close", leave_worker_alive)
    output = tmp_path / "teardown.json"

    report = benchmark.measure_sweep(tmp_path / "profile.json", output, timeout_seconds=2)

    assert report["status"] == "interrupted_or_unsafe"
    assert report["stop_reason"] == "WorkerTeardownUnverified"
    runs = cast(list[dict[str, object]], report["runs"])
    assert runs[0]["status"] == runs[1]["status"] == "complete"
    assert all(run["status"] == "not_run" for run in runs[2:])
    assert len(_SweepRuntime.sessions) == 1
