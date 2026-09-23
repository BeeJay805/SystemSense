"""Contract tests for opt-in, same-request laptop fast-brain profiling."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    ProviderIdentity,
)


def _requests() -> tuple[DecisionRequest, ...]:
    from benchmarks.decision_provider_profile import synthetic_broad_request

    base = synthetic_broad_request()
    return tuple(
        base.model_copy(
            update={
                "correlation_id": f"laptop_fixture_{index}",
                "symptom": symptom,
            }
        )
        for index, symptom in enumerate(("Wi-Fi disconnects", "PDF turns slowly", "Game stutters"))
    )


class _CompleteProvider:
    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="fake-complete", provider_version="1", role="fast_decision"
        )

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        pages = request.attention_context or request.evidence_context
        return DecisionResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            ranked_attention_page_ids=tuple(
                f"{page.evidence_id}:{index}" for index, page in enumerate(pages)
            ),
            considered_evidence_count=len({str(page.evidence_id) for page in pages}),
        )


def test_same_hashed_requests_cold_construction_and_distinct_warm_calls() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    constructions: list[str] = []

    def factory() -> ProviderSession:
        constructions.append("constructed")
        return ProviderSession(_CompleteProvider())

    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan("first", factory, attention_required=True),
            ProviderPlan("second", factory, attention_required=True),
        ),
        deadline_ms=5_000,
        redaction_attested=True,
    )
    assert constructions == ["constructed", "constructed"]
    assert [sample["phase"] for sample in report["providers"]["first"]["samples"]] == [
        "cold",
        "warm",
        "warm",
    ]
    assert (
        report["providers"]["first"]["request_hashes"]
        == report["providers"]["second"]["request_hashes"]
    )
    assert len(set(report["providers"]["first"]["request_hashes"])) == 3
    assert report["providers"]["first"]["summary"]["complete"] == 3
    for sample in report["providers"]["first"]["samples"]:
        baseline = sample["baseline_owned_process_tree_rss_bytes"]
        peak = sample["peak_owned_process_tree_rss_bytes"]
        cpu_seconds = sample["owned_process_tree_cpu_seconds"]
        assert baseline is not None and peak is not None and peak >= baseline
        assert cpu_seconds is not None and cpu_seconds >= 0
    assert "Wi-Fi disconnects" not in str(report)


def test_deadline_coverage_and_construction_failures_remain_in_denominator() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    class _Incomplete(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return super().decide(request).model_copy(update={"ranked_attention_page_ids": ()})

    def unavailable() -> ProviderSession:
        raise RuntimeError("unavailable")

    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan(
                "coverage", lambda: ProviderSession(_Incomplete()), attention_required=True
            ),
            ProviderPlan("missing", unavailable, attention_required=True),
        ),
        deadline_ms=1,
        redaction_attested=True,
    )
    coverage = report["providers"]["coverage"]
    missing = report["providers"]["missing"]
    assert coverage["summary"]["planned"] == 3
    assert coverage["summary"]["complete"] == 0
    assert all(
        sample["status"] in {"coverage_failure", "deadline_miss"} for sample in coverage["samples"]
    )
    assert coverage["summary"]["coverage_failure"] == 3
    assert missing["summary"]["planned"] == 3
    assert [item["status"] for item in missing["samples"]] == [
        "construction_error",
        "not_run",
        "not_run",
    ]


def test_late_incomplete_response_counts_both_deadline_and_coverage() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    class _Incomplete(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return super().decide(request).model_copy(update={"ranked_attention_page_ids": ()})

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("late", lambda: ProviderSession(_Incomplete()), attention_required=True),),
        deadline_ms=0.001,
        redaction_attested=True,
    )
    result = report["providers"]["late"]
    assert result["summary"]["deadline_miss"] == 3
    assert result["summary"]["coverage_failure"] == 3
    assert all(
        sample["deadline_exceeded"] is True and sample["coverage_complete"] is False
        for sample in result["samples"]
    )


def test_none_response_is_invalid_not_unexplained_call_error() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    class _NoneProvider(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return None  # type: ignore[return-value]

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("none", lambda: ProviderSession(_NoneProvider())),),
        redaction_attested=True,
    )
    assert all(
        sample["status"] == "invalid_response" and sample["failure_type"] == "UnexpectedType"
        for sample in report["providers"]["none"]["samples"]
    )


def test_declared_laya_keyword_fallback_is_degraded_not_complete_or_invalid() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains
    from systemsense.decision.baseline import KeywordBaselineDecisionProvider

    baseline = KeywordBaselineDecisionProvider()

    class _Fallback(_CompleteProvider):
        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return baseline.decide(request).model_copy(update={"degraded": True})

    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan(
                "laya-like",
                lambda: ProviderSession(_Fallback()),
                attention_required=True,
                fallback_identity=baseline.identity,
            ),
        ),
        deadline_ms=0.001,
        redaction_attested=True,
    )
    assert report["providers"]["laya-like"]["summary"]["degraded"] == 3
    assert report["providers"]["laya-like"]["summary"]["deadline_miss"] == 3
    assert report["providers"]["laya-like"]["summary"]["complete"] == 0


def test_refuses_unattested_or_repeated_warm_workload() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    plan = (ProviderPlan("fake", lambda: ProviderSession(_CompleteProvider())),)
    with pytest.raises(ValueError, match="redaction attestation"):
        compare_fast_brains(_requests(), plan, redaction_attested=False)
    with pytest.raises(ValueError, match="distinct"):
        compare_fast_brains((_requests()[0], _requests()[0]), plan, redaction_attested=True)


def test_request_files_are_read_from_one_bounded_binary_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain

    path = tmp_path / "request.json"
    path.write_text(_requests()[0].model_dump_json(), encoding="utf-8")

    def forbidden_read_text(self: Path, *args: object, **kwargs: object) -> str:
        pytest.fail("request reader must use one bounded binary read")

    monkeypatch.setattr(Path, "read_text", forbidden_read_text)
    assert laptop_fast_brain._read_requests((path,))[0].case_id == _requests()[0].case_id  # pyright: ignore[reportPrivateUsage]


def test_laya_ram_refusal_does_not_construct_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    from benchmarks import laptop_fast_brain
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    monkeypatch.setattr(
        laptop_fast_brain.psutil, "virtual_memory", lambda: type("Memory", (), {"available": 0})()
    )

    def forbidden() -> ProviderSession:
        raise AssertionError("provider should not be constructed")

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("laya", forbidden, attention_required=True, cpu_laya=True),),
        redaction_attested=True,
    )
    assert [sample["status"] for sample in report["providers"]["laya"]["samples"]] == [
        "admission_refused",
        "not_run",
        "not_run",
    ]


def test_laya_requires_explicit_untruncated_attention_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from benchmarks import laptop_fast_brain
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    monkeypatch.setattr(
        laptop_fast_brain.psutil,
        "virtual_memory",
        lambda: type("Memory", (), {"available": 16 * 1024**3})(),
    )
    report = compare_fast_brains(
        _requests(),
        (
            ProviderPlan(
                "laya-like",
                lambda: ProviderSession(_CompleteProvider()),
                attention_required=True,
                cpu_laya=True,
            ),
        ),
        redaction_attested=True,
    )
    assert report["providers"]["laya-like"]["summary"]["coverage_failure"] == 3


def test_fast_failures_have_no_successful_latency_summary() -> None:
    from benchmarks.laptop_fast_brain import ProviderPlan, ProviderSession, compare_fast_brains

    def unavailable() -> ProviderSession:
        raise RuntimeError("unavailable")

    report = compare_fast_brains(
        _requests(),
        (ProviderPlan("missing", unavailable),),
        redaction_attested=True,
    )
    summary = report["providers"]["missing"]["summary"]
    assert summary["complete"] == 0
    assert summary["complete_wall_p95_ms"] is None
    assert summary["wall_p95_ms"] is not None
    assert report["resource_scope"] == "whole_harness_process_tree_order_confounded"


def test_cli_defaults_to_deterministic_providers_without_loading_laya(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain
    from benchmarks.laptop_fast_brain import ProviderSession

    files: list[str] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        files.extend(("--request-json", str(path)))
    output = tmp_path / "profile.json"

    def forbidden_laya(_profile: Path) -> ProviderSession:
        pytest.fail("CPU Laya must be explicit")

    monkeypatch.setattr(
        laptop_fast_brain,
        "_laya_session",
        forbidden_laya,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["laptop_fast_brain", *files, "--redaction-attested", "--output", str(output)],
    )
    laptop_fast_brain.main()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert set(report["providers"]) == {"keyword", "typed-feature"}
    assert all(item["summary"]["planned"] == 3 for item in report["providers"].values())
    assert report["ordinary_laptop_qualified"] is False


def test_isolated_workers_use_distinct_processes_and_matching_inputs(tmp_path: Path) -> None:
    from benchmarks.decision_provider_profile import catalog_sha256, request_sha256
    from benchmarks.laptop_fast_brain import compare_fast_brains_isolated

    paths: list[Path] = []
    requests = _requests()
    for index, request in enumerate(requests):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.append(path)
    report = compare_fast_brains_isolated(tuple(paths), redaction_attested=True)
    assert report["schema_version"] == 3
    assert report["resource_scope"] == "sampled_worker_tree_windows_job_custody_sequential"
    assert report["ordinary_laptop_qualified"] is False
    assert report["diagnostic_quality_measured"] is False
    assert set(report["providers"]) == {"keyword", "typed-feature"}
    pids = [record["worker_pid"] for record in report["providers"].values()]
    assert all(pid != os.getpid() for pid in pids)
    assert len(set(pids)) == 2
    expected_requests = tuple(request_sha256(request) for request in requests)
    expected_catalogs = tuple(catalog_sha256(request) for request in requests)
    for record in report["providers"].values():
        assert tuple(record["request_hashes"]) == expected_requests
        assert tuple(record["catalog_hashes"]) == expected_catalogs
        assert record["summary"]["planned"] == len(requests)


def test_supervisor_timeout_reaps_worker_and_descendant(tmp_path: Path) -> None:
    import psutil

    from benchmarks import laptop_fast_brain
    from benchmarks.laptop_fast_brain import WorkerTimeout

    child_pid_path = tmp_path / "child.pid"
    code = (
        "import pathlib,subprocess,sys,time; "
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(p.pid)); "
        "time.sleep(60)"
    )
    with pytest.raises(WorkerTimeout) as timed_out:
        laptop_fast_brain._supervise_worker((sys.executable, "-c", code), timeout_seconds=1)  # pyright: ignore[reportPrivateUsage]
    child_pid = int(child_pid_path.read_text(encoding="utf-8"))
    for _ in range(30):
        if not psutil.pid_exists(child_pid) and not psutil.pid_exists(timed_out.value.pid):
            break
        time.sleep(0.05)
    assert not psutil.pid_exists(child_pid)
    assert not psutil.pid_exists(timed_out.value.pid)


def test_oversized_worker_output_is_bounded_and_reaped() -> None:
    import psutil

    from benchmarks import laptop_fast_brain

    code = "import sys,time;sys.stdout.write('x'*1100000);sys.stdout.flush();time.sleep(60)"
    with pytest.raises(laptop_fast_brain.WorkerOutputLimit) as oversized:
        laptop_fast_brain._supervise_worker(  # pyright: ignore[reportPrivateUsage]
            (sys.executable, "-c", code), timeout_seconds=5
        )
    assert not psutil.pid_exists(oversized.value.pid)


def test_oversized_handshake_is_bounded_and_reaped() -> None:
    import psutil

    from benchmarks import laptop_fast_brain

    code = "import sys,time;sys.stdout.write('x'*5000);sys.stdout.flush();time.sleep(60)"
    with pytest.raises(laptop_fast_brain.WorkerProtocolError) as oversized:
        laptop_fast_brain._supervise_worker(  # pyright: ignore[reportPrivateUsage]
            (sys.executable, "-c", code), timeout_seconds=5, verify_handshake=True
        )
    assert not psutil.pid_exists(oversized.value.pid)


def test_invalid_utf8_stdout_is_a_failed_worker() -> None:
    from benchmarks import laptop_fast_brain

    code = "import sys;sys.stdout.buffer.write(bytes([255]));sys.stdout.flush()"
    with pytest.raises(laptop_fast_brain.WorkerOutputDecodeError):
        laptop_fast_brain._supervise_worker(  # pyright: ignore[reportPrivateUsage]
            (sys.executable, "-c", code), timeout_seconds=5
        )


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object custody")
def test_normal_worker_exit_reaps_lingering_child(tmp_path: Path) -> None:
    import psutil

    from benchmarks import laptop_fast_brain

    child_pid_path = tmp_path / "normal-child.pid"
    code = (
        "import pathlib,subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(p.pid)); "
        "print('done',flush=True)"
    )
    try:
        output, _launcher_pid, exit_code, _worker_pid = laptop_fast_brain._supervise_worker(  # pyright: ignore[reportPrivateUsage]
            (sys.executable, "-c", code), timeout_seconds=5
        )
        assert output.strip() == "done"
        assert exit_code == 0
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        for _ in range(40):
            if not psutil.pid_exists(child_pid):
                break
            time.sleep(0.05)
        assert not psutil.pid_exists(child_pid)
    finally:
        if child_pid_path.exists():
            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            if psutil.pid_exists(child_pid):
                psutil.Process(child_pid).kill()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object custody")
def test_timeout_reaps_children_spawned_near_deadline(tmp_path: Path) -> None:
    import psutil

    from benchmarks import laptop_fast_brain

    child_pids_path = tmp_path / "late-children.txt"
    code = (
        "import pathlib,subprocess,sys,time; "
        f"p=pathlib.Path({str(child_pids_path)!r}); "
        "[(p.open('a').write(str(subprocess.Popen([sys.executable,'-c',"
        "'import time;time.sleep(60)']).pid)+'\\n'),time.sleep(.2)) "
        "for _ in range(4)]; time.sleep(60)"
    )
    try:
        with pytest.raises(laptop_fast_brain.WorkerTimeout):
            laptop_fast_brain._supervise_worker(  # pyright: ignore[reportPrivateUsage]
                (sys.executable, "-c", code), timeout_seconds=2
            )
        child_pids = [int(pid) for pid in child_pids_path.read_text(encoding="utf-8").splitlines()]
        assert len(child_pids) >= 2
        for _ in range(40):
            if all(not psutil.pid_exists(pid) for pid in child_pids):
                break
            time.sleep(0.05)
        assert all(not psutil.pid_exists(pid) for pid in child_pids)
    finally:
        if child_pids_path.exists():
            for pid_text in child_pids_path.read_text(encoding="utf-8").splitlines():
                pid = int(pid_text)
                if psutil.pid_exists(pid):
                    psutil.Process(pid).kill()


def test_supervisor_cancellation_reaps_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    import psutil

    from benchmarks import laptop_fast_brain

    worker_pid: list[int] = []

    def interrupted_read(worker: subprocess.Popen[str], timeout_seconds: float) -> str:
        worker_pid.append(worker.pid)
        raise KeyboardInterrupt

    monkeypatch.setattr(laptop_fast_brain, "_read_worker_output", interrupted_read)
    with pytest.raises(KeyboardInterrupt):
        laptop_fast_brain._supervise_worker(  # pyright: ignore[reportPrivateUsage]
            (sys.executable, "-c", "import time;time.sleep(60)"), timeout_seconds=5
        )
    assert worker_pid and not psutil.pid_exists(worker_pid[0])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Object custody")
def test_job_assignment_refuses_changed_process_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    import win32con
    import win32job

    from benchmarks import laptop_fast_brain

    worker = subprocess.Popen(
        (sys.executable, "-c", "import time;time.sleep(60)"),
        creationflags=win32con.CREATE_SUSPENDED,
        text=True,
    )
    job = laptop_fast_brain._WindowsJob()  # pyright: ignore[reportPrivateUsage]

    def forbidden_assign(*args: object, **kwargs: object) -> None:
        pytest.fail("identity mismatch must be rejected before job assignment")

    monkeypatch.setattr(win32job, "AssignProcessToJobObject", forbidden_assign)
    try:
        original = laptop_fast_brain.psutil.Process(worker.pid).create_time()
        with pytest.raises(ValueError, match="PID was reused"):
            job.assign_and_resume(
                worker, laptop_fast_brain.ProcessIdentity(worker.pid, original + 1)
            )
    finally:
        worker.kill()
        job.close()
        worker.wait(timeout=5)


def test_unconfirmed_cleanup_skips_later_providers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain

    paths: list[Path] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.append(path)

    def failed_cleanup(*args: object, **kwargs: object) -> object:
        raise laptop_fast_brain.WorkerCleanupError(12345, (12346,), "AccessDenied")

    monkeypatch.setattr(laptop_fast_brain, "_supervise_worker", failed_cleanup)
    report = laptop_fast_brain.compare_fast_brains_isolated(tuple(paths), redaction_attested=True)
    first = report["providers"]["keyword"]
    assert first["worker_pid"] == 12345
    assert first["worker_cleanup_confirmed"] is False
    assert first["worker_cleanup_alive_pids"] == (12346,)
    assert first["worker_cleanup_error_type"] == "AccessDenied"
    assert first["summary"]["planned"] == 3
    assert all(
        sample["status"] == "not_run" for sample in report["providers"]["typed-feature"]["samples"]
    )


def test_output_limit_keeps_all_requests_in_failure_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain

    paths: list[Path] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.append(path)

    def too_much_output(*args: object, **kwargs: object) -> object:
        raise laptop_fast_brain.WorkerOutputLimit(12345)

    monkeypatch.setattr(laptop_fast_brain, "_supervise_worker", too_much_output)
    report = laptop_fast_brain.compare_fast_brains_isolated(tuple(paths), redaction_attested=True)
    for record in report["providers"].values():
        assert record["summary"]["planned"] == 3
        assert record["summary"]["complete"] == 0
        assert record["worker_cleanup_confirmed"] is True
        assert all(sample["failure_type"] == "WorkerOutputLimit" for sample in record["samples"])


def test_rejects_reported_pid_outside_launched_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain

    paths: list[Path] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.append(path)
    real_supervise = laptop_fast_brain._supervise_worker  # pyright: ignore[reportPrivateUsage]

    def forged_pid(
        command: tuple[str, ...], *, timeout_seconds: float, verify_handshake: bool
    ) -> tuple[str, int, int, int | None]:
        output, pid, exit_code, verified_pid = real_supervise(
            command, timeout_seconds=timeout_seconds, verify_handshake=verify_handshake
        )
        payload = json.loads(output)
        payload["worker_pid"] = -1
        return json.dumps(payload), pid, exit_code, verified_pid

    monkeypatch.setattr(laptop_fast_brain, "_supervise_worker", forged_pid)
    report = laptop_fast_brain.compare_fast_brains_isolated(tuple(paths), redaction_attested=True)
    assert report["providers"]["keyword"]["summary"]["other_failure_or_not_run"] == 3
    assert report["providers"]["keyword"]["samples"][0]["failure_type"] == "InvalidWorkerReport"


@pytest.mark.parametrize(
    "corruption",
    (
        "sample_hash",
        "summary",
        "provider_id",
        "degraded_complete",
        "late_complete",
        "ranked_overflow",
        "considered_overflow",
        "proposal_overflow",
    ),
)
def test_invalid_worker_sample_or_summary_is_not_counted_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    from benchmarks import laptop_fast_brain

    paths: list[Path] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.append(path)
    real_supervise = laptop_fast_brain._supervise_worker  # pyright: ignore[reportPrivateUsage]

    def corrupt_record(
        command: tuple[str, ...], *, timeout_seconds: float, verify_handshake: bool
    ) -> tuple[str, int, int, int | None]:
        output, pid, exit_code, verified_pid = real_supervise(
            command, timeout_seconds=timeout_seconds, verify_handshake=verify_handshake
        )
        payload = json.loads(output)
        if corruption == "sample_hash":
            payload["record"]["samples"][0]["request_sha256"] = "wrong"
        elif corruption == "summary":
            payload["record"]["summary"]["complete"] = 999
        elif corruption == "degraded_complete":
            payload["record"]["samples"][0]["response_degraded"] = True
        elif corruption == "late_complete":
            payload["record"]["samples"][0]["wall_ms"] = 3_001.0
            payload["record"]["summary"] = laptop_fast_brain._summary(  # pyright: ignore[reportPrivateUsage]
                payload["record"]["samples"]
            )
        elif corruption == "ranked_overflow":
            sample = payload["record"]["samples"][0]
            sample["ranked_pages"] = sample["supplied_pages"] + 1
        elif corruption == "considered_overflow":
            sample = payload["record"]["samples"][0]
            pages = _requests()[0].attention_context or _requests()[0].evidence_context
            sample["considered_evidence"] = len({str(page.evidence_id) for page in pages}) + 1
        elif corruption == "proposal_overflow":
            payload["record"]["samples"][0]["proposal_count"] = _requests()[0].max_probes + 1
        else:
            payload["record"]["provider_id"] = "forged-provider"
        return json.dumps(payload), pid, exit_code, verified_pid

    monkeypatch.setattr(laptop_fast_brain, "_supervise_worker", corrupt_record)
    report = laptop_fast_brain.compare_fast_brains_isolated(tuple(paths), redaction_attested=True)
    assert all(record["summary"]["complete"] == 0 for record in report["providers"].values())
    assert report["providers"]["keyword"]["samples"][0]["failure_type"] == "InvalidWorkerReport"


@pytest.mark.parametrize(
    "corruption",
    ("coverage_flag", "ranked_underflow", "considered_underflow", "contradictory_coverage"),
)
def test_typed_complete_without_attention_coverage_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    from benchmarks import laptop_fast_brain

    paths: list[Path] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.append(path)
    real_supervise = laptop_fast_brain._supervise_worker  # pyright: ignore[reportPrivateUsage]

    def incomplete_coverage(
        command: tuple[str, ...], *, timeout_seconds: float, verify_handshake: bool
    ) -> tuple[str, int, int, int | None]:
        output, pid, exit_code, verified_pid = real_supervise(
            command, timeout_seconds=timeout_seconds, verify_handshake=verify_handshake
        )
        if "typed-feature" in command:
            payload = json.loads(output)
            sample = payload["record"]["samples"][0]
            if corruption == "coverage_flag":
                sample["coverage_complete"] = False
            elif corruption == "ranked_underflow":
                sample["ranked_pages"] -= 1
            elif corruption == "considered_underflow":
                sample["considered_evidence"] -= 1
            else:
                sample["ranked_pages"] -= 1
                sample["status"] = "coverage_failure"
                payload["record"]["summary"] = laptop_fast_brain._summary(  # pyright: ignore[reportPrivateUsage]
                    payload["record"]["samples"]
                )
            output = json.dumps(payload)
        return output, pid, exit_code, verified_pid

    monkeypatch.setattr(laptop_fast_brain, "_supervise_worker", incomplete_coverage)
    report = laptop_fast_brain.compare_fast_brains_isolated(tuple(paths), redaction_attested=True)
    assert report["providers"]["keyword"]["summary"]["complete"] == 3
    assert report["providers"]["typed-feature"]["summary"]["complete"] == 0
    assert (
        report["providers"]["typed-feature"]["samples"][0]["failure_type"] == "InvalidWorkerReport"
    )


def test_hash_mismatch_invalidates_isolated_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain

    paths: list[Path] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.append(path)
    real_supervise = laptop_fast_brain._supervise_worker  # pyright: ignore[reportPrivateUsage]

    def changed_hash(
        command: tuple[str, ...], *, timeout_seconds: float, verify_handshake: bool
    ) -> tuple[str, int, int, int | None]:
        output, pid, exit_code, verified_pid = real_supervise(
            command, timeout_seconds=timeout_seconds, verify_handshake=verify_handshake
        )
        payload = json.loads(output)
        payload["record"]["request_hashes"][0] = "changed"
        return json.dumps(payload), pid, exit_code, verified_pid

    monkeypatch.setattr(laptop_fast_brain, "_supervise_worker", changed_hash)
    with pytest.raises(laptop_fast_brain.InputMismatch, match="request hashes mismatch"):
        laptop_fast_brain.compare_fast_brains_isolated(tuple(paths), redaction_attested=True)


def test_isolated_cli_preserves_existing_output_and_requires_attestation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain

    paths: list[str] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        paths.extend(("--request-json", str(path)))
    output = tmp_path / "profile.json"
    monkeypatch.setattr(
        sys, "argv", ["laptop_fast_brain", *paths, "--isolated-processes", "--output", str(output)]
    )
    with pytest.raises(SystemExit):
        laptop_fast_brain.main()
    assert not output.exists()
    output.write_text("existing", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "laptop_fast_brain",
            *paths,
            "--isolated-processes",
            "--redaction-attested",
            "--output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit):
        laptop_fast_brain.main()
    assert output.read_text(encoding="utf-8") == "existing"


def test_isolated_cli_writes_only_the_requested_new_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laptop_fast_brain

    files: list[str] = []
    for index, request in enumerate(_requests()):
        path = tmp_path / f"request-{index}.json"
        path.write_text(request.model_dump_json(), encoding="utf-8")
        files.extend(("--request-json", str(path)))
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "laptop_fast_brain",
            *files,
            "--isolated-processes",
            "--redaction-attested",
            "--output",
            str(output),
        ],
    )
    laptop_fast_brain.main()
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["schema_version"] == 3
    assert set(report["providers"]) == {"keyword", "typed-feature"}
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "report.json",
        "request-0.json",
        "request-1.json",
        "request-2.json",
    ]
