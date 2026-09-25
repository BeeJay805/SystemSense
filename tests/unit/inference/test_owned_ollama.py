"""The owned server stays suspended until external lifetime admission succeeds."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from systemsense.inference.ollama import LocalInferenceError
from systemsense.inference.owned_ollama import (
    OwnedOllamaConfig,
    OwnedOllamaError,
    OwnedOllamaService,
    launch_owned_ollama,
)


def test_owned_launch_passes_required_windows_directories_without_inheriting_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, _ = _setup(tmp_path)
    captured: dict[str, Any] = {}
    for name in ("SystemRoot", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
        directory = tmp_path / name
        directory.mkdir()
        monkeypatch.setenv(name, str(directory))
    monkeypatch.setenv("SECRET_PROBE", "do-not-inherit")

    def fake_popen(*args: Any, **kwargs: Any) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("systemsense.inference.owned_ollama.subprocess.Popen", fake_popen)
    launch_owned_ollama(config)
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["USERPROFILE"] == str(tmp_path / "USERPROFILE")
    assert env["APPDATA"] == str(tmp_path / "APPDATA")
    assert env["LOCALAPPDATA"] == str(tmp_path / "LOCALAPPDATA")
    assert env["TEMP"] == str(tmp_path / "TEMP")
    assert env["TMP"] == str(tmp_path / "TMP")
    assert env["HOME"] == env["USERPROFILE"]
    assert env["OLLAMA_NO_CLOUD"] == "1"
    assert "SECRET_PROBE" not in env


def test_listener_can_precede_ready_model_tags(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    process = FakeProcess()
    events: list[str] = []
    job = FakeJob(events)
    attempts = 0

    def listeners() -> list[Any]:
        if "resume" not in events:
            return []
        return [SimpleNamespace(laddr=("127.0.0.1", 12434), status="LISTEN", pid=4321)]

    def inspect() -> bytes:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise LocalInferenceError("local Ollama request exceeded its total deadline")
        return b'{"models":[{"name":"qwen3.8:27b","digest":"' + b"a" * 64 + b'"}]}'

    def launch(_config: OwnedOllamaConfig) -> FakeProcess:
        return process

    service = OwnedOllamaService(
        config,
        admit=_allow,
        finalize_admission=_finalize,
        launcher=launch,
        job_factory=lambda: job,
        listeners=listeners,
        owns_listener=_owned,
        inspect_models=inspect,
        verify_process=_verified,
    )
    service.start()
    assert attempts == 2
    assert service.ready
    assert service.close().tree_exit_verified


def test_unready_model_tags_still_end_at_startup_deadline(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    process = FakeProcess()
    events: list[str] = []
    job = FakeJob(events)

    def listeners() -> list[Any]:
        if "resume" not in events:
            return []
        return [SimpleNamespace(laddr=("127.0.0.1", 12434), status="LISTEN", pid=4321)]

    def inspect() -> bytes:
        raise LocalInferenceError("local Ollama request exceeded its total deadline")

    def launch(_config: OwnedOllamaConfig) -> FakeProcess:
        return process

    service = OwnedOllamaService(
        config,
        admit=_allow,
        finalize_admission=_finalize,
        launcher=launch,
        job_factory=lambda: job,
        listeners=listeners,
        owns_listener=_owned,
        inspect_models=inspect,
        verify_process=_verified,
    )
    with pytest.raises(OwnedOllamaError, match="owned Ollama startup timed out") as error:
        service.start()
    assert error.value.tree_exit_verified
    assert service.close().tree_exit_verified


class FakeProcess:
    pid = 4321
    _handle = 77

    def __init__(self) -> None:
        self.exited = False

    def poll(self) -> int | None:
        return 1 if self.exited else None

    def kill(self) -> None:
        self.exited = True

    def wait(self, timeout: float) -> int:
        self.exited = True
        return 1


class FakeJob:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.assigned = False
        self.empty = True

    def assign_suspended(self, process: FakeProcess) -> None:
        self.events.append("assign")
        self.assigned = True
        self.empty = False

    def resume_assigned(self, process: FakeProcess) -> None:
        self.events.append("resume")

    def is_assigned_worker(self, process: FakeProcess) -> bool:
        return self.assigned

    def terminate_processes(self) -> None:
        self.events.append("terminate")
        self.empty = True

    def wait_until_empty(self, timeout_seconds: float) -> bool:
        self.events.append("verify")
        return self.empty

    def close(self) -> None:
        self.events.append("job_close")


def _allow(_process: Any, _job: Any) -> bool:
    return True


def _deny(_process: Any, _job: Any) -> bool:
    return False


def _verified(_process: Any, _path: Path) -> bool:
    return True


def _owned(_job: Any, _process: Any, _pid: int) -> bool:
    return True


def _finalize(_verified: bool, _job: Any | None, _process: Any | None) -> bool:
    return True


def _setup(tmp_path: Path, *, digest: str | None = None) -> tuple[OwnedOllamaConfig, Path]:
    binary = tmp_path / "ollama.exe"
    binary.write_bytes(b"pinned executable")
    models = tmp_path / "models"
    models.mkdir()
    return (
        OwnedOllamaConfig(
            executable=binary,
            executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            models_dir=models,
            endpoint="http://127.0.0.1:12434/api/chat",
            model="qwen3.8:27b",
            model_digest=digest or "a" * 64,
            startup_timeout_seconds=0.1,
            exit_timeout_seconds=0.1,
        ),
        binary,
    )


def test_admission_precedes_resume_and_model_inspection(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    events: list[str] = []
    process = FakeProcess()
    job = FakeJob(events)

    def launch(*args: Any, **kwargs: Any) -> FakeProcess:
        events.append("launch")
        return process

    def admit(*args: Any) -> bool:
        events.append("admit")
        assert job.assigned
        return True

    def listeners() -> list[Any]:
        events.append("listeners")
        if "resume" not in events:
            return []
        return [SimpleNamespace(laddr=("127.0.0.1", 12434), status="LISTEN", pid=4321)]

    def inspect() -> bytes:
        events.append("inspect")
        return b'{"models":[{"name":"qwen3.8:27b","digest":"' + b"a" * 64 + b'"}]}'

    def finalize(verified: bool, _job: Any | None, _process: Any | None) -> bool:
        events.append("finalize")
        assert verified
        assert "job_close" not in events
        return True

    service = OwnedOllamaService(
        config,
        admit=admit,
        finalize_admission=finalize,
        launcher=launch,
        job_factory=lambda: job,
        listeners=listeners,
        owns_listener=_owned,
        inspect_models=inspect,
        verify_process=_verified,
    )
    service.start()
    assert events.index("assign") < events.index("admit") < events.index("resume")
    assert events.index("resume") < events.index("inspect")
    assert service.ready
    closed = service.close()
    assert closed.tree_exit_verified and closed.admission_finalized
    assert events.index("verify") < events.index("finalize") < events.index("job_close")


def test_denied_admission_never_resumes_or_inspects(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    events: list[str] = []
    job = FakeJob(events)
    service = OwnedOllamaService(
        config,
        admit=_deny,
        finalize_admission=_finalize,
        launcher=lambda *_, **__: FakeProcess(),
        job_factory=lambda: job,
        listeners=lambda: [],
        owns_listener=_owned,
        inspect_models=lambda: events.append("inspect") or b"{}",
        verify_process=_verified,
    )
    with pytest.raises(OwnedOllamaError, match="admission denied") as exc:
        service.start()
    assert exc.value.tree_exit_verified
    assert "resume" not in events and "inspect" not in events


def test_existing_listener_prevents_launch(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    service = OwnedOllamaService(
        config,
        admit=_allow,
        finalize_admission=_finalize,
        launcher=lambda *_, **__: pytest.fail("must not launch"),
        listeners=lambda: [SimpleNamespace(laddr=("127.0.0.1", 12434), status="LISTEN", pid=99)],
    )
    with pytest.raises(OwnedOllamaError, match="already has a listener"):
        service.start()


def test_wrong_digest_and_unowned_listener_fail_closed(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)

    def check(owned: bool, digest: str) -> None:
        events: list[str] = []
        job = FakeJob(events)

        def listeners() -> list[Any]:
            if "resume" not in events:
                return []
            return [SimpleNamespace(laddr=("127.0.0.1", 12434), status="LISTEN", pid=4321)]

        def owns_listener(_job: Any, _process: Any, _pid: int) -> bool:
            return owned

        def inspect() -> bytes:
            return b'{"models":[{"name":"qwen3.8:27b","digest":"' + digest.encode() + b'"}]}'

        service = OwnedOllamaService(
            config,
            admit=_allow,
            finalize_admission=_finalize,
            launcher=lambda *_, **__: FakeProcess(),
            job_factory=lambda: job,
            listeners=listeners,
            owns_listener=owns_listener,
            inspect_models=inspect,
            verify_process=_verified,
        )
        with pytest.raises(OwnedOllamaError) as exc:
            service.start()
        assert exc.value.tree_exit_verified

    check(False, "a" * 64)
    check(True, "b" * 64)


def test_uncertain_exit_is_visible(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    events: list[str] = []
    job = FakeJob(events)
    job.wait_until_empty = lambda _: False  # type: ignore[method-assign]
    service = OwnedOllamaService(
        config,
        admit=_deny,
        finalize_admission=_finalize,
        launcher=lambda *_, **__: FakeProcess(),
        job_factory=lambda: job,
        listeners=lambda: [],
        verify_process=_verified,
    )
    with pytest.raises(OwnedOllamaError) as exc:
        service.start()
    assert not exc.value.tree_exit_verified
    assert not service.close().tree_exit_verified


def test_lost_assignment_after_resume_never_uses_root_only_exit_proof(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    events: list[str] = []
    process = FakeProcess()
    job = FakeJob(events)

    def listeners() -> list[Any]:
        if "resume" not in events:
            return []
        return [SimpleNamespace(laddr=("127.0.0.1", 12434), status="LISTEN", pid=4321)]

    def finalize(verified: bool, _job: Any | None, _process: Any | None) -> bool:
        assert not verified
        events.append("quarantine")
        return True

    service = OwnedOllamaService(
        config,
        admit=_allow,
        finalize_admission=finalize,
        launcher=lambda *_, **__: process,
        job_factory=lambda: job,
        listeners=listeners,
        owns_listener=_owned,
        inspect_models=lambda: b'{"models":[{"name":"qwen3.8:27b","digest":"' + b"a" * 64 + b'"}]}',
        verify_process=_verified,
    )
    service.start()
    job.assigned = False
    job.empty = False  # The runner child is still alive.
    job.terminate_processes = lambda: events.append("terminate")  # type: ignore[method-assign]
    result = service.close()
    assert not result.tree_exit_verified
    assert result.admission_finalized
    assert result.resume_attempted
    assert "quarantine" in events


def test_resume_exception_with_lost_assignment_quarantines(tmp_path: Path) -> None:
    config, _ = _setup(tmp_path)
    events: list[str] = []
    job = FakeJob(events)

    def fail_resume(_process: FakeProcess) -> None:
        job.assigned = False
        raise RuntimeError("resume uncertain")

    job.resume_assigned = fail_resume  # type: ignore[method-assign]
    service = OwnedOllamaService(
        config,
        admit=_allow,
        finalize_admission=_finalize,
        launcher=lambda *_, **__: FakeProcess(),
        job_factory=lambda: job,
        listeners=lambda: [],
        verify_process=_verified,
    )
    with pytest.raises(OwnedOllamaError, match="resume uncertain") as exc:
        service.start()
    result = service.close()
    assert not exc.value.tree_exit_verified
    assert not result.tree_exit_verified
    assert result.resume_attempted
