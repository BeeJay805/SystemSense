from __future__ import annotations

import json
from pathlib import Path

import pytest

from systemsense.application.setup_worker_failure_diagnostics import (
    failure_record,
    primary_failure,
    write_failure_record,
)


def test_failure_diagnostic_omits_exception_text_and_writes_attempt_log(tmp_path: Path) -> None:
    error = OSError(5, "private path and token")
    record = failure_record(
        "b2c8d568-62d7-4dcf-b6d8-82e1738fc458",
        "worker_assigned",
        "worker_job_assignment",
        error,
        child_exit_observed=True,
        job_empty=True,
        job_closed=True,
    )
    path = tmp_path / "b2c8d568-62d7-4dcf-b6d8-82e1738fc458.failure.log"

    write_failure_record(path, record)

    content = path.read_text(encoding="utf-8")
    restored = json.loads(content)
    assert restored["primary"] == {
        "stage": "worker_job_assignment",
        "exception_type": "OSError",
        "winerror": None,
        "errno": 5,
    }
    assert "private path" not in content
    assert path.exists()


def test_failure_diagnostic_requires_existing_parent_and_never_overwrites(tmp_path: Path) -> None:
    record = failure_record(
        "b2c8d568-62d7-4dcf-b6d8-82e1738fc458",
        "worker_assigned",
        "worker_job_assignment",
        RuntimeError("secret"),
        child_exit_observed=True,
        job_empty=True,
        job_closed=True,
    )
    missing_parent = tmp_path / "missing" / "attempt.failure.log"
    with pytest.raises(FileExistsError):
        write_failure_record(missing_parent, record)
    assert not missing_parent.parent.exists()

    existing = tmp_path / "attempt.failure.log"
    existing.write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError):
        write_failure_record(existing, record)
    assert existing.read_text(encoding="utf-8") == "preserve"


def test_primary_failure_rejects_invalid_stage_without_leaking_message() -> None:
    with pytest.raises(ValueError):
        primary_failure("worker assignment\nsecret", RuntimeError("secret"))
