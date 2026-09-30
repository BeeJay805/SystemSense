"""Sanitized, attempt-scoped setup failure diagnostics retained after rollback."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def _safe_code(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def primary_failure(stage: str, error: BaseException) -> dict[str, Any]:
    """Extract bounded codes without serializing exception text or traceback."""
    if not stage or len(stage) > 64 or not stage.replace("_", "").isalnum():
        raise ValueError("invalid diagnostic stage")
    record: dict[str, Any] = {
        "stage": stage,
        "exception_type": str(getattr(error, "exception_type", type(error).__name__))[:80],
        "winerror": _safe_code(getattr(error, "winerror", None)),
        "errno": _safe_code(getattr(error, "errno", None)),
    }
    thread_count = getattr(error, "thread_count", None)
    if isinstance(thread_count, int) and not isinstance(thread_count, bool):
        record["thread_count"] = thread_count
    return record


def failure_record(
    attempt_id: str,
    phase: str,
    stage: str,
    error: BaseException,
    *,
    child_exit_observed: bool | None,
    job_empty: bool | None,
    job_closed: bool | None,
    cleanup_error: BaseException | None = None,
) -> dict[str, Any]:
    if not attempt_id or len(attempt_id) > 64 or not attempt_id.replace("-", "").isalnum():
        raise ValueError("invalid attempt id")
    if not phase or len(phase) > 64 or not phase.replace("_", "").isalnum():
        raise ValueError("invalid phase")
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "recorded_at": datetime.now(UTC).isoformat(),
        "attempt_id": attempt_id,
        "last_durable_phase": phase,
        "primary": primary_failure(stage, error),
        "cleanup": {
            "child_exit_observed": child_exit_observed,
            "job_empty": job_empty,
            "job_closed": job_closed,
            "uncertain": cleanup_error is not None
            or child_exit_observed is False
            or job_empty is False
            or job_closed is False,
        },
    }
    if cleanup_error is not None:
        record["cleanup"]["exception_type"] = type(cleanup_error).__name__[:80]
        record["cleanup"]["winerror"] = _safe_code(getattr(cleanup_error, "winerror", None))
        record["cleanup"]["errno"] = _safe_code(getattr(cleanup_error, "errno", None))
    return record


def write_failure_record(path: Path, record: dict[str, Any]) -> None:
    """Atomically persist in the attempt-owned receipt directory; no raw error data."""
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not path.parent.is_dir() or path.exists():
        raise FileExistsError("failure diagnostic parent missing or target already exists")
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except BaseException:
        temp_path.unlink(missing_ok=True)
        raise
