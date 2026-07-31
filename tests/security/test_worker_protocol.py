import os

from systemsense.orchestration.executor import (
    ProbeExecutor,
    WorkerExecutionStatus,
)


def test_unknown_probe_is_denied_before_worker_execution() -> None:
    result = ProbeExecutor().execute(
        "unknown.probe",
        {},
        timeout_ms=1000,
    )

    assert result.status is WorkerExecutionStatus.DENIED
    assert result.evidence == ()


def test_registered_worker_uses_typed_parameters() -> None:
    executor = ProbeExecutor()

    accepted = executor.execute(
        "fixture.echo",
        {"message": "hello"},
        timeout_ms=1000,
    )
    rejected = executor.execute(
        "fixture.echo",
        {"message": "hello", "command": "whoami"},
        timeout_ms=1000,
    )

    assert accepted.status is WorkerExecutionStatus.OK
    assert accepted.evidence[0]["message"] == "hello"
    assert rejected.status is WorkerExecutionStatus.FAILED


def test_worker_environment_does_not_inherit_parent_secrets() -> None:
    previous = os.environ.get("SYSTEMSENSE_TEST_SECRET")
    os.environ["SYSTEMSENSE_TEST_SECRET"] = "must-not-cross-worker-boundary"
    try:
        result = ProbeExecutor().execute(
            "fixture.environment",
            {},
            timeout_ms=1000,
        )
    finally:
        if previous is None:
            os.environ.pop("SYSTEMSENSE_TEST_SECRET", None)
        else:
            os.environ["SYSTEMSENSE_TEST_SECRET"] = previous

    assert result.status is WorkerExecutionStatus.OK
    keys = result.evidence[0]["keys"]
    assert isinstance(keys, list)
    assert "SYSTEMSENSE_TEST_SECRET" not in keys
