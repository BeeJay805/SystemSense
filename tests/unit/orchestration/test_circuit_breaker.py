from datetime import UTC, datetime, timedelta

from systemsense.orchestration.circuit_breaker import CircuitBreaker, CircuitState

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_repeated_failures_open_then_half_open_after_cooldown() -> None:
    circuit = CircuitBreaker(failure_threshold=2, cooldown=timedelta(seconds=30))

    circuit.record_failure(at=_NOW)
    assert circuit.allow(at=_NOW)
    circuit.record_failure(at=_NOW)

    assert circuit.state is CircuitState.OPEN
    assert not circuit.allow(at=_NOW + timedelta(seconds=29))
    assert circuit.allow(at=_NOW + timedelta(seconds=30))
    assert circuit.state is CircuitState.HALF_OPEN


def test_half_open_success_closes_and_failure_reopens() -> None:
    circuit = CircuitBreaker(failure_threshold=1, cooldown=timedelta(seconds=10))
    circuit.record_failure(at=_NOW)
    assert circuit.allow(at=_NOW + timedelta(seconds=10))

    circuit.record_success()
    assert circuit.state is CircuitState.CLOSED
    assert circuit.allow(at=_NOW + timedelta(seconds=11))

    circuit.record_failure(at=_NOW + timedelta(seconds=12))
    assert circuit.allow(at=_NOW + timedelta(seconds=22))
    circuit.record_failure(at=_NOW + timedelta(seconds=22))
    assert circuit.state is CircuitState.OPEN
