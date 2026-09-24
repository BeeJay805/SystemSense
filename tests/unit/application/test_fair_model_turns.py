"""A bounded turn gate does not share provider instances or OS authority."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from systemsense.application.fair_model_turns import FairModelTurns, ModelTurnRegistration


def _deadline(seconds: float = 2) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=seconds)


def _wait_for_pending(gate: FairModelTurns, count: int) -> None:
    until = time.monotonic() + 1
    while gate.pending_count != count and time.monotonic() < until:
        time.sleep(0.005)
    assert gate.pending_count == count


def test_registration_is_bounded_and_thread_start_failure_can_unregister() -> None:
    gate = FairModelTurns(max_registered=2)
    first = gate.register("first")
    second = gate.register("second")
    assert first is not None and second is not None
    assert gate.register("third") is None
    assert gate.registered_count == 2
    first.close()  # worker thread could not start
    first.close()
    third = gate.register("third")
    assert third is not None
    assert gate.registered_count == 2
    second.close()
    third.close()
    assert gate.registered_count == 0


def test_waiting_case_gets_turn_before_first_case_repeats() -> None:
    gate = FairModelTurns(max_registered=2)
    first = gate.register("first")
    second = gate.register("second")
    assert first is not None and second is not None
    initial = first.acquire(deadline_at=_deadline())
    assert initial.status == "acquired" and initial.lease is not None
    order: list[str] = []
    failures: list[BaseException] = []

    def take_turn(name: str, registration: ModelTurnRegistration) -> None:
        try:
            attempt = registration.acquire(deadline_at=_deadline())
            assert attempt.status == "acquired" and attempt.lease is not None
            with attempt.lease:
                order.append(name)
        except BaseException as error:
            failures.append(error)

    waiting = threading.Thread(target=take_turn, args=("second", second), daemon=True)
    repeat = threading.Thread(target=take_turn, args=("first-repeat", first), daemon=True)
    waiting.start()
    _wait_for_pending(gate, 1)
    initial.lease.release()
    repeat.start()
    waiting.join(2)
    repeat.join(2)
    assert not waiting.is_alive() and not repeat.is_alive()
    assert not failures
    assert order == ["second", "first-repeat"]
    first.close()
    second.close()


def test_prior_served_waiter_cannot_be_overtaken_by_new_cases() -> None:
    gate = FairModelTurns(max_registered=3)
    prior = gate.register("prior")
    owner = gate.register("owner")
    newcomer = gate.register("newcomer")
    assert prior is not None and owner is not None and newcomer is not None
    first = prior.acquire(deadline_at=_deadline())
    assert first.lease is not None
    first.lease.release()
    held = owner.acquire(deadline_at=_deadline())
    assert held.lease is not None
    order: list[str] = []
    failures: list[BaseException] = []

    def use_turn(name: str, registration: ModelTurnRegistration) -> None:
        try:
            attempt = registration.acquire(deadline_at=_deadline())
            assert attempt.lease is not None
            with attempt.lease:
                order.append(name)
        except BaseException as error:
            failures.append(error)

    earlier = threading.Thread(target=use_turn, args=("prior", prior), daemon=True)
    later = threading.Thread(target=use_turn, args=("newcomer", newcomer), daemon=True)
    earlier.start()
    _wait_for_pending(gate, 1)
    later.start()
    _wait_for_pending(gate, 2)
    held.lease.release()
    earlier.join(2)
    later.join(2)
    assert not earlier.is_alive() and not later.is_alive()
    assert not failures
    assert order == ["prior", "newcomer"]
    prior.close()
    owner.close()
    newcomer.close()


def test_wait_deadline_and_cancellation_do_not_acquire_or_leak_tickets() -> None:
    gate = FairModelTurns(max_registered=3)
    owner = gate.register("owner")
    expired = gate.register("expired")
    cancelled = gate.register("cancelled")
    assert owner is not None and expired is not None and cancelled is not None
    active = owner.acquire(deadline_at=_deadline())
    assert active.lease is not None
    timeout_result: list[str] = []
    cancel_result: list[str] = []
    cancellation = threading.Event()

    timeout_thread = threading.Thread(
        target=lambda: timeout_result.append(expired.acquire(deadline_at=_deadline(0.06)).status),
        daemon=True,
    )
    cancel_thread = threading.Thread(
        target=lambda: cancel_result.append(
            cancelled.acquire(deadline_at=_deadline(), cancel_event=cancellation).status
        ),
        daemon=True,
    )
    timeout_thread.start()
    cancel_thread.start()
    _wait_for_pending(gate, 2)
    cancellation.set()
    timeout_thread.join(1)
    cancel_thread.join(1)
    assert not timeout_thread.is_alive() and not cancel_thread.is_alive()
    assert timeout_result == ["expired"]
    assert cancel_result == ["cancelled"]
    assert gate.pending_count == 0
    active.lease.release()
    owner.close()
    expired.close()
    cancelled.close()


def test_closing_registration_cannot_release_active_model_turn_early() -> None:
    gate = FairModelTurns(max_registered=1)
    owner = gate.register("owner")
    assert owner is not None
    attempt = owner.acquire(deadline_at=_deadline())
    assert attempt.lease is not None
    owner.close()
    assert gate.register("replacement") is None
    assert owner.acquire(deadline_at=_deadline()).status == "closed"
    attempt.lease.release()
    attempt.lease.release()
    replacement = gate.register("replacement")
    assert replacement is not None
    later = replacement.acquire(deadline_at=_deadline())
    assert later.status == "acquired" and later.lease is not None
    later.lease.release()
    replacement.close()
    assert gate.registered_count == 0


def test_one_registration_cannot_request_overlapping_turns() -> None:
    gate = FairModelTurns()
    registration = gate.register("case")
    assert registration is not None
    first = registration.acquire(deadline_at=_deadline())
    assert first.lease is not None
    with pytest.raises(RuntimeError, match="already has a model turn"):
        registration.acquire(deadline_at=_deadline())
    first.lease.release()
    registration.close()


def test_rejects_non_utc_or_expired_deadline_without_queueing() -> None:
    gate = FairModelTurns()
    registration = gate.register("case")
    assert registration is not None
    with pytest.raises(ValueError, match="timezone-aware"):
        registration.acquire(deadline_at=datetime.now())
    assert registration.acquire(deadline_at=_deadline(-1)).status == "expired"
    assert gate.pending_count == 0
    registration.close()
