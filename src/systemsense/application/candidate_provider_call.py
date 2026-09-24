"""Bounded invocation boundary for replaceable candidate decision providers."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime

from systemsense.decision.candidates import (
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
)
from systemsense.decision.provider import CandidateDecisionProvider

_ACTIVE_PROVIDER_CALLS = threading.BoundedSemaphore(2)
_CANCEL_POLL_SECONDS = 0.05


def call_candidate_provider(
    provider: CandidateDecisionProvider,
    request: CandidateDecisionRequestV1,
    cancel_event: threading.Event | None = None,
) -> CandidateDecisionResponseV1 | CandidateDecisionGapV1:
    """Wait only to the frozen deadline; leave a stalled worker daemonized and capped.

    A timed-out or cancelled call keeps its slot until its worker actually exits.
    The bound is intentionally conservative: at most two live provider workers,
    including those whose callers have already stopped waiting.
    """

    if cancel_event is not None and cancel_event.is_set():
        raise RuntimeError("candidate provider call cancelled")
    remaining = (request.deadline_at - datetime.now(UTC)).total_seconds()
    if remaining <= 0:
        raise TimeoutError("candidate provider deadline expired")
    deadline = time.monotonic() + remaining
    private_request = request.model_copy(deep=True)
    if not _ACTIVE_PROVIDER_CALLS.acquire(blocking=False):
        raise RuntimeError("candidate provider capacity exhausted")

    done = threading.Event()
    responses: list[object] = []
    failures: list[str] = []

    def invoke() -> None:
        try:
            responses.append(provider.decide_candidates(private_request))
        except Exception as error:
            # No provider exception text crosses into case-visible failure state.
            failures.append(type(error).__name__)
        finally:
            _ACTIVE_PROVIDER_CALLS.release()
            done.set()

    worker = threading.Thread(target=invoke, name="systemsense-candidate-decision", daemon=True)
    try:
        worker.start()
    except Exception:
        _ACTIVE_PROVIDER_CALLS.release()
        raise RuntimeError("candidate provider worker unavailable") from None

    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise RuntimeError("candidate provider call cancelled")
        remaining = min(
            deadline - time.monotonic(),
            (request.deadline_at - datetime.now(UTC)).total_seconds(),
        )
        if remaining <= 0:
            raise TimeoutError("candidate provider deadline expired")
        if done.wait(timeout=min(remaining, _CANCEL_POLL_SECONDS)):
            if cancel_event is not None and cancel_event.is_set():
                raise RuntimeError("candidate provider call cancelled")
            if time.monotonic() >= deadline or datetime.now(UTC) >= request.deadline_at:
                raise TimeoutError("candidate provider deadline expired")
            if failures:
                raise RuntimeError(f"candidate provider failed: {failures[0]}")
            if not responses or not isinstance(
                responses[0], (CandidateDecisionResponseV1, CandidateDecisionGapV1)
            ):
                raise RuntimeError("candidate provider returned an invalid response")
            return responses[0]
