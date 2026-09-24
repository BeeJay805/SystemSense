"""A misbehaving advisory provider must not hold the investigation thread."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from systemsense.application.candidate_provider_call import call_candidate_provider
from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
)
from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import SafetyClass
from systemsense.orchestration.scheduler import ResourceClass


def _request(*, deadline_ms: int = 1000) -> CandidateDecisionRequestV1:
    return CandidateDecisionRequestV1(
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="candidate:watchdog:1",
        deadline_at=datetime.now(UTC) + timedelta(milliseconds=deadline_ms),
        symptom="PDF is slow",
        available_candidates=(
            AdmittedCandidateRefV1(
                candidate_id="cand_v1_" + "a" * 32,
                probe_id="application.target_pressure",
                description="Read bounded pressure for an application",
                manifest_sha256="b" * 64,
                invocation_sha256="c" * 64,
                cost_ms=100,
                resource_class=ResourceClass.PROCESS,
                safety_class=SafetyClass.R1,
            ),
        ),
        reference_context=({"mutable": "original"},),
        budget_ms=1000,
        max_candidates=1,
    )


class _Provider:
    identity = ProviderIdentity(
        provider_id="watchdog-fixture", provider_version="1", role="fast_decision"
    )

    def __init__(
        self, *, release: threading.Event | None = None, started: threading.Event | None = None
    ):
        self.release = release
        self.started = started
        self.calls = 0
        self.worker_was_daemon = False

    def decide_candidates(self, request: CandidateDecisionRequestV1) -> CandidateDecisionGapV1:
        self.calls += 1
        self.worker_was_daemon = threading.current_thread().daemon
        request.reference_context[0]["mutable"] = "provider-mutated"
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            self.release.wait(timeout=10)
        return CandidateDecisionGapV1(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            reason_code="ranker_unavailable",
        )


def test_fast_provider_returns_without_mutating_caller_request() -> None:
    request = _request()
    provider = _Provider()

    response = call_candidate_provider(provider, request)

    assert isinstance(response, CandidateDecisionGapV1)
    assert response.case_id == request.case_id
    assert request.reference_context == ({"mutable": "original"},)
    assert provider.worker_was_daemon


def test_absolute_deadline_rejects_stalled_provider_and_expires_without_start() -> None:
    release = threading.Event()
    started = threading.Event()
    provider = _Provider(release=release, started=started)
    try:
        began = time.monotonic()
        with pytest.raises(TimeoutError, match="deadline"):
            call_candidate_provider(provider, _request(deadline_ms=150))
        assert time.monotonic() - began < 1.0
        assert started.is_set()
        with pytest.raises(TimeoutError, match="deadline"):
            call_candidate_provider(provider, _request(deadline_ms=-1))
        assert provider.calls == 1
    finally:
        release.set()


def test_cancelled_wait_rejects_late_provider_result() -> None:
    release = threading.Event()
    started = threading.Event()
    cancelled = threading.Event()
    provider = _Provider(release=release, started=started)
    timer = threading.Timer(0.06, cancelled.set)
    timer.start()
    try:
        began = time.monotonic()
        with pytest.raises(RuntimeError, match="cancelled"):
            call_candidate_provider(provider, _request(deadline_ms=1000), cancel_event=cancelled)
        assert started.is_set()
        assert time.monotonic() - began < 1.0
    finally:
        release.set()
        timer.join(timeout=1)


def test_two_stranded_calls_cap_global_worker_capacity() -> None:
    release = threading.Event()
    first_started = threading.Event()
    second_started = threading.Event()
    first = _Provider(release=release, started=first_started)
    second = _Provider(release=release, started=second_started)
    try:
        with pytest.raises(TimeoutError):
            call_candidate_provider(first, _request(deadline_ms=150))
        with pytest.raises(TimeoutError):
            call_candidate_provider(second, _request(deadline_ms=150))
        assert first_started.is_set() and second_started.is_set()
        third = _Provider()
        began = time.monotonic()
        with pytest.raises(RuntimeError, match="capacity"):
            call_candidate_provider(third, _request(deadline_ms=1000))
        assert time.monotonic() - began < 0.5
        assert third.calls == 0
    finally:
        release.set()
    # Completion eventually frees both permits, including after caller timeout.
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            assert isinstance(
                call_candidate_provider(_Provider(), _request()), CandidateDecisionGapV1
            )
            break
        except RuntimeError as error:
            if "capacity" not in str(error):
                raise
            time.sleep(0.01)
    else:
        pytest.fail("completed stranded workers did not release capacity")


def test_provider_error_is_typed_and_does_not_strand_capacity() -> None:
    class BrokenProvider(_Provider):
        def decide_candidates(self, request: CandidateDecisionRequestV1) -> CandidateDecisionGapV1:
            raise ValueError("private provider exception text")

    with pytest.raises(RuntimeError, match="candidate provider failed") as caught:
        call_candidate_provider(BrokenProvider(), _request())
    assert "private provider exception text" not in str(caught.value)
    assert isinstance(call_candidate_provider(_Provider(), _request()), CandidateDecisionGapV1)
