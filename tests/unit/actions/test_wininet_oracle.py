"""Contract tests for an owned, fixed-destination WinINet lab check.

The transport and evidence sink are fakes. No network call is possible here.
"""

from datetime import UTC, datetime, timedelta

import pytest

from systemsense.actions.wininet_oracle import (
    LabCheckDescriptor,
    LabWinInetOracle,
    LabWinInetResponse,
)
from systemsense.actions.wininet_proxy import ConnectivityVerdict

SID = "S-1-5-21-1000-2000-3000-1001"
T0 = datetime(2026, 9, 22, tzinfo=UTC)


class FakeTransport:
    def __init__(self, response: LabWinInetResponse) -> None:
        self.response = response
        self.calls: list[LabCheckDescriptor] = []

    def check(self, descriptor: LabCheckDescriptor) -> LabWinInetResponse:
        self.calls.append(descriptor)
        return self.response


class EvidenceSink:
    def __init__(self) -> None:
        self.records: list[object] = []

    def save(self, record: object) -> None:
        self.records.append(record)


def _descriptor() -> LabCheckDescriptor:
    return LabCheckDescriptor(
        check_id="lab.wininet.external_https",
        host="probe.example.org",
        path="/health/204",
        expected_user_sid=SID,
        timeout_ms=3000,
    )


def _response(**changes: object) -> LabWinInetResponse:
    values: dict[str, object] = {
        "status": 204,
        "body_bytes": 0,
        "redirected": False,
        "final_host": "probe.example.org",
        "executing_user_sid": SID,
        "elapsed_ms": 100,
        "error": None,
    }
    values.update(changes)
    return LabWinInetResponse(**values)  # type: ignore[arg-type]


def _oracle(
    response: LabWinInetResponse, *, sid: list[str] | None = None
) -> tuple[LabWinInetOracle, FakeTransport, EvidenceSink]:
    transport = FakeTransport(response)
    sink = EvidenceSink()
    current_sid = sid if sid is not None else [SID]
    ticks = iter((T0, T0 + timedelta(milliseconds=100)))
    oracle = LabWinInetOracle(
        descriptor=_descriptor(),
        transport=transport,
        current_user_sid=lambda: current_sid[0],
        evidence=sink,
        clock=lambda: next(ticks),
    )
    return oracle, transport, sink


def test_only_registered_check_is_supported_and_has_no_url_argument() -> None:
    oracle, transport, sink = _oracle(_response())
    assert oracle.supports("lab.wininet.external_https")
    assert not oracle.supports("other")
    with pytest.raises(ValueError, match="unregistered"):
        oracle.check("other")
    assert transport.calls == [] and sink.records == []


def test_success_requires_exact_scope_and_persists_independent_evidence() -> None:
    oracle, transport, sink = _oracle(_response())
    first = oracle.check("lab.wininet.external_https")
    assert first.passed and first.path == "wininet_current_user"
    assert first.destination_scope == "external"
    assert first.observed_at == T0 + timedelta(milliseconds=100)
    assert len(transport.calls) == len(sink.records) == 1
    record = sink.records[0]
    assert record.evidence_id == first.evidence_id  # type: ignore[attr-defined]
    assert record.started_at == T0  # type: ignore[attr-defined]
    assert record.observed_at == first.observed_at  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "changes",
    [
        {"status": 200},
        {"status": 302, "redirected": True},
        {"body_bytes": 1},
        {"final_host": "portal.example.net"},
        {"executing_user_sid": "S-1-5-21-9000-9000-9000-1001"},
        {"elapsed_ms": 3001},
        {"error": "tls_failure"},
    ],
)
def test_nonmatching_response_is_failure_with_evidence(changes: dict[str, object]) -> None:
    oracle, _transport, sink = _oracle(_response(**changes))
    result = oracle.check("lab.wininet.external_https")
    assert not result.passed
    assert len(sink.records) == 1


def test_sid_change_during_request_cannot_be_treated_as_connectivity_failure() -> None:
    sid = [SID]

    class SwitchingTransport(FakeTransport):
        def check(self, descriptor: LabCheckDescriptor) -> LabWinInetResponse:
            sid[0] = "S-1-5-21-9000-9000-9000-1001"
            return super().check(descriptor)

    transport = SwitchingTransport(_response())
    sink = EvidenceSink()
    oracle = LabWinInetOracle(
        descriptor=_descriptor(),
        transport=transport,
        current_user_sid=lambda: sid[0],
        evidence=sink,
        clock=lambda: T0,
    )
    with pytest.raises(RuntimeError, match="identity"):
        oracle.check("lab.wininet.external_https")
    assert sink.records == []


def test_transport_exception_is_failed_observation_without_leaking_message() -> None:
    class FailingTransport:
        def check(self, descriptor: LabCheckDescriptor) -> LabWinInetResponse:
            raise RuntimeError("secret proxy username and URL")

    sink = EvidenceSink()
    ticks = iter((T0, T0 + timedelta(milliseconds=1)))
    oracle = LabWinInetOracle(
        descriptor=_descriptor(),
        transport=FailingTransport(),
        current_user_sid=lambda: SID,
        evidence=sink,
        clock=lambda: next(ticks),
    )
    result = oracle.check("lab.wininet.external_https")
    assert not result.passed
    assert result.verdict is ConnectivityVerdict.UNAVAILABLE
    assert "secret" not in repr(sink.records[0])


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("wininet_12029", ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE),
        ("wininet_12007", ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE),
        ("worker_error", ConnectivityVerdict.UNAVAILABLE),
        ("deadline_exceeded", ConnectivityVerdict.UNAVAILABLE),
        ("wininet_12037", ConnectivityVerdict.UNAVAILABLE),
    ],
)
def test_only_measured_network_failures_can_precede_a_repair(
    error: str, expected: ConnectivityVerdict
) -> None:
    oracle, _transport, sink = _oracle(_response(status=None, error=error))
    result = oracle.check("lab.wininet.external_https")
    assert not result.passed
    assert result.verdict is expected
    assert sink.records[0].result_code == expected.value  # type: ignore[attr-defined]


def test_direct_control_uses_same_fixed_endpoint_with_separate_provenance() -> None:
    descriptor = _descriptor()
    proxy_transport = FakeTransport(_response(status=502))
    direct_transport = FakeTransport(_response())
    sink = EvidenceSink()
    ticks = iter(T0 + timedelta(milliseconds=step) for step in (0, 100, 200, 300))
    oracle = LabWinInetOracle(
        descriptor=descriptor,
        transport=proxy_transport,
        direct_transport=direct_transport,
        current_user_sid=lambda: SID,
        evidence=sink,
        clock=lambda: next(ticks),
    )
    proxy = oracle.check(descriptor.check_id)
    direct = oracle.check_direct_control(descriptor.check_id)
    assert not proxy.passed and direct.passed
    assert proxy.path == "wininet_current_user"
    assert direct.path == "wininet_direct_control"
    assert proxy.evidence_id != direct.evidence_id
    assert proxy_transport.calls == direct_transport.calls == [descriptor]
    assert [record.path for record in sink.records] == [  # type: ignore[attr-defined]
        "wininet_current_user",
        "wininet_direct_control",
    ]


def test_direct_control_is_explicitly_unavailable_without_registered_transport() -> None:
    oracle, transport, sink = _oracle(_response())
    with pytest.raises(RuntimeError, match="direct control unavailable"):
        oracle.check_direct_control("lab.wininet.external_https")
    assert transport.calls == [] and sink.records == []


def test_evidence_save_failure_cannot_return_success() -> None:
    class FailingSink:
        def save(self, record: object) -> None:
            raise OSError("evidence store unavailable")

    oracle = LabWinInetOracle(
        descriptor=_descriptor(),
        transport=FakeTransport(_response()),
        current_user_sid=lambda: SID,
        evidence=FailingSink(),
        clock=lambda: T0,
    )
    with pytest.raises(OSError, match="evidence store unavailable"):
        oracle.check("lab.wininet.external_https")


@pytest.mark.parametrize(
    "host,path", [("localhost", "/ok"), ("127.0.0.1", "/ok"), ("a.b", "//evil")]
)
def test_descriptor_rejects_local_or_noncanonical_destinations(host: str, path: str) -> None:
    with pytest.raises(ValueError):
        LabCheckDescriptor("lab.wininet.external_https", host, path, SID, 3000)
