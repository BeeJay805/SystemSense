"""An exact test-owned loopback task is observed by the product, not its oracle."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.candidate_catalog import general_measurement_candidate_catalog
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.loopback_owner import trusted_loopback_owner
from systemsense.application.loopback_task_observation import (
    TestOwnedLoopbackTaskV1,
    UserOwnedLoopbackTaskV1,
    observe_test_owned_loopback_task,
    observe_user_owned_loopback_task,
    parse_user_owned_loopback_task,
)
from systemsense.application.service import ApplicationService
from systemsense.application.task_observation import resolve_task_observation
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal
from systemsense.domain.affected_task import AffectedTaskKind, ReportedAffectedTaskV1
from systemsense.domain.evidence import EvidenceRecord
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("healthy", "http_200_nonce_match"),
        ("503", "http_503"),
        ("stall", "timeout"),
        ("wrong_nonce", "wrong_response"),
    ],
)
def test_product_records_exact_loopback_task_outcome(
    tmp_path: Path, mode: str, expected: str
) -> None:
    nonce = "a" * 32

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == f"/health/{nonce}"
            if mode == "stall":
                threading.Event().wait(0.4)
                return
            if mode == "503":
                self.send_error(503)
                return
            body = (("0" * 32 if mode == "wrong_nonce" else nonce) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with SQLiteStore(tmp_path / "case.db") as store:
                investigator = default_investigator(store)
                state = investigator.create(
                    objective="Investigate this test endpoint",
                    reported_task=ReportedAffectedTaskV1(
                        kind=AffectedTaskKind.NETWORK_CONNECTION,
                        action=(f"GET http://127.0.0.1:{server.server_port}/health/{nonce}"),
                        target_hint=f"127.0.0.1:{server.server_port}",
                        reported_outcome="Please check the status page result.",
                    ),
                )
                record = observe_test_owned_loopback_task(
                    store,
                    case_id=state.case_id,
                    scope=TestOwnedLoopbackTaskV1(port=server.server_port, nonce=nonce),
                    timeout_seconds=0.15,
                )
                facts = {fact.name: fact.value for fact in record.facts}
                assert facts["outcome"] == expected
                assert facts["target_handle"] == f"127.0.0.1:{server.server_port}"
                assert store.probe_execution(str(record.collector.execution_id)) is not None
                row = store.evidence(
                    case_id=str(state.case_id), evidence_id=str(record.evidence_id)
                )
                assert row is not None
                assert EvidenceRecord.model_validate_json(row.record_json) == record
                bound = InvestigationRepository(store).load(str(state.case_id))
                assert bound.task_observation_reference is not None
                task = resolve_task_observation(
                    store, case_id=state.case_id, reference=bound.task_observation_reference
                )
                assert task.scope == "test_owned_loopback"
                assert task.observed == expected
                assert task.reported_task_relation == "exact_action_replayed"
                registry, needs = general_measurement_candidate_catalog(
                    store, default_probe_runner(), state.case_id
                )
                assert "network.listeners" in {need.capability_id for need in needs}
                assert needs[0].capability_id == "network.listeners"
                assert {need.capability_id for need in needs} == {
                    "network.listeners",
                    "network.loopback_replay",
                }
                running = InvestigationRepository(store).save(
                    bound.model_copy(update={"status": InvestigationStatus.RUNNING}),
                    expected_version=bound.state_version,
                    event="started",
                    detail="Focused candidate admission test.",
                )
                listener_need = next(
                    need for need in needs if need.capability_id == "network.listeners"
                )
                issued = registry.issue(state.case_id, running.state_version, listener_need)
                assert not isinstance(issued, CandidateGap)
                assert issued.probe_id == "network.listeners"
                with store.transaction():
                    store.connection.execute(
                        "UPDATE probe_executions SET started_at=? WHERE execution_id=?",
                        ("2020-01-01T00:00:00+00:00", str(record.collector.execution_id)),
                    )
                with pytest.raises(ValueError, match="custody"):
                    resolve_task_observation(
                        store,
                        case_id=state.case_id,
                        reference=bound.task_observation_reference,
                    )
                context = investigator.context(str(state.case_id))
                assert any(
                    item.evidence_id == record.evidence_id and item.facts["outcome"] == expected
                    for item in context
                )
        finally:
            server.shutdown()
            thread.join(timeout=2)


@pytest.mark.parametrize(
    "objective",
    (
        "Check https://127.0.0.1:59152/health/" + "a" * 32,
        "Check http://localhost:59152/health/" + "a" * 32,
        "Check http://127.0.0.1:80/health/" + "a" * 32,
        "Check http://127.0.0.1:59152/other/" + "a" * 32,
        "Check http://127.0.0.1:59152/health/" + "a" * 32 + "?extra=1",
        "Compare http://127.0.0.1:59152/health/"
        + "a" * 32
        + " with http://127.0.0.1:59153/health/"
        + "b" * 32,
    ),
)
def test_user_selected_task_parser_rejects_ambiguous_or_broader_urls(objective: str) -> None:
    assert parse_user_owned_loopback_task(objective) is None


@pytest.mark.parametrize("punctuation", ["?", "!"])
def test_user_selected_url_accepts_sentence_punctuation(punctuation: str) -> None:
    nonce = "e" * 32
    objective = (
        f"Can you check http://127.0.0.1:59152/health/{nonce}{punctuation} "
        "The local page seems wrong."
    )
    assert parse_user_owned_loopback_task(objective) == UserOwnedLoopbackTaskV1(
        port=59152, nonce=nonce
    )


def test_user_selected_exact_loopback_get_is_persisted_with_distinct_scope(tmp_path: Path) -> None:
    nonce = "c" * 32

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == f"/health/{nonce}"
            body = (nonce + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            objective = (
                f"My local status page http://127.0.0.1:{server.server_port}/health/{nonce} "
                "is not working"
            )
            scope = parse_user_owned_loopback_task(objective)
            assert scope == UserOwnedLoopbackTaskV1(port=server.server_port, nonce=nonce)
            assert scope is not None
            with SQLiteStore(tmp_path / "case.db") as store:
                investigator = default_investigator(store)
                state = investigator.create(
                    objective=objective,
                    reported_task=ReportedAffectedTaskV1(
                        kind=AffectedTaskKind.NETWORK_CONNECTION,
                        action=f"GET http://127.0.0.1:{server.server_port}/health/{nonce}",
                        target_hint=f"127.0.0.1:{server.server_port}",
                        reported_outcome="The user asked Dyad to check this exact health GET.",
                    ),
                )
                record = observe_user_owned_loopback_task(store, case_id=state.case_id, scope=scope)
                events = SearchFrontierRepository(store).pending_investigator_events(state.case_id)
                assert len(events) == 1
                assert events[0].source_evidence_id == record.evidence_id
                assert events[0].source_execution_id == record.collector.execution_id
                bound = InvestigationRepository(store).load(str(state.case_id))
                assert bound.task_observation_reference is not None
                context = resolve_task_observation(
                    store, case_id=state.case_id, reference=bound.task_observation_reference
                )
                assert context.scope == "user_owned_loopback"
                assert context.observed == "http_200_nonce_match"
                assert context.evidence_id == record.evidence_id
                assert context.reported_task_relation == "exact_action_replayed"
                assert "<redacted-url>" in bound.objective
                target = investigator._select_target_evidence(  # pyright: ignore[reportPrivateUsage]
                    bound, investigator.context(str(state.case_id))
                )
                assert target.scanned_object_count > 0
                assert not any("No supported exact IPv4:port" in note for note in target.notes)
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_normal_case_start_observes_only_the_exact_user_selected_health_get(
    tmp_path: Path,
) -> None:
    nonce = "d" * 32
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            body = (nonce + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        service = ApplicationService(tmp_path / "case.db", factory=default_investigator)
        try:
            objective = f"The local page http://127.0.0.1:{server.server_port}/health/{nonce} fails"
            started = service.start_case(objective, 30000, 4)
            assert requests == [f"/health/{nonce}"]
            with SQLiteStore(tmp_path / "case.db") as store:
                state = InvestigationRepository(store).load(str(started["case_id"]))
                assert state.task_observation_reference is not None
                context = resolve_task_observation(
                    store, case_id=state.case_id, reference=state.task_observation_reference
                )
                assert context.scope == "user_owned_loopback"
                assert context.observed == "http_200_nonce_match"
            deadline = time.monotonic() + 15
            result: dict[str, object] | None = None
            while time.monotonic() < deadline:
                result = service.get_case(str(started["case_id"]))
                if result["status"] in {"complete", "failed", "cancelled"}:
                    break
                time.sleep(0.05)
            assert result is not None and result["status"] == "complete"
            assert result["outcome"] == "awaiting_recurrence"
            assert "No failure was reproduced" in str(result["summary"])
        finally:
            service.close()
            server.shutdown()
            thread.join(timeout=2)


@pytest.mark.parametrize("listener_present", [False, True])
def test_basic_timeout_checks_later_listener_without_claiming_request_time_cause(
    tmp_path: Path, listener_present: bool
) -> None:
    nonce = "e" * 32

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            threading.Event().wait(3)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    if port < 49152:
        server.server_close()
        pytest.skip("Windows high-port loopback fixture unavailable")
    thread = None
    if listener_present:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
    else:
        server.server_close()
    service = ApplicationService(tmp_path / "case.db", factory=default_investigator)
    try:
        objective = f"My local status page http://127.0.0.1:{port}/health/{nonce} is not working"
        started = service.start_case(objective, 30000, 4)
        deadline = time.monotonic() + 35
        result: dict[str, object] | None = None
        while time.monotonic() < deadline:
            result = service.get_case(str(started["case_id"]))
            if result["status"] in {"complete", "failed", "cancelled"}:
                break
            time.sleep(0.1)
        assert result is not None and result["status"] == "complete"
        assert result["outcome"] == "insufficient_observability"
        evidence = cast("list[dict[str, object]]", result["evidence"])
        task = next(item for item in evidence if item["probe_id"] == "task.loopback_http")
        facts = cast("dict[str, object]", task["facts"])
        assert facts["outcome"] in {"timeout", "connection_refused"}
        assert any(item["probe_id"] == "network.listeners" for item in evidence)
        assert (
            "A later listener snapshot found an owner on that port"
            if listener_present
            else "A later complete listener-table search found no listener on that port"
        ) in str(result["summary"])
        assert "request-time cause remains unresolved" in str(result["summary"])
        with SQLiteStore(tmp_path / "case.db") as store:
            case_state = InvestigationRepository(store).load(str(started["case_id"]))
            case_id = case_state.case_id
            owner = trusted_loopback_owner(store, case_id)
            assert (owner is not None) == listener_present
            assert (
                default_investigator(store)._loopback_check_precedes_deep_review(  # pyright: ignore[reportPrivateUsage]
                    case_state
                )
                is False
            )
            if owner is not None:
                assert owner.port == port
                assert owner.nonce == nonce
                _, owner_needs = general_measurement_candidate_catalog(
                    store, default_probe_runner(), case_id
                )
                assert "network.listener_owner_pressure" in case_state.completed_probe_ids
                assert not any(
                    need.capability_id == "network.listener_owner_pressure" for need in owner_needs
                )
                with store.transaction():
                    store.connection.execute(
                        "UPDATE probe_executions SET status='unavailable' "
                        "WHERE case_id=? AND probe_id='network.listeners'",
                        (str(case_id),),
                    )
                assert trusted_loopback_owner(store, case_id) is None
    finally:
        service.close()
        if thread is not None:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()


def test_product_records_refused_connection_without_inventing_http_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RefusedConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            raise ConnectionRefusedError()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "systemsense.application.loopback_task_observation.http.client.HTTPConnection",
        RefusedConnection,
    )
    port = 59152
    with SQLiteStore(tmp_path / "case.db") as store:
        state = default_investigator(store).create(objective="Investigate this test endpoint")
        record = observe_test_owned_loopback_task(
            store,
            case_id=state.case_id,
            scope=TestOwnedLoopbackTaskV1(port=port, nonce="b" * 32),
            timeout_seconds=0.15,
        )
        facts = {fact.name: fact.value for fact in record.facts}
        assert facts["outcome"] == "connection_refused"
        assert facts["http_status"] is None


def test_reported_action_must_match_exact_test_scope_before_any_get(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        state = default_investigator(store).create(
            objective="Investigate this test endpoint",
            reported_task=ReportedAffectedTaskV1(
                kind=AffectedTaskKind.NETWORK_CONNECTION,
                action="GET http://127.0.0.1:59153/health/" + "b" * 32,
                target_hint="127.0.0.1:59153",
                reported_outcome="Please check the status page result.",
            ),
        )
        with pytest.raises(ValueError, match="does not match"):
            observe_test_owned_loopback_task(
                store,
                case_id=state.case_id,
                scope=TestOwnedLoopbackTaskV1(port=59152, nonce="b" * 32),
            )
        assert store.probe_execution_count(case_id=str(state.case_id)) == 0


def test_exact_loopback_question_rejects_unrelated_host_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RefusedConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(self, *_args: object, **_kwargs: object) -> None:
            raise ConnectionRefusedError()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        "systemsense.application.loopback_task_observation.http.client.HTTPConnection",
        RefusedConnection,
    )
    with SQLiteStore(tmp_path / "case.db") as store:
        investigator = default_investigator(store)
        state = investigator.create(objective="Investigate 127.0.0.1:59152 status page")
        observe_test_owned_loopback_task(
            store,
            case_id=state.case_id,
            scope=TestOwnedLoopbackTaskV1(port=59152, nonce="b" * 32),
            timeout_seconds=0.1,
        )
        bound = InvestigationRepository(store).load(str(state.case_id))
        capabilities = {item.probe_id: item for item in investigator.capabilities}

        def proposal(probe_id: str) -> ProbeProposal:
            capability = capabilities[probe_id]
            return ProbeProposal(
                probe_id=probe_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
                estimated_cost_ms=capability.cost_ms,
                resource_class=capability.resource_class,
                safety_class=capability.safety_class,
                dedupe_key=f"scoped:{probe_id}",
            )

        chosen = investigator._eligible(  # pyright: ignore[reportPrivateUsage]
            (
                proposal("application.snapshot"),
                proposal("core.system"),
                proposal("network.listeners"),
            ),
            bound,
            30_000,
        )
        assert tuple(item.probe_id for item in chosen) == ("network.listeners",)


@pytest.mark.parametrize("port,nonce", [(80, "a" * 32), (49152, "x" * 32), (49152, "a" * 31)])
def test_scope_rejects_non_fixture_shape(port: int, nonce: str) -> None:
    with pytest.raises(ValueError):
        TestOwnedLoopbackTaskV1(port=port, nonce=nonce)
