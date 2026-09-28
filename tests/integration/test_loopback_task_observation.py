"""An exact test-owned loopback task is observed by the product, not its oracle."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.candidate_catalog import general_measurement_candidate_catalog
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.loopback_task_observation import (
    TestOwnedLoopbackTaskV1,
    observe_test_owned_loopback_task,
)
from systemsense.application.task_observation import resolve_task_observation
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal
from systemsense.domain.affected_task import AffectedTaskKind, ReportedAffectedTaskV1
from systemsense.domain.evidence import EvidenceRecord
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


@pytest.mark.parametrize(
    "mode,expected",
    [("healthy", "http_200_nonce_match"), ("503", "http_503"), ("stall", "timeout")],
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
                assert {need.capability_id for need in needs} == {"network.listeners"}
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
            (proposal("application.snapshot"), proposal("core.system")),
            bound,
            30_000,
        )
        assert tuple(item.probe_id for item in chosen) == ("core.system",)


@pytest.mark.parametrize("port,nonce", [(80, "a" * 32), (49152, "x" * 32), (49152, "a" * 31)])
def test_scope_rejects_non_fixture_shape(port: int, nonce: str) -> None:
    with pytest.raises(ValueError):
        TestOwnedLoopbackTaskV1(port=port, nonce=nonce)
