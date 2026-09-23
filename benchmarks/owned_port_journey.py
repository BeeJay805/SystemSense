"""Controlled real-host port conflict rehearsal with an owned blocker only.

The harness owns the fault and exact action. SystemSense only investigates. A
successful result is a host integration check, not diagnostic accuracy, a
consumer repair, or evidence about WinINet.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path
from typing import Any, TextIO, cast

import psutil

from systemsense.application.bootstrap import default_investigator, default_planner
from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationState
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
    SelfWrite,
)
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass, TaskStatus
from systemsense.packs.runtime import NoParameters
from systemsense.storage.sqlite_store import SQLiteStore

_ADDRESS = "127.0.0.1"
_BLOCKER = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('127.0.0.1', int(__import__('sys').argv[1])))
s.listen(4)
while True:
    c, _ = s.accept()
    with c:
        c.recv(4096)
        c.sendall(
            b'HTTP/1.1 200 OK\\r\\nContent-Length: 7\\r\\n'
            b'Connection: close\\r\\n\\r\\nBLOCKED'
        )
"""
_TARGET = """
import json
import os
import socket
import sys
from datetime import UTC, datetime

address, raw_port = sys.argv[1:3]
port = int(raw_port)
result = {
    'address': address,
    'port': port,
    'protocol': 'tcp4',
    'pid': os.getpid(),
    'bind_started_at': None,
    'bind_succeeded': False,
    'served_http': False,
    'errno': None,
    'winerror': None,
    'socket_error': None,
    'socket_exclusive_address_use': False,
    'socket_reuse_address': True,
}
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        result['socket_exclusive_address_use'] = bool(
            server.getsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE)
        )
        result['socket_reuse_address'] = bool(
            server.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR)
        )
        if sys.stdin.buffer.readline(16) != b'START\\n':
            raise RuntimeError('observer did not release target')
        result['bind_started_at'] = datetime.now(UTC).isoformat()
        server.bind((address, port))
        result['bind_succeeded'] = True
        result['bind_completed_at'] = datetime.now(UTC).isoformat()
        server.listen(1)
        server.settimeout(3)
        with server.accept()[0] as client:
            client.settimeout(2)
            request = client.recv(4096)
            if b'GET /health HTTP/1.1' in request:
                client.sendall(
                    b'HTTP/1.1 200 OK\\r\\nContent-Length: 9\\r\\n'
                    b'Connection: close\\r\\n\\r\\nTARGET_OK'
                )
                result['served_http'] = True
    except OSError as error:
        result['bind_completed_at'] = datetime.now(UTC).isoformat()
        result['errno'] = error.errno
        result['winerror'] = getattr(error, 'winerror', None)
        result['socket_error'] = str(error)
result['finished_at'] = datetime.now(UTC).isoformat()
print(json.dumps(result, separators=(',', ':')), flush=True)
"""


def _stamp() -> str:
    return datetime.now(UTC).isoformat()


def _elapsed(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


def _owned_endpoint(pid: int, port: int) -> bool:
    return any(
        row.pid == pid
        and row.status == "LISTEN"
        and row.laddr
        and row.laddr.ip == _ADDRESS
        and row.laddr.port == port
        for row in psutil.net_connections(kind="tcp")
    )


def _same_creation(observed: str, actual: str) -> bool:
    try:
        left = datetime.fromisoformat(observed)
        right = datetime.fromisoformat(actual)
        return (
            left.utcoffset() is not None
            and right.utcoffset() is not None
            and abs((left - right).total_seconds()) < 0.01
        )
    except (TypeError, ValueError):
        return False


def matching_owned_listener(
    listeners: list[dict[str, Any]],
    port: int,
    pid: int,
    name: str,
    created: str,
) -> bool:
    """Require one exact, available endpoint owner from the persisted probe."""
    matches = [
        item
        for item in listeners
        if item.get("protocol") == "tcp4"
        and item.get("local_address") == _ADDRESS
        and item.get("local_port") == port
    ]
    return len(matches) == 1 and (
        matches[0].get("owner_status") == "available"
        and matches[0].get("pid") == pid
        and isinstance(matches[0].get("process_name"), str)
        and matches[0]["process_name"].casefold() == name.casefold()
        and isinstance(matches[0].get("process_creation_time"), str)
        and _same_creation(matches[0]["process_creation_time"], created)
    )


def _choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((_ADDRESS, 0))
        return int(sock.getsockname()[1])


def _http_read(port: int) -> bytes:
    with socket.create_connection((_ADDRESS, port), timeout=2) as client:
        client.settimeout(2)
        client.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        chunks: list[bytes] = []
        while data := client.recv(4096):
            chunks.append(data)
    return b"".join(chunks)


def _run_target_observer(port: int) -> dict[str, Any]:
    """Run one fixed target configuration in a separate bounded process."""
    digest = target_configuration_digest(port)
    started_at = _stamp()
    process = subprocess.Popen(
        [getattr(sys, "_base_executable", sys.executable), "-c", _TARGET, _ADDRESS, str(port)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    measurement: dict[str, Any] = {
        "pid": process.pid,
        "process_creation_time": None,
        "configuration_digest": digest,
        "started_at": started_at,
        "finished_at": None,
        "completed": False,
        "exit_code": None,
        "bind_succeeded": False,
        "served_http": False,
        "http_response_verified": False,
        "raw_stdout": "",
        "raw_stderr": "",
        "raw_result": None,
        "observer_error": None,
    }
    deadline = time.monotonic() + 6
    try:
        created = datetime.fromtimestamp(psutil.Process(process.pid).create_time(), UTC)
        measurement["process_creation_time"] = created.isoformat()
        if process.stdin is None:
            raise RuntimeError("target observer start pipe is unavailable")
        process.stdin.write(b"START\n")
        process.stdin.flush()
        while time.monotonic() < deadline and process.poll() is None:
            if _owned_endpoint(process.pid, port):
                try:
                    response = _http_read(port)
                    measurement["http_response_verified"] = response.startswith(
                        b"HTTP/1.1 200 OK\r\n"
                    ) and response.endswith(b"\r\n\r\nTARGET_OK")
                except OSError as error:
                    measurement["observer_error"] = f"HTTP check: {type(error).__name__}"
                break
            time.sleep(0.05)
        remaining = max(0.1, deadline - time.monotonic())
        stdout, stderr = process.communicate(timeout=remaining)
        measurement["exit_code"] = process.returncode
        measurement["raw_stdout"] = stdout[:4096].decode("utf-8", errors="replace")
        measurement["raw_stderr"] = stderr[:4096].decode("utf-8", errors="replace")
        if len(stdout) > 4096 or len(stderr) > 4096:
            raise ValueError("target observer output exceeded limit")
        decoded = json.loads(measurement["raw_stdout"])
        if not isinstance(decoded, dict):
            raise ValueError("target observer did not return an object")
        raw = cast(dict[str, Any], decoded)
        measurement["raw_result"] = raw
        if (
            process.returncode != 0
            or raw.get("address") != _ADDRESS
            or raw.get("port") != port
            or raw.get("protocol") != "tcp4"
            or raw.get("pid") != process.pid
            or not isinstance(raw.get("bind_started_at"), str)
            or not isinstance(raw.get("bind_completed_at"), str)
            or not isinstance(raw.get("finished_at"), str)
            or not isinstance(raw.get("bind_succeeded"), bool)
            or not isinstance(raw.get("served_http"), bool)
        ):
            raise ValueError("target observer result failed identity or schema validation")
        measurement["bind_succeeded"] = raw["bind_succeeded"]
        measurement["served_http"] = raw["served_http"]
        measurement["completed"] = True
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
        psutil.Error,
    ) as error:
        measurement["observer_error"] = f"{type(error).__name__}: {error}"
    finally:
        cleanup_errors: list[str] = []
        try:
            still_running = process.poll() is None
        except Exception as error:
            cleanup_errors.append(f"poll: {type(error).__name__}: {error}")
            still_running = True
        if still_running:
            try:
                process.terminate()
            except Exception as error:
                cleanup_errors.append(f"terminate: {type(error).__name__}: {error}")
            try:
                stdout, stderr = process.communicate(timeout=2)
            except Exception as error:
                cleanup_errors.append(f"communicate: {type(error).__name__}: {error}")
                try:
                    process.kill()
                except Exception as kill_error:
                    cleanup_errors.append(f"kill: {type(kill_error).__name__}: {kill_error}")
                try:
                    stdout, stderr = process.communicate(timeout=2)
                except Exception as final_error:
                    cleanup_errors.append(
                        f"final communicate: {type(final_error).__name__}: {final_error}"
                    )
                else:
                    measurement["raw_stdout"] = stdout[:4096].decode("utf-8", errors="replace")
                    measurement["raw_stderr"] = stderr[:4096].decode("utf-8", errors="replace")
            else:
                measurement["raw_stdout"] = stdout[:4096].decode("utf-8", errors="replace")
                measurement["raw_stderr"] = stderr[:4096].decode("utf-8", errors="replace")
            measurement["exit_code"] = process.returncode
        try:
            if process.poll() is None:
                try:
                    process.kill()
                    stdout, stderr = process.communicate(timeout=2)
                    measurement["raw_stdout"] = stdout[:4096].decode("utf-8", errors="replace")
                    measurement["raw_stderr"] = stderr[:4096].decode("utf-8", errors="replace")
                    measurement["exit_code"] = process.returncode
                except Exception as error:
                    cleanup_errors.append(
                        f"final kill/communicate: {type(error).__name__}: {error}"
                    )
                if process.poll() is None:
                    cleanup_errors.append("observer process exit not confirmed")
        except Exception as error:
            cleanup_errors.append(f"final poll: {type(error).__name__}: {error}")
        if cleanup_errors:
            measurement["completed"] = False
            prior = measurement["observer_error"]
            measurement["observer_error"] = "; ".join(
                [*([str(prior)] if prior is not None else []), *cleanup_errors]
            )
        measurement["finished_at"] = _stamp()
    return measurement


def target_configuration_digest(port: int) -> str:
    configuration = {"address": _ADDRESS, "port": port, "protocol": "tcp4", "script": _TARGET}
    return hashlib.sha256(json.dumps(configuration, sort_keys=True).encode()).hexdigest()


def _utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value)
        offset = stamp.utcoffset()
    except ValueError:
        return None
    if offset is None or offset.total_seconds() != 0:
        return None
    return stamp.astimezone(UTC)


def _valid_target_measurement(measurement: dict[str, Any]) -> bool:
    """Cross-check a completed child's raw result against its process wrapper."""
    raw_value = measurement.get("raw_result")
    raw_stdout = measurement.get("raw_stdout")
    if not isinstance(raw_value, dict) or not isinstance(raw_stdout, str):
        return False
    raw = cast(dict[str, Any], raw_value)
    if len(raw_stdout.encode("utf-8")) > 4096:
        return False
    try:
        if json.loads(raw_stdout) != raw:
            return False
    except (ValueError, TypeError):
        return False
    port = raw.get("port")
    pid = raw.get("pid")
    if (
        measurement.get("completed") is not True
        or measurement.get("observer_error") is not None
        or type(measurement.get("exit_code")) is not int
        or measurement.get("exit_code") != 0
        or type(port) is not int
        or not 0 < port <= 65_535
        or type(pid) is not int
        or pid <= 0
        or measurement.get("pid") != pid
        or measurement.get("configuration_digest") != target_configuration_digest(port)
        or raw.get("address") != _ADDRESS
        or raw.get("protocol") != "tcp4"
        or type(raw.get("bind_succeeded")) is not bool
        or type(raw.get("served_http")) is not bool
        or measurement.get("bind_succeeded") is not raw.get("bind_succeeded")
        or measurement.get("served_http") is not raw.get("served_http")
        or (raw.get("served_http") is True and raw.get("bind_succeeded") is not True)
    ):
        return False
    stamps = tuple(
        _utc_timestamp(value)
        for value in (
            measurement.get("started_at"),
            raw.get("bind_started_at"),
            raw.get("bind_completed_at"),
            raw.get("finished_at"),
            measurement.get("finished_at"),
        )
    )
    if any(stamp is None for stamp in stamps):
        return False
    return all(
        earlier <= later
        for earlier, later in pairwise(stamp for stamp in stamps if stamp is not None)
    )


def validated_target_bind_failure(
    measurement: dict[str, Any],
) -> tuple[datetime, dict[str, JsonValue]] | None:
    """Promote only a separately observed, exact Windows bind failure to facts.

    The sealed harness fault label is never an input. The caller still must
    persist these facts with a trusted source and case binding before assessment.
    """

    if not _valid_target_measurement(measurement):
        return None
    raw = cast(dict[str, Any], measurement["raw_result"])
    created = _utc_timestamp(measurement.get("process_creation_time"))
    started = _utc_timestamp(measurement.get("started_at"))
    bind_started = _utc_timestamp(raw.get("bind_started_at"))
    failed_at = _utc_timestamp(raw.get("bind_completed_at"))
    if (
        created is None
        or started is None
        or bind_started is None
        or failed_at is None
        or not started - timedelta(seconds=5) <= created <= bind_started <= failed_at
        or raw.get("bind_succeeded") is not False
        or raw.get("served_http") is not False
        or raw.get("winerror") != 10048
        or raw.get("errno") != 10048
        or raw.get("socket_exclusive_address_use") is not True
        or raw.get("socket_reuse_address") is not False
    ):
        return None
    return failed_at, {
        "contract_version": 1,
        "failure_kind": "winsock_bind",
        "winsock_error": 10048,
        "protocol": "tcp4",
        "local_address": _ADDRESS,
        "local_port": cast(int, raw["port"]),
        "target_pid": cast(int, raw["pid"]),
        "target_process_creation_time": created.isoformat(),
        "socket_exclusive_address_use": True,
        "socket_reuse_address": False,
    }


def target_recovered(measurement: dict[str, Any]) -> bool:
    """An observer error, absent result, or failed HTTP check never means recovery."""
    if not _valid_target_measurement(measurement):
        return False
    raw = cast(dict[str, Any], measurement["raw_result"])
    return (
        measurement.get("bind_succeeded") is True
        and measurement.get("served_http") is True
        and measurement.get("http_response_verified") is True
        and raw.get("errno") is None
        and raw.get("winerror") is None
        and raw.get("socket_error") is None
    )


def measurements_ordered(before: dict[str, Any], after: dict[str, Any]) -> bool:
    before_started = _utc_timestamp(before.get("started_at"))
    before_finished = _utc_timestamp(before.get("finished_at"))
    after_started = _utc_timestamp(after.get("started_at"))
    after_finished = _utc_timestamp(after.get("finished_at"))
    return (
        before_started is not None
        and before_finished is not None
        and after_started is not None
        and after_finished is not None
        and before_started <= before_finished < after_started <= after_finished
    )


def _listener_evidence(store: SQLiteStore, case_id: str) -> list[EvidenceRecord]:
    return [
        EvidenceRecord.model_validate_json(row.record_json)
        for row in store.evidence_page(
            case_id=case_id, offset=0, limit=100, category="network.listeners"
        )
    ]


def _complete_owned_listener(
    record: EvidenceRecord, port: int, pid: int, name: str, created: str
) -> bool:
    facts = {fact.name: fact.value for fact in record.facts}
    status = facts.get("collection_status")
    if status not in ("available", "partial"):
        return False
    if status == "partial" and set(record.limitations) != {
        "one or more listener process identities were unavailable"
    }:
        return False
    rows = facts.get("listeners")
    if (
        facts.get("omitted_listener_count") != 0
        or not isinstance(rows, list)
        or any(not isinstance(row, dict) for row in rows)
    ):
        return False
    listeners = cast(list[dict[str, Any]], rows)
    if len([row for row in listeners if row.get("local_port") == port]) != 1:
        return False
    return matching_owned_listener(listeners, port, pid, name, created)


def _run_registered_probe(
    *,
    investigator: Investigator,
    state: InvestigationState,
    probe_id: str,
    resource: ResourceClass,
    cost_ms: int,
    runtime: DiagnosticRuntime | None = None,
) -> None:
    proposal = ProbeProposal(
        probe_id=probe_id,
        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
        priority=1.0,
        estimated_cost_ms=cost_ms,
        resource_class=resource,
        dedupe_key=f"controlled:{probe_id}",
    )
    selected_runtime = runtime or investigator.runtime
    # The benchmark seeds an exact registered probe without invoking a model planner.
    results = selected_runtime.execute_plan(
        investigator._opened(state, (proposal,))  # pyright: ignore[reportPrivateUsage]
    )
    if len(results) != 1 or results[0].status is not TaskStatus.SUCCEEDED:
        raise RuntimeError(f"registered {probe_id} observation did not complete")


def _target_failure_runtime(store: SQLiteStore, measurement: dict[str, Any]) -> DiagnosticRuntime:
    validated = validated_target_bind_failure(measurement)
    if validated is None:
        raise RuntimeError("target-side bind failure observation is invalid")
    observed_at, facts = validated

    def observe(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        return ProbeObservation(
            summary="Separate target process reported an exact Windows bind failure.",
            facts=facts,
            observed_at=observed_at,
            captured_at=datetime.now(UTC),
            limitations=(
                "Controlled target-process observation; not an independent VM oracle.",
                "The harness fault label and post-action result are not probe inputs.",
            ),
        )

    definition = ProbeDefinition(
        manifest=ProbeManifest(
            probe_id="target.bind_failure",
            version=1,
            implementation_id="builtin.target.bind_failure",
            question="Did the controlled target report an exact bind failure?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
                self_writes=(SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=1000, max_output_bytes=4096, max_records=16),
            category="target",
        ),
        parameter_model=NoParameters,
        handler=observe,
        isolated=False,
    )
    return DiagnosticRuntime(
        store=store,
        case_service=CaseService(store, default_planner()),
        probe_runner=ProbeRunner(definitions=(definition,)),
    )


def run_owned_port_journey(database_path: Path, *, budget_ms: int = 30_000) -> dict[str, Any]:
    """Run the complete journey on Windows; report failures without claiming repair."""
    if os.name != "nt":
        raise RuntimeError("controlled host rehearsal requires Windows")
    if database_path.exists():
        raise FileExistsError(database_path)
    if budget_ms < 5000 or budget_ms > 600_000:
        raise ValueError("budget_ms must be between 5000 and 600000")
    port = _choose_port()
    result: dict[str, Any] = {
        "schema_version": 2,
        "classification": "controlled_host_rehearsal",
        "investigation_providers": {
            "attention": "keyword_baseline",
            "reasoning": "deterministic",
        },
        "diagnostic_accuracy_claim": False,
        "consumer_repair_claim": False,
        "wininet_proof": False,
        "action_scope": "harness_owned_disposable_process",
        "endpoint": f"{_ADDRESS}:{port}",
        "started_at": _stamp(),
        "before": {"bind_failed_address_in_use": False},
        "investigation": {"listener_probe_observed": False},
        "action": {"bound_to_owned_blocker": False, "owned_blocker_terminated": False},
        "after": {"target_bind_succeeded": False, "target_http_verified": False},
        "status": "failed",
        "failure_stage": None,
        "failure_reason": None,
        "timings_ms": {},
    }
    blocker: subprocess.Popen[bytes] | None = None
    stage = "start_owned_blocker"
    started = time.perf_counter()
    try:
        blocker = subprocess.Popen(
            [getattr(sys, "_base_executable", sys.executable), "-c", _BLOCKER, str(port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and blocker.poll() is None:
            if _owned_endpoint(blocker.pid, port):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("owned blocker did not establish its exact listener")
        owner = psutil.Process(blocker.pid)
        owner_name = owner.name()
        owner_created = datetime.fromtimestamp(owner.create_time(), UTC).isoformat()
        result["blocker"] = {"pid": blocker.pid, "name": owner_name, "created_at": owner_created}
        result["timings_ms"]["start_blocker"] = _elapsed(started)

        stage = "observe_listener_before_target"
        started = time.perf_counter()
        objective = f"The app cannot bind to {_ADDRESS}:{port} because the address is in use."
        with SQLiteStore(database_path) as store:
            investigator = default_investigator(store)
            state = investigator.create(
                objective=objective, budget_ms=budget_ms, max_rounds=2, max_probes=8
            )
            result["investigation"]["case_id"] = str(state.case_id)
            _run_registered_probe(
                investigator=investigator,
                state=state,
                probe_id="network.listeners",
                resource=ResourceClass.NETWORK,
                cost_ms=1500,
            )
            pre_records = _listener_evidence(store, str(state.case_id))
            if len(pre_records) != 1:
                raise RuntimeError("pre-failure listener snapshot is missing or ambiguous")
            pre_record = pre_records[0]
            if not _complete_owned_listener(
                pre_record, port, blocker.pid, owner_name, owner_created
            ):
                raise RuntimeError("pre-failure listener observation is incomplete")
            result["investigation"]["pre_failure_listener_evidence_id"] = str(
                pre_record.evidence_id
            )
            result["investigation"]["pre_failure_listener_observed_at"] = (
                pre_record.observed_at.isoformat()
            )
        result["timings_ms"]["pre_failure_listener"] = _elapsed(started)

        stage = "reproduce_bind_failure"
        started = time.perf_counter()
        before = _run_target_observer(port)
        result["before"]["observer"] = before
        raw_before = before.get("raw_result")
        before_result = cast(dict[str, Any], raw_before) if isinstance(raw_before, dict) else None
        result["before"]["bind_failed_address_in_use"] = bool(
            _valid_target_measurement(before)
            and before["bind_succeeded"] is False
            and before["served_http"] is False
            and before_result is not None
            and before_result.get("winerror") == 10048
        )
        if not result["before"]["bind_failed_address_in_use"]:
            raise RuntimeError("separate target did not report exact address-in-use bind failure")
        result["before"]["blocker_http_verified"] = b"BLOCKED" in _http_read(port)
        if not result["before"]["blocker_http_verified"]:
            raise RuntimeError("owned blocker did not serve its expected response")
        result["timings_ms"]["reproduce_failure"] = _elapsed(started)

        stage = "investigate_read_only"
        started = time.perf_counter()
        with SQLiteStore(database_path) as store:
            investigator = default_investigator(store)
            _run_registered_probe(
                investigator=investigator,
                state=state,
                probe_id="target.bind_failure",
                resource=ResourceClass.CPU,
                cost_ms=1000,
                runtime=_target_failure_runtime(store, before),
            )
            target_records = [
                EvidenceRecord.model_validate_json(row.record_json)
                for row in store.evidence_page(
                    case_id=str(state.case_id),
                    offset=0,
                    limit=10,
                    category="target.bind_failure",
                )
            ]
            if len(target_records) != 1:
                raise RuntimeError("target-side bind failure was not persisted exactly once")
            result["investigation"]["target_failure_evidence_id"] = str(
                target_records[0].evidence_id
            )
            result["investigation"]["target_failure_observed_at"] = target_records[
                0
            ].observed_at.isoformat()
            _run_registered_probe(
                investigator=investigator,
                state=state,
                probe_id="network.listeners",
                resource=ResourceClass.NETWORK,
                cost_ms=1500,
            )
            post_records = _listener_evidence(store, str(state.case_id))
            if len(post_records) != 2:
                raise RuntimeError("post-failure listener snapshot is missing or ambiguous")
            post_record = next(
                (record for record in post_records if record.evidence_id != pre_record.evidence_id),
                None,
            )
            if post_record is None or not _complete_owned_listener(
                post_record, port, blocker.pid, owner_name, owner_created
            ):
                raise RuntimeError("post-failure listener observation is incomplete")
            result["investigation"]["post_failure_listener_evidence_id"] = str(
                post_record.evidence_id
            )
            result["investigation"]["post_failure_listener_observed_at"] = (
                post_record.observed_at.isoformat()
            )
            finished = investigator.run(str(state.case_id))
            result["investigation"].update(
                {
                    "case_id": str(state.case_id),
                    "status": finished.status.value,
                    "outcome": finished.outcome.value,
                    "assessment": (
                        finished.assessment.model_dump(mode="json")
                        if finished.assessment is not None
                        else None
                    ),
                    "completed_probe_ids": list(finished.completed_probe_ids),
                    "warnings": list(finished.warnings),
                }
            )
            assessment = finished.assessment
            if (
                finished.outcome.value != "supported_explanation"
                or assessment is None
                or assessment.disposition.value != "supported_observed_explanation"
                or assessment.claim_kind is None
                or assessment.claim_kind.value != "owned_tcp_bind_conflict"
                or {str(item) for item in assessment.evidence_ids}
                != {
                    result["investigation"]["pre_failure_listener_evidence_id"],
                    result["investigation"]["target_failure_evidence_id"],
                    result["investigation"]["post_failure_listener_evidence_id"],
                }
            ):
                raise RuntimeError("investigator did not support the exact observed bind conflict")
            records = _listener_evidence(store, str(state.case_id))
            result["investigation"]["listener_evidence_ids"] = [
                str(record.evidence_id) for record in records
            ]
            result["investigation"]["listener_probe_observed"] = bool(records)
            matching = [
                record
                for record in records
                if _complete_owned_listener(record, port, blocker.pid, owner_name, owner_created)
            ]
            result["timings_ms"]["investigation"] = _elapsed(started)
            if {str(record.evidence_id) for record in matching} != {
                str(pre_record.evidence_id),
                str(post_record.evidence_id),
            }:
                raise RuntimeError(
                    "investigator did not persist two exact owned-listener identities"
                )
            evidence = post_record
            result["investigation"].update(
                {
                    "matched_evidence_id": str(evidence.evidence_id),
                    "observed_at": evidence.observed_at.isoformat(),
                    "captured_at": evidence.captured_at.isoformat(),
                    "source_id": evidence.source.source_id,
                    "limitations": list(evidence.limitations),
                }
            )

        stage = "bind_exact_owned_action"
        started = time.perf_counter()
        # Action is confined to the process this harness started. Recheck PID,
        # creation time, exact endpoint, and the Popen handle before changing it.
        if blocker.poll() is not None or not _owned_endpoint(blocker.pid, port):
            raise RuntimeError("owned blocker identity changed before action")
        current = psutil.Process(blocker.pid)
        if current.name().casefold() != owner_name.casefold() or not _same_creation(
            datetime.fromtimestamp(current.create_time(), UTC).isoformat(), owner_created
        ):
            raise RuntimeError("owned blocker process identity changed before action")
        result["action"].update(
            {
                "bound_to_owned_blocker": True,
                "action": "terminate_harness_started_process_only",
                "pid": blocker.pid,
                "process_creation_time": owner_created,
                "endpoint": f"{_ADDRESS}:{port}",
                "evidence_id": str(evidence.evidence_id),
                "authority": "harness_owned_disposable_process",
            }
        )
        blocker.terminate()
        blocker.wait(timeout=5)
        result["action"]["owned_blocker_terminated"] = True
        result["timings_ms"]["exact_action"] = _elapsed(started)

        stage = "check_target_after_action"
        started = time.perf_counter()
        after = _run_target_observer(port)
        result["after"]["observer"] = after
        result["after"]["target_bind_succeeded"] = (
            _valid_target_measurement(after) and after["bind_succeeded"] is True
        )
        result["after"]["target_http_verified"] = target_recovered(after)
        if before["configuration_digest"] != after["configuration_digest"]:
            raise RuntimeError("target observer configuration changed between measurements")
        if not measurements_ordered(before, after):
            raise RuntimeError("target measurements are not in causal order")
        if not result["after"]["target_http_verified"]:
            raise RuntimeError("separate target did not complete bind and HTTP verification")
        result["timings_ms"]["post_action_target_check"] = _elapsed(started)
        # This harness-owned action proves target recovery only. It does not
        # exercise consumer authorization or independent VM fault injection.
        result["status"] = "controlled_target_recovered_only"
    except Exception as error:
        result["failure_stage"] = stage
        result["failure_reason"] = f"{type(error).__name__}: {error}"
    finally:
        cleanup_errors: list[str] = []
        if blocker is not None:
            # Cleanup of our own Popen handle is distinct from the bound action.
            try:
                still_running = blocker.poll() is None
            except Exception as error:
                cleanup_errors.append(f"poll: {type(error).__name__}: {error}")
                still_running = True
            if still_running:
                try:
                    blocker.terminate()
                except Exception as error:
                    cleanup_errors.append(f"terminate: {type(error).__name__}: {error}")
                try:
                    blocker.wait(timeout=2)
                except Exception as error:
                    cleanup_errors.append(f"wait: {type(error).__name__}: {error}")
                    try:
                        blocker.kill()
                    except Exception as kill_error:
                        cleanup_errors.append(f"kill: {type(kill_error).__name__}: {kill_error}")
                    try:
                        blocker.wait(timeout=2)
                    except Exception as final_error:
                        cleanup_errors.append(
                            f"final wait: {type(final_error).__name__}: {final_error}"
                        )
            try:
                if blocker.poll() is None:
                    try:
                        blocker.kill()
                        blocker.wait(timeout=2)
                    except Exception as error:
                        cleanup_errors.append(f"final kill/wait: {type(error).__name__}: {error}")
                    if blocker.poll() is None:
                        cleanup_errors.append("owned blocker exit not confirmed")
            except Exception as error:
                cleanup_errors.append(f"final poll: {type(error).__name__}: {error}")
        result["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            result["status"] = "uncertain"
            if result["failure_reason"] is None:
                result["failure_stage"] = "owned_blocker_cleanup"
                result["failure_reason"] = "; ".join(cleanup_errors)
        result["ended_at"] = _stamp()
    return result


def _write_durable_report(stream: TextIO, result: dict[str, Any]) -> None:
    """Replace the reserved report's content and sync it before proceeding."""
    encoded = json.dumps(result, indent=2)
    stream.seek(0)
    stream.write(encoded)
    stream.truncate()
    stream.flush()
    os.fsync(stream.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--budget-ms", type=int, default=30_000)
    args = parser.parse_args()
    if args.database.resolve() == args.output.resolve():
        parser.error("database and output must differ")
    initial: dict[str, Any] = {
        "schema_version": 2,
        "classification": "controlled_host_rehearsal",
        "status": "in_progress",
        "started_at": _stamp(),
        "diagnostic_accuracy_claim": False,
        "consumer_repair_claim": False,
        "wininet_proof": False,
    }
    with args.output.open("x+", encoding="utf-8") as stream:
        _write_durable_report(stream, initial)
        try:
            result = run_owned_port_journey(args.database, budget_ms=args.budget_ms)
        except BaseException as error:
            uncertain = {
                **initial,
                "status": "uncertain",
                "failure_stage": "host_run_exception",
                "failure_reason": type(error).__name__,
                "ended_at": _stamp(),
            }
            _write_durable_report(stream, uncertain)
            if isinstance(error, Exception):
                return 1
            raise
        _write_durable_report(stream, result)
    return 0 if result["status"] == "controlled_target_recovered_only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
