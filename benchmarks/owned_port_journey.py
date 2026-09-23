"""Controlled real-host port conflict rehearsal with an owned blocker only.

The harness owns the fault and exact action. SystemSense only investigates. A
successful result is a host integration check, not diagnostic accuracy, a
consumer repair, or evidence about WinINet.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from systemsense.application.bootstrap import default_investigator
from systemsense.domain.evidence import EvidenceRecord
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


def _target_response(sock: socket.socket, port: int) -> bool:
    """Serve one real request on the target's newly bound socket."""
    sock.listen(1)
    sock.settimeout(3)
    with socket.create_connection((_ADDRESS, port), timeout=2) as client:
        client.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        with sock.accept()[0] as accepted:
            accepted.settimeout(2)
            if b"GET /health" not in accepted.recv(4096):
                return False
            accepted.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        client.settimeout(2)
        return b"HTTP/1.1 200 OK\r\n" in client.recv(4096)


def _listener_evidence(store: SQLiteStore, case_id: str) -> list[EvidenceRecord]:
    return [
        EvidenceRecord.model_validate_json(row.record_json)
        for row in store.evidence_page(
            case_id=case_id, offset=0, limit=100, category="network.listeners"
        )
    ]


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
        "schema_version": 1,
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

        stage = "reproduce_bind_failure"
        started = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
            try:
                target.bind((_ADDRESS, port))
            except OSError as error:
                if error.errno not in {98, 10048} and getattr(error, "winerror", None) != 10048:
                    raise
                result["before"]["bind_failed_address_in_use"] = True
                result["before"]["socket_error"] = str(error)
            else:
                raise RuntimeError("target unexpectedly bound while owned blocker was listening")
        result["before"]["blocker_http_verified"] = b"BLOCKED" in _http_read(port)
        if not result["before"]["blocker_http_verified"]:
            raise RuntimeError("owned blocker did not serve its expected response")
        result["timings_ms"]["reproduce_failure"] = _elapsed(started)

        stage = "investigate_read_only"
        started = time.perf_counter()
        with SQLiteStore(database_path) as store:
            investigator = default_investigator(store)
            objective = (
                f"Which process owns TCP listener {_ADDRESS}:{port}? "
                "The target application cannot bind because its address is in use."
            )
            state = investigator.create(
                objective=objective, budget_ms=budget_ms, max_rounds=2, max_probes=8
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
            records = _listener_evidence(store, str(state.case_id))
            result["investigation"]["listener_evidence_ids"] = [
                str(record.evidence_id) for record in records
            ]
            result["investigation"]["listener_probe_observed"] = bool(records)
            matching: list[EvidenceRecord] = []
            for record in records:
                facts = {fact.name: fact.value for fact in record.facts}
                raw = facts.get("listeners")
                if not isinstance(raw, list):
                    continue
                listeners = [item for item in raw if isinstance(item, dict)]
                if matching_owned_listener(listeners, port, blocker.pid, owner_name, owner_created):
                    matching.append(record)
            result["timings_ms"]["investigation"] = _elapsed(started)
            if len(matching) != 1:
                raise RuntimeError("investigator did not persist one exact owned-listener identity")
            evidence = matching[0]
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as target:
            target.bind((_ADDRESS, port))
            result["after"]["target_bind_succeeded"] = True
            result["after"]["target_http_verified"] = _target_response(target, port)
        if not result["after"]["target_http_verified"]:
            raise RuntimeError("target bound but did not serve expected HTTP response")
        result["timings_ms"]["post_action_target_check"] = _elapsed(started)
        # This harness recovery is real but does not make the investigator's
        # unsupported conclusion into an autonomous diagnosis.
        result["status"] = "controlled_target_recovered_only"
    except Exception as error:
        result["failure_stage"] = stage
        result["failure_reason"] = f"{type(error).__name__}: {error}"
    finally:
        if blocker is not None and blocker.poll() is None:
            # Cleanup of our own Popen handle is distinct from the bound action.
            blocker.terminate()
            try:
                blocker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                blocker.kill()
                blocker.wait(timeout=5)
        result["ended_at"] = _stamp()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--budget-ms", type=int, default=30_000)
    args = parser.parse_args()
    if args.database.resolve() == args.output.resolve():
        parser.error("database and output must differ")
    result = run_owned_port_journey(args.database, budget_ms=args.budget_ms)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    return 0 if result["status"] == "controlled_target_recovered_only" else 1


if __name__ == "__main__":
    raise SystemExit(main())
