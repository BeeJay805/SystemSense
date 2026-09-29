"""Blinded real-Windows loopback qualification through the normal case service.

The evaluator owns only temporary high-port loopback HTTP servers. Fixture mode,
independent HTTP results, and socket-table reads stay in the evaluator directory;
Dyad receives the same exact-URL user report in every case. This is a narrow
network-task benchmark, not general Windows diagnostic qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from secrets import token_hex
from typing import Any

import psutil

from systemsense.application.bootstrap import (
    default_capabilities,
    default_case_runtime,
    default_investigator,
    default_planner,
)
from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime, default_probe_scheduler
from systemsense.application.service import ApplicationService
from systemsense.application.subscription_setup import load_desktop_subscription_providers
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.inference.factory import AdvisoryProviders
from systemsense.orchestration.executor import CancellationSignal
from systemsense.orchestration.probes import ProbeRun, ProbeRunner, ProbeRunStatus
from systemsense.orchestration.scheduler import HostWorkSlot
from systemsense.packs.runtime import default_probe_definitions
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_ROOT = Path(__file__).resolve().parents[1]
_CASES = _ROOT / "benchmarks" / "fixtures" / "private_alpha_cases.json"
_KEY = _ROOT / "benchmarks" / "ground_truth" / "private_alpha_recipes.json"
_TERMINAL = {"complete", "cancelled", "failed", "interrupted"}


def _stamp() -> str:
    return datetime.now(UTC).isoformat()


def _write(path: Path, value: object) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OwnedServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, port: int, nonce: str, mode: str) -> None:
        self.nonce = nonce
        self.mode = mode
        self.request_count = 0
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                owner.request_count += 1
                if self.path != f"/health/{owner.nonce}":
                    self.send_error(404)
                    return
                response_mode = owner.mode
                if response_mode == "intermittent":
                    response_mode = "http_503" if owner.request_count % 2 else "healthy"
                if response_mode == "stall":
                    time.sleep(5)
                    return
                if response_mode == "http_503":
                    self.send_error(503)
                    return
                body = (
                    ("0" * 32 if response_mode == "wrong_nonce" else owner.nonce) + "\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        super().__init__(("127.0.0.1", port), Handler)
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    def start(self) -> OwnedServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=3)


def _port() -> int:
    with socket.socket() as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        port = int(endpoint.getsockname()[1])
    if port < 49152:
        raise RuntimeError("the exact task requires a high dynamic port")
    return port


def _get(port: int, nonce: str) -> dict[str, object]:
    started = time.monotonic()
    result: dict[str, object] = {"at": _stamp(), "target": f"127.0.0.1:{port}"}
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request("GET", f"/health/{nonce}")
        response = connection.getresponse()
        body = response.read(65) if response.status == 200 else b""
        result.update(
            status=response.status,
            outcome=(
                "healthy"
                if response.status == 200 and body == (nonce + "\n").encode()
                else "wrong_response"
                if response.status == 200
                else f"http_{response.status}"
            ),
        )
    except (OSError, TimeoutError) as error:
        result.update(outcome="request_error", error_type=type(error).__name__)
    finally:
        connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def _listeners(port: int) -> dict[str, object]:
    at = _stamp()
    try:
        rows = [
            {"pid": row.pid, "address": row.laddr.ip}
            for row in psutil.net_connections(kind="tcp")
            if row.status == "LISTEN" and row.laddr and row.laddr.port == port
        ]
    except (OSError, RuntimeError, psutil.Error) as error:
        return {"at": at, "status": "unavailable", "error_type": type(error).__name__}
    return {"at": at, "status": "available", "rows": rows}


def _oracle(target: int, target_nonce: str, control: int, control_nonce: str) -> dict[str, Any]:
    return {
        "target": _get(target, target_nonce),
        "target_listeners": _listeners(target),
        "control": _get(control, control_nonce),
        "control_listeners": _listeners(control),
    }


class ResourceSampler:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self.samples: list[dict[str, float]] = []
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        owner = psutil.Process()
        while not self._stop.is_set():
            rss = 0
            for process in [owner, *owner.children(recursive=True)]:
                try:
                    rss += process.memory_info().rss
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            self.samples.append({"elapsed_ms": time.monotonic() * 1000, "tree_rss_bytes": rss})
            self._stop.wait(0.2)

    def __enter__(self) -> ResourceSampler:
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


class DenyingListenerRunner(ProbeRunner):
    """Synthetic missing-access control; it never changes Windows permissions."""

    def __init__(self) -> None:
        super().__init__(definitions=default_probe_definitions())

    def run(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
        host_slot: HostWorkSlot | None = None,
    ) -> ProbeRun:
        if probe_id != "network.listeners":
            return super().run(
                probe_id,
                parameters,
                deadline_at=deadline_at,
                cancellation=cancellation,
                host_slot=host_slot,
            )
        now = utc_now()
        return ProbeRun(
            execution_id=ExecutionId.new(),
            probe_id=probe_id,
            status=ProbeRunStatus.DENIED,
            started_at=now,
            finished_at=now,
            elapsed_ms=0,
            error="Synthetic evaluation: listener-table access denied; no Windows ACL changed.",
        )


def _factory(
    providers: AdvisoryProviders | None, *, synthetic_missing_access: bool
) -> Callable[[SQLiteStore], Investigator]:
    def make(store: SQLiteStore) -> Investigator:
        if providers is None and not synthetic_missing_access:
            return default_investigator(store)
        runtime = (
            DiagnosticRuntime(
                store=store,
                case_service=CaseService(store, default_planner()),
                probe_runner=DenyingListenerRunner(),
                scheduler=default_probe_scheduler(store),
            )
            if synthetic_missing_access
            else default_case_runtime(store)
        )
        return Investigator(
            store=store,
            runtime=runtime,
            capabilities=default_capabilities(),
            decision=(
                KeywordBaselineDecisionProvider() if providers is None else providers.decision
            ),
            reasoning=(
                DeterministicReasoningProvider() if providers is None else providers.reasoning
            ),
            knowledge=None if providers is None else providers.knowledge,
            catalog_attention=None if providers is None else providers.catalog_attention,
            frontier_ranker=None if providers is None else providers.frontier_ranker,
        )

    return make


def _product_case(
    output: Path,
    objective: str,
    providers: AdvisoryProviders | None,
    *,
    synthetic_missing_access: bool,
    budget_ms: int,
    max_rounds: int,
) -> dict[str, Any]:
    started = time.monotonic()
    with ResourceSampler() as resources:
        service = ApplicationService(
            output / "cases.db",
            factory=_factory(providers, synthetic_missing_access=synthetic_missing_access),
            inference_status={
                "enabled": providers is not None,
                "mode": "laya-sol" if providers is not None else "deterministic",
                "start_allowed": True,
            },
        )
        try:
            case = service.start_case(objective, budget_ms, max_rounds)
            case_id = str(case["case_id"])
            deadline = time.monotonic() + budget_ms / 1000 + 10
            while time.monotonic() < deadline:
                result = service.get_case(case_id)
                if result["status"] in _TERMINAL:
                    break
                time.sleep(0.2)
            else:
                service.cancel_case(case_id)
                result = service.get_case(case_id)
                raise TimeoutError(f"case did not finish: {result['status']}")
        finally:
            service.close()
    _write(output / "product-case.json", result)
    _write(
        output / "runtime.json",
        {
            "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
            "resource_samples": len(resources.samples),
            "tree_rss_first_bytes": resources.samples[0]["tree_rss_bytes"],
            "tree_rss_peak_bytes": max(row["tree_rss_bytes"] for row in resources.samples),
            "resource_scope": "evaluator Python process plus descendants; 200 ms samples",
        },
    )
    return result


def _trial(
    output: Path,
    case_id: str,
    mode: str,
    providers: AdvisoryProviders | None,
    *,
    objective_template: str = "My local status page {exact_url} is not working",
    budget_ms: int = 90_000,
    max_rounds: int = 6,
) -> None:
    output.mkdir(exist_ok=False)
    target, control = _port(), _port()
    while target == control:
        control = _port()
    target_nonce, control_nonce = token_hex(16), token_hex(16)
    if objective_template.count("{exact_url}") != 1 or objective_template.count("{") != 1:
        raise ValueError("case objective must contain exactly one exact URL placeholder")
    objective = objective_template.replace(
        "{exact_url}", f"http://127.0.0.1:{target}/health/{target_nonce}"
    )
    _write(output / "intake.json", {"case_id": case_id, "objective": objective})
    target_server: OwnedServer | None = None
    control_server: OwnedServer | None = None
    restored = False
    try:
        target_server = OwnedServer(target, target_nonce, "healthy").start()
        control_server = OwnedServer(control, control_nonce, "healthy").start()
        baseline = _oracle(target, target_nonce, control, control_nonce)
        _write(output / "evaluator" / "baseline.json", baseline)
        if (
            baseline["target"]["outcome"] != "healthy"
            or baseline["control"]["outcome"] != "healthy"
        ):
            raise RuntimeError("independent healthy baseline failed")
        if mode != "healthy":
            target_server.stop()
            target_server = None
            if mode != "no_listener":
                target_server = OwnedServer(
                    target, target_nonce, "http_503" if mode == "missing_access" else mode
                ).start()
        during = _oracle(target, target_nonce, control, control_nonce)
        _write(output / "evaluator" / "during.json", during)
        if during["control"]["outcome"] != "healthy":
            raise RuntimeError("healthy control drifted")
        if mode == "no_listener" and during["target_listeners"]["rows"]:
            raise RuntimeError("target still has a listener")
        result = _product_case(
            output,
            objective,
            providers,
            synthetic_missing_access=mode == "missing_access",
            budget_ms=budget_ms,
            max_rounds=max_rounds,
        )
        midpoint = _oracle(target, target_nonce, control, control_nonce)
        _write(output / "evaluator" / "midpoint.json", midpoint)
        if midpoint["control"]["outcome"] != "healthy":
            raise RuntimeError("healthy control drifted during investigation")
        _write(
            output / "result-index.json",
            {"case_id": case_id, "outcome": result["outcome"], "status": result["status"]},
        )
    finally:
        if target_server is not None:
            target_server.stop()
        try:
            target_server = OwnedServer(target, target_nonce, "healthy").start()
            restore = _oracle(target, target_nonce, control, control_nonce)
            restored = restore["target"]["outcome"] == restore["control"]["outcome"] == "healthy"
            _write(output / "evaluator" / "restored.json", {**restore, "verified": restored})
        finally:
            if target_server is not None:
                target_server.stop()
            if control_server is not None:
                control_server.stop()
            _write(
                output / "evaluator" / "cleanup.json",
                {"restored": restored, "owned_servers_stopped": True},
            )
    if not restored:
        raise RuntimeError("independent restoration failed")


def run(split: str, output: Path, route: str) -> None:
    if (
        os.name != "nt"
        or not output.is_absolute()
        or output.exists()
        or output.is_relative_to(_ROOT)
    ):
        raise ValueError("a new private absolute output directory on Windows is required")
    cases = json.loads(_CASES.read_text(encoding="utf-8"))
    recipes = json.loads(_KEY.read_text(encoding="utf-8"))
    if cases["schema_version"] != recipes["schema_version"] or len(cases["cases"]) < 20:
        raise ValueError("frozen suite is incomplete")
    case_ids = {item["case_id"] for item in cases["cases"]}
    if case_ids != set(recipes["recipes"]):
        raise ValueError("case and evaluator recipe IDs differ")
    output.mkdir(parents=True)
    _write(
        output / "frozen-input.json",
        {
            "at": _stamp(),
            "split": split,
            "route": route,
            "case_manifest_sha256": _sha(_CASES),
            "evaluator_key_sha256": _sha(_KEY),
            "head": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=_ROOT, text=True
            ).strip(),
            "dirty_diff_sha256": hashlib.sha256(
                subprocess.check_output(["git", "diff", "--binary"], cwd=_ROOT)
            ).hexdigest(),
        },
    )
    startup = time.monotonic()
    providers = load_desktop_subscription_providers() if route == "model" else None
    _write(
        output / "model-startup.json",
        {
            "elapsed_ms": round((time.monotonic() - startup) * 1000, 3),
            "runtime": None if providers is None else providers.runtime_status(),
        },
    )
    try:
        for item in cases["cases"]:
            if item["split"] != split:
                continue
            case_id = item["case_id"]
            case_output = output / case_id
            case_started = time.monotonic()
            try:
                _trial(
                    case_output,
                    case_id,
                    recipes["recipes"][case_id]["mode"],
                    providers,
                    objective_template=item["objective_template"],
                    budget_ms=item["budget_ms"],
                    max_rounds=item["max_rounds"],
                )
            except BaseException as error:
                _write(
                    case_output / "failure.json",
                    {
                        "at": _stamp(),
                        "elapsed_ms": round((time.monotonic() - case_started) * 1000, 3),
                        "error_type": type(error).__name__,
                        "error": str(error)[:500],
                    },
                )
                raise
    finally:
        if providers is not None:
            providers.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("development", "holdout"), required=True)
    parser.add_argument("--route", choices=("model", "basic"), default="model")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.split, args.output, args.route)
