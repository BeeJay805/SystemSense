import socket
import urllib.request
from pathlib import Path
from typing import Never

import pytest

from benchmarks.report import build_report
from benchmarks.runner import load_benchmark_cases
from systemsense.application.case_service import CaseService
from systemsense.domain.cases import CaseKind
from systemsense.domain.time import utc_now
from systemsense.mcp_server import MCPWorkspace, default_case_runtime, default_planner
from systemsense.packs.application.processes import PsutilProcessBackend
from systemsense.packs.core.resources import PsutilResourceBackend, collect_resources
from systemsense.packs.core.system import PsutilSystemBackend, collect_system_identity
from systemsense.packs.local_ai.packages import current_packages
from systemsense.packs.local_ai.python import current_python_environment
from systemsense.packs.network.adapters import PsutilAdapterBackend
from systemsense.packs.network.connections import PsutilNetworkConnectionBackend
from systemsense.platform.windows.capabilities import (
    CapabilityDetector,
    SystemCapabilityBackend,
)
from systemsense.storage.sqlite_store import SQLiteStore


def test_normal_local_collection_and_case_flow_open_no_application_sockets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    attempts: list[str] = []

    def deny_socket(*_args: object, **_kwargs: object) -> Never:
        attempts.append("socket")
        raise AssertionError("application socket creation is forbidden")

    monkeypatch.setattr(socket, "socket", deny_socket)
    monkeypatch.setattr(socket, "create_connection", deny_socket)
    monkeypatch.setattr(urllib.request, "urlopen", deny_socket)

    now = utc_now()
    collect_system_identity(PsutilSystemBackend(), captured_at=now)
    collect_resources(PsutilResourceBackend(), captured_at=now)
    PsutilProcessBackend().snapshots(max_records=8)
    PsutilAdapterBackend().adapters()
    PsutilNetworkConnectionBackend().connections(max_records=8)
    current_python_environment()
    current_packages(max_records=32)
    CapabilityDetector(SystemCapabilityBackend()).detect(now=now)
    build_report(load_benchmark_cases())

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        case_service = CaseService(store, default_planner())
        workspace = MCPWorkspace(
            store=store,
            case_service=case_service,
            case_runtime=default_case_runtime(store, case_service=case_service),
        )
        opened = workspace.open_case(
            kind=CaseKind.GENERAL,
            symptom="offline fixture",
            target_traits=(),
            budget_ms=1_000,
            max_probes=8,
            created_at=now,
        )
        workspace.get_case_brief(case_id=opened.case.case_id, max_chars=800)

    assert attempts == []
