import socket
from pathlib import Path
from typing import cast

from benchmarks.ab.systemsense_bridge import MCPToolBridge, qualify_systemsense
from benchmarks.ab.tools import SYSTEMSENSE_TOOL_NAMES
from systemsense.application.case_service import CaseService
from systemsense.mcp_server import (
    MCPWorkspace,
    default_case_runtime,
    default_planner,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _workspace(store: SQLiteStore) -> MCPWorkspace:
    service = CaseService(store, default_planner())
    return MCPWorkspace(
        store=store,
        case_service=service,
        case_runtime=default_case_runtime(store, case_service=service),
    )


def test_mcp_bridge_discovers_exact_surface_and_preserves_case_state(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        bridge = MCPToolBridge(_workspace(store))

        definitions = bridge.definitions()
        opened = cast(
            "dict[str, object]",
            bridge.call(
                "open_case",
                {
                    "kind": "application",
                    "symptom": "Local app exits with address in use.",
                    "target_traits": ["application", "network"],
                    "budget_ms": 2000,
                    "max_probes": 8,
                },
            ),
        )
        case = cast("dict[str, object]", opened["case"])
        brief = cast(
            "dict[str, object]",
            bridge.call(
                "get_case_brief",
                {"case_id": str(case["case_id"]), "max_chars": 1000},
            ),
        )

        assert {tool.name for tool in definitions} == SYSTEMSENSE_TOOL_NAMES
        assert len(cast("str", brief["text"])) <= 1000


def test_systemsense_qualification_checks_health_audit_and_signal(tmp_path: Path) -> None:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 8000))
        listener.listen()
        with SQLiteStore(tmp_path / "systemsense.db") as store:
            result = qualify_systemsense(
                workspace=_workspace(store),
                store=store,
                symptom=(
                    "My local development app stopped starting after I resumed the PC. "
                    "It prints a Windows socket address-in-use error and exits."
                ),
                expected_evidence_terms=("8000",),
                expected_coverage_categories=("application", "network"),
            )

        assert result.database_case_count_before == 0
        assert result.doctor_ok is True
        assert result.case_audit_ok is True
        assert result.signal_found is True
        assert result.explicit_coverage_found is False
        assert set(result.discovered_tool_names) == SYSTEMSENSE_TOOL_NAMES


def test_systemsense_qualification_does_not_treat_coverage_as_signal(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        result = qualify_systemsense(
            workspace=_workspace(store),
            store=store,
            symptom="Local app exits with a Windows socket address-in-use error.",
            expected_evidence_terms=("signal-that-cannot-exist",),
            expected_coverage_categories=("application", "network"),
        )

    assert result.signal_found is False
    assert result.explicit_coverage_found is False
