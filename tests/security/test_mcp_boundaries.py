import json
from pathlib import Path
from typing import cast

import anyio
import pytest
from mcp.server.mcpserver import MCPServer

from systemsense.application.case_service import CaseService
from systemsense.domain.cases import CaseKind
from systemsense.domain.ids import EvidenceId
from systemsense.domain.time import utc_now
from systemsense.mcp_server import (
    MCPWorkspace,
    WorkspaceAccessError,
    create_mcp_server,
    run_stdio,
)
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.storage.sqlite_store import SQLiteStore

_FORBIDDEN_FIELDS = {"command", "path", "query_language", "sql", "url", "xpath"}


def _schema_contains(schema: object, key: str) -> bool:
    if isinstance(schema, dict):
        mapping = cast("dict[object, object]", schema)
        return key in mapping or any(_schema_contains(value, key) for value in mapping.values())
    if isinstance(schema, list):
        values = cast("list[object]", schema)
        return any(_schema_contains(value, key) for value in values)
    return False


def _workspace(store: SQLiteStore) -> MCPWorkspace:
    planner = DeterministicPlanner(
        candidates=(
            ProbeCandidate(
                probe_id="core.system",
                cost_ms=50,
                value=1.0,
                common=True,
            ),
        )
    )
    return MCPWorkspace(store=store, case_service=CaseService(store, planner))


def test_mcp_input_schemas_are_bounded_and_expose_no_arbitrary_access(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        server = create_mcp_server(_workspace(store))
        tools = anyio.run(server.list_tools)

    for tool in tools:
        properties = cast("dict[str, object]", tool.input_schema.get("properties", {}))
        assert not (_FORBIDDEN_FIELDS & set(properties))
        for name, schema in properties.items():
            if name in {"symptom", "cursor", "category"}:
                assert _schema_contains(schema, "maxLength")
            if name in {"limit", "max_chars", "budget_ms", "max_probes"}:
                assert _schema_contains(schema, "maximum")


def test_cross_case_evidence_and_tampered_cursors_are_rejected(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        workspace = _workspace(store)
        first = workspace.open_case(
            kind=CaseKind.GENERAL,
            symptom="first",
            target_traits=(),
            budget_ms=1_000,
            max_probes=8,
            created_at=utc_now(),
        )
        second = workspace.open_case(
            kind=CaseKind.GENERAL,
            symptom="second",
            target_traits=(),
            budget_ms=1_000,
            max_probes=8,
            created_at=utc_now(),
        )
        evidence_id = EvidenceId(root="ev_00000000000000000000000000000000")
        for number in range(6):
            suffix = f"{number:032x}"
            source_id = f"src_{number:064x}"
            captured_at = utc_now().isoformat()
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=str(first.case.case_id),
                    evidence_id=f"ev_{suffix}",
                    source_id=source_id,
                    record_json=json.dumps(
                        {
                            "schema_version": 1,
                            "evidence_id": f"ev_{suffix}",
                            "case_id": str(first.case.case_id),
                            "statement_kind": "observed_fact",
                            "observed_at": captured_at,
                            "captured_at": captured_at,
                            "source": {
                                "type": "fixture",
                                "source_id": source_id,
                                "locator": {},
                            },
                            "collector": {
                                "id": "application.fixture",
                                "version": 1,
                                "execution_id": f"exec_{suffix}",
                            },
                            "summary": f"fixture {number}",
                            "facts": [],
                            "extraction": {
                                "confidence": 1.0,
                                "parser": "fixture",
                                "parser_version": 1,
                            },
                            "limitations": [],
                            "sensitivity": "system_metadata",
                        }
                    ),
                    captured_at=captured_at,
                )

        with pytest.raises(WorkspaceAccessError):
            workspace.get_evidence(
                case_id=second.case.case_id,
                evidence_id=evidence_id,
            )

        page = workspace.query_case_evidence(
            case_id=first.case.case_id,
            category=None,
            statement_kind=None,
            limit=5,
            cursor=None,
        )
        if page.next_cursor is not None:
            with pytest.raises(WorkspaceAccessError):
                workspace.query_case_evidence(
                    case_id=first.case.case_id,
                    category=None,
                    statement_kind=None,
                    limit=5,
                    cursor=page.next_cursor + "tampered",
                )


def test_public_runner_forces_stdio_transport() -> None:
    transports: list[str] = []

    class FakeServer:
        def run(self, transport: str) -> None:
            transports.append(transport)

    run_stdio(cast("MCPServer[None]", FakeServer()))

    assert transports == ["stdio"]
