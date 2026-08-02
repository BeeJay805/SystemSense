"""Use the real in-memory MCP protocol in the treatment agent."""

from __future__ import annotations

from typing import cast

import anyio
from mcp.client._memory import InMemoryTransport
from mcp.client.session import ClientSession
from pydantic import Field

from benchmarks.ab.contracts import ExperimentModel
from benchmarks.ab.tools import ToolDefinition
from systemsense.domain.cases import CaseKind
from systemsense.mcp_server import MCPWorkspace, create_mcp_server
from systemsense.storage.sqlite_store import SQLiteStore


class SystemSenseQualificationResult(ExperimentModel):
    database_case_count_before: int = Field(ge=0)
    doctor_ok: bool
    case_audit_ok: bool
    signal_found: bool
    explicit_coverage_found: bool
    discovered_tool_names: tuple[str, ...]
    case_id: str


class MCPToolBridge:
    """Persistent workspace behind short-lived, in-memory MCP sessions."""

    def __init__(self, workspace: MCPWorkspace) -> None:
        self._server = create_mcp_server(workspace)

    def definitions(self) -> tuple[ToolDefinition, ...]:
        return anyio.run(self._definitions)

    def call(self, name: str, arguments: dict[str, object]) -> object:
        return anyio.run(self._call, name, arguments)

    async def _definitions(self) -> tuple[ToolDefinition, ...]:
        async with InMemoryTransport(self._server, raise_exceptions=True) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                listed = await session.list_tools()
                return tuple(
                    ToolDefinition(
                        name=tool.name,
                        description=tool.description or tool.name,
                        parameters=cast("dict[str, object]", tool.input_schema),
                    )
                    for tool in sorted(listed.tools, key=lambda item: item.name)
                )

    async def _call(self, name: str, arguments: dict[str, object]) -> object:
        async with InMemoryTransport(self._server, raise_exceptions=True) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                result = await session.call_tool(name, arguments)
                if result.is_error:
                    messages = [str(item.model_dump(mode="json")) for item in result.content]
                    raise RuntimeError(f"SystemSense tool {name} failed: {'; '.join(messages)}")
                if result.structured_content is not None:
                    return result.structured_content
                return [item.model_dump(mode="json") for item in result.content]


def qualify_systemsense(
    *,
    workspace: MCPWorkspace,
    store: SQLiteStore,
    kind: CaseKind,
    symptom: str,
    expected_evidence_terms: tuple[str, ...],
    expected_coverage_categories: tuple[str, ...],
) -> SystemSenseQualificationResult:
    bridge = MCPToolBridge(workspace)
    definitions = bridge.definitions()
    database_case_count_before = store.case_count()
    doctor_ok = store.integrity_check() == "ok" and store.schema_version() >= 1
    opened = cast(
        "dict[str, object]",
        bridge.call(
            "open_case",
            {
                "kind": kind.value,
                "symptom": symptom,
                "target_traits": [],
                "budget_ms": 5000,
                "max_probes": 16,
            },
        ),
    )
    case_id = str(opened["case_id"])
    executed_probe_count = int(cast("int", opened["executed_probe_count"]))
    evidence_rows = store.evidence_page(case_id=case_id, offset=0, limit=256)
    coverage_rows = store.coverage_page(case_id=case_id, offset=0, limit=128)
    terms = tuple(term.casefold() for term in expected_evidence_terms)
    has_signal = all(
        any(term in row.record_json.casefold() for row in evidence_rows) for term in terms
    )
    coverage_categories = {category.casefold() for category in expected_coverage_categories}
    has_explicit_coverage = all(
        any(f'"category":"{category}"' in row.record_json.casefold() for row in coverage_rows)
        for category in coverage_categories
    )
    return SystemSenseQualificationResult(
        database_case_count_before=database_case_count_before,
        doctor_ok=doctor_ok,
        case_audit_ok=store.audit_count(case_id=case_id) == executed_probe_count,
        signal_found=has_signal,
        explicit_coverage_found=has_explicit_coverage,
        discovered_tool_names=tuple(tool.name for tool in definitions),
        case_id=case_id,
    )
