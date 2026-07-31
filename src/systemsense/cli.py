"""Local JSON CLI for cases, inventory, sentinel operation, and health checks."""

from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, NoReturn, cast

import anyio
import typer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel

from systemsense.application.case_service import CaseService
from systemsense.domain.cases import CaseKind
from systemsense.domain.ids import CaseId
from systemsense.domain.time import utc_now
from systemsense.mcp_server import (
    MCPWorkspace,
    default_case_runtime,
    default_database_path,
    default_planner,
)
from systemsense.platform.windows.capabilities import (
    CapabilityDetector,
    SystemCapabilityBackend,
)
from systemsense.platform.windows.eventlog import (
    FixedEventLogAdapter,
    PyWin32EventLogBackend,
)
from systemsense.sentinel import Sentinel, SentinelRunner
from systemsense.storage.sqlite_store import SQLiteStore

app = typer.Typer(
    name="systemsense",
    help="Read-only Windows diagnostic evidence for humans and AI agents.",
    no_args_is_help=True,
)
case_app = typer.Typer(help="Create and inspect diagnostic cases.")
inventory_app = typer.Typer(help="Inspect timestamped static system inventory.")
sentinel_app = typer.Typer(help="Run bounded passive Event Log polling.")
app.add_typer(case_app, name="case")
app.add_typer(inventory_app, name="inventory")
app.add_typer(sentinel_app, name="sentinel")


def _database_path() -> Path:
    override = os.environ.get("SYSTEMSENSE_DATA_DIR")
    if override:
        return Path(override) / "systemsense.db"
    return default_database_path()


def _workspace(store: SQLiteStore) -> MCPWorkspace:
    case_service = CaseService(store, default_planner())
    return MCPWorkspace(
        store=store,
        case_service=case_service,
        case_runtime=default_case_runtime(store, case_service=case_service),
    )


def _emit(value: object) -> None:
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json")
    else:
        payload = value
    typer.echo(
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _fail(message: str, *, code: int = 2) -> NoReturn:
    typer.echo(json.dumps({"error": message}, separators=(",", ":")), err=True)
    raise typer.Exit(code)


@case_app.command("create")
def create_case(
    symptom: Annotated[str, typer.Option(min=1, max=2000)],
    kind: Annotated[CaseKind, typer.Option()] = CaseKind.GENERAL,
    trait: Annotated[list[str] | None, typer.Option("--trait")] = None,
    budget_ms: Annotated[int, typer.Option(min=100, max=60_000)] = 10_000,
    max_probes: Annotated[int, typer.Option(min=1, max=32)] = 16,
) -> None:
    """Create a persisted case and return its deterministic probe plan."""

    with SQLiteStore(_database_path()) as store:
        opened = _workspace(store).open_case(
            kind=kind,
            symptom=symptom,
            target_traits=trait or (),
            budget_ms=budget_ms,
            max_probes=max_probes,
            created_at=utc_now(),
        )
        _emit(opened)


@case_app.command("show")
def show_case(
    case_id: Annotated[str, typer.Argument()],
    max_chars: Annotated[int, typer.Option(min=512, max=12_000)] = 6_000,
) -> None:
    """Show a compact cited case brief."""

    try:
        typed_case_id = CaseId(root=case_id)
        with SQLiteStore(_database_path()) as store:
            brief = _workspace(store).get_case_brief(
                case_id=typed_case_id,
                max_chars=max_chars,
            )
            _emit(brief)
    except ValueError as error:
        _fail(str(error))


@inventory_app.command("show")
def show_inventory(
    category: Annotated[str | None, typer.Option(max=64)] = None,
    limit: Annotated[int, typer.Option(min=1, max=500)] = 100,
) -> None:
    """List bounded current inventory records, optionally by exact category."""

    with SQLiteStore(_database_path()) as store:
        rows = store.inventory_page(category=category, limit=limit)
        items: list[dict[str, object]] = []
        for row in rows:
            record: object = json.loads(row.record_json)
            items.append(
                {
                    "category": row.category,
                    "fact_key": row.fact_key,
                    "observed_at": row.observed_at,
                    "record": record,
                }
            )
        _emit({"items": items, "count": len(items)})


@sentinel_app.command("run")
def run_sentinel(
    case_id: Annotated[str, typer.Option()],
    channel: Annotated[list[str] | None, typer.Option("--channel")] = None,
    limit: Annotated[int, typer.Option(min=1, max=100)] = 50,
    polls: Annotated[int, typer.Option(min=1, max=10_000)] = 1,
    interval_seconds: Annotated[float, typer.Option(min=0, max=3600)] = 5.0,
) -> None:
    """Poll only registered local Event Log channels for a bounded number of cycles."""

    try:
        typed_case_id = CaseId(root=case_id)
        with SQLiteStore(_database_path()) as store:
            if store.case(case_id) is None:
                _fail("case is unavailable")
            sentinel = Sentinel(
                FixedEventLogAdapter(PyWin32EventLogBackend()),
                store,
            )
            result = SentinelRunner(sentinel, now=utc_now).run(
                case_id=typed_case_id,
                channels=tuple(channel or ("Application", "System")),
                limit=limit,
                max_polls=polls,
                interval_seconds=interval_seconds,
            )
            _emit(result)
    except ValueError as error:
        _fail(str(error))


@app.command("doctor")
def doctor() -> None:
    """Report local capability coverage and database health."""

    snapshot = CapabilityDetector(SystemCapabilityBackend()).detect()
    with SQLiteStore(_database_path()) as store:
        _emit(
            {
                "database_integrity": store.integrity_check(),
                "database_schema_version": store.schema_version(),
                "platform": snapshot.platform,
                "windows_build": snapshot.windows_build,
                "architecture": snapshot.architecture,
                "captured_at": snapshot.captured_at.isoformat(),
                "capabilities": [
                    capability.model_dump(mode="json") for capability in snapshot.capabilities
                ],
            }
        )


async def _mcp_stdio_status() -> dict[str, object]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "systemsense.mcp_server"],
        env={"SYSTEMSENSE_DATA_DIR": str(_database_path().parent)},
    )
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as session:
            initialized = await session.initialize()
            listed = await session.list_tools()

    tools = sorted(tool.name for tool in listed.tools)
    expected = [
        "get_case_brief",
        "get_coverage_map",
        "get_evidence",
        "inspect_more",
        "open_case",
        "query_case_evidence",
    ]
    if initialized.instructions is None:
        raise RuntimeError("MCP server did not advertise agent instructions")
    if tools != expected:
        raise RuntimeError("MCP server tool surface does not match the six-tool contract")
    return {
        "instructions": True,
        "protocol_version": initialized.protocol_version,
        "server": initialized.server_info.name,
        "status": "ready",
        "tools": tools,
        "transport": "stdio",
    }


@app.command("mcp-check")
def mcp_check() -> None:
    """Verify the real stdio server handshake, instructions, and tool contract."""

    try:
        _emit(anyio.run(_mcp_stdio_status))
    except Exception as error:
        _fail(f"MCP readiness check failed: {error}")


@app.command("benchmark")
def benchmark() -> None:
    """Run the deterministic local engineering benchmark."""

    try:
        module = importlib.import_module("benchmarks.runner")
        benchmark_main = cast("Callable[[], int]", module.main)
    except (ImportError, AttributeError):
        _fail("benchmark harness is unavailable")
    raise typer.Exit(benchmark_main())


def main() -> None:
    app()


if __name__ == "__main__":
    main()
