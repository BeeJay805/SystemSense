"""Local JSON CLI for cases, inventory, sentinel operation, and health checks."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, NoReturn

import typer
from pydantic import BaseModel

from systemsense.application.bootstrap import (
    default_case_runtime,
    default_database_path,
    default_investigator,
    default_passive_recorder,
    default_planner,
)
from systemsense.application.case_service import CaseService
from systemsense.application.workspace import EvidenceWorkspace
from systemsense.domain.cases import CaseKind
from systemsense.domain.ids import CaseId
from systemsense.domain.time import utc_now
from systemsense.inference.host_lease import HostInferenceLeaseLedger, LeaseBudget
from systemsense.inference.managed_laya import ManagedLayaAdmission, ManagedLayaPolicy
from systemsense.inference.profile import InferenceExecutionPolicy
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger
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

if TYPE_CHECKING:
    from systemsense.inference.factory import AdvisoryProviders
    from systemsense.inference.profile import LocalInferenceProfile

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


@app.command("investigate")
def investigate(
    objective: Annotated[str, typer.Argument()],
    budget_ms: Annotated[int | None, typer.Option(min=100, max=600_000)] = None,
    max_rounds: Annotated[int, typer.Option(min=1, max=12)] = 4,
    profile: Annotated[Path | None, typer.Option(dir_okay=False)] = None,
    pilot_capture_worker_input: Annotated[
        bool,
        typer.Option(help="Opt in to local unreviewed Laya worker-input capture for a pilot."),
    ] = False,
) -> None:
    """Run a durable read-only investigation and print its cited case report."""
    from systemsense.application.bootstrap import default_capabilities
    from systemsense.application.investigator import Investigator
    from systemsense.application.service import ApplicationService
    from systemsense.inference.factory import load_advisory_providers
    from systemsense.inference.profile import load_inference_profile

    try:
        inference_profile = load_inference_profile(profile)
        if pilot_capture_worker_input and (
            inference_profile.schema_version != 4
            or inference_profile.runtime_strategy != "warm-independent"
            or inference_profile.decision_provider != "laya"
        ):
            raise ValueError("pilot worker capture requires a warm independent Laya profile")
        execution_policy = inference_profile.resolved_execution_policy()
        managed_admission = (
            None
            if inference_profile.schema_version == 4
            else _managed_laya_admission(execution_policy)
        )
        providers = (
            _v4_providers(inference_profile)
            if inference_profile.schema_version == 4
            and inference_profile.runtime_strategy != "disabled"
            else load_advisory_providers(
                inference_profile.inference,
                fast_provider=(
                    "typed-feature"
                    if execution_policy.decision_provider == "typed-feature"
                    else "configured"
                ),
                laya_config=(
                    inference_profile.laya.runtime_config()
                    if execution_policy.decision_provider == "laya"
                    and inference_profile.laya.enabled
                    else None
                ),
                laya_timeout_seconds=inference_profile.laya.timeout_seconds,
                execution_policy=execution_policy,
                managed_admission=managed_admission,
            )
        )
    except ValueError as error:
        _fail(str(error))

    inference_status_source: dict[str, object] | Callable[[], dict[str, object]] = (
        inference_profile.inference_status()
    )
    if execution_policy.managed_gpu:

        def live_managed_status() -> dict[str, object]:
            return _managed_inference_status(
                inference_profile.inference_status(), providers.runtime_status()
            )

        inference_status_source = live_managed_status

    def factory(store: SQLiteStore) -> Investigator:
        return Investigator(
            store=store,
            runtime=default_case_runtime(store),
            capabilities=default_capabilities(),
            decision=providers.decision,
            reasoning=providers.reasoning,
            knowledge=providers.knowledge,
            catalog_attention=providers.catalog_attention,
            frontier_ranker=providers.frontier_ranker,
            capture_frontier_worker_inputs=pilot_capture_worker_input,
        )

    try:
        service = ApplicationService(
            _database_path(),
            factory=factory,
            inference_status=inference_status_source,
        )
        try:
            started = service.start_case(
                objective,
                inference_profile.investigation_budget_ms if budget_ms is None else budget_ms,
                max_rounds,
            )
            case_id = str(started["case_id"])
            try:
                service.wait()
            except KeyboardInterrupt:
                service.cancel_case(case_id)
                service.wait()
            _emit(service.get_case(case_id))
        finally:
            service.close()
    finally:
        providers.close()


@app.command("serve")
def serve_local(
    port: Annotated[int, typer.Option(min=1024, max=65535)] = 18765,
    enable_inference: Annotated[bool, typer.Option()] = False,
    decision_model: Annotated[str | None, typer.Option()] = None,
    reasoning_model: Annotated[str | None, typer.Option()] = None,
    allow_gpu: Annotated[bool, typer.Option()] = False,
    profile: Annotated[Path | None, typer.Option(dir_okay=False)] = None,
    prewarm_laya: Annotated[bool, typer.Option()] = False,
    prewarm_reasoning: Annotated[bool, typer.Option()] = False,
) -> None:
    """Open the local case application on loopback; inference is optional."""
    from systemsense.application.bootstrap import default_capabilities
    from systemsense.application.investigator import Investigator
    from systemsense.application.service import ApplicationService
    from systemsense.inference.factory import load_advisory_providers
    from systemsense.inference.laya_runtime import LayaRuntimeError
    from systemsense.inference.profile import load_inference_profile
    from systemsense.inference.settings import LocalInferenceConfig
    from systemsense.interface.server import serve

    inference_profile: LocalInferenceProfile | None = None

    legacy_options = (
        enable_inference or decision_model is not None or reasoning_model is not None or allow_gpu
    )
    if profile is not None and legacy_options:
        _fail("--profile cannot be combined with legacy inference model options")
    try:
        if legacy_options:
            config = LocalInferenceConfig(
                enabled=enable_inference,
                decision_model=decision_model,
                reasoning_model=reasoning_model,
                allow_gpu=allow_gpu,
            )
            laya_config = None
            laya_timeout = 60.0
            fast_provider = "configured"
            execution_policy = None
            managed_admission = None
            inference_status: dict[str, object] = {
                "enabled": config.enabled,
                "mode": "local" if config.enabled else "deterministic",
                "decision_model": config.decision_model,
                "reasoning_model": config.reasoning_model,
                "allow_gpu": config.allow_gpu,
            }
        else:
            inference_profile = load_inference_profile(profile)
            execution_policy = inference_profile.resolved_execution_policy()
            managed_admission = (
                None
                if inference_profile.schema_version == 4
                else _managed_laya_admission(execution_policy)
            )
            config = inference_profile.inference
            laya_config = (
                inference_profile.laya.runtime_config()
                if execution_policy.decision_provider == "laya" and inference_profile.laya.enabled
                else None
            )
            laya_timeout = inference_profile.laya.timeout_seconds
            fast_provider = (
                "typed-feature"
                if execution_policy.decision_provider == "typed-feature"
                else "configured"
            )
            inference_status = inference_profile.inference_status()
        if (prewarm_laya and (legacy_options or laya_config is None)) or (
            prewarm_reasoning
            and (
                legacy_options
                or execution_policy is None
                or execution_policy.reasoning_provider != "ollama"
            )
        ):
            _fail("model prewarm requires an enabled compatible local inference profile")
        providers = (
            _v4_providers(inference_profile)
            if inference_profile is not None
            and inference_profile.schema_version == 4
            and inference_profile.runtime_strategy != "disabled"
            else load_advisory_providers(
                config,
                fast_provider=fast_provider,
                laya_config=laya_config,
                laya_timeout_seconds=laya_timeout,
                execution_policy=execution_policy,
                managed_admission=managed_admission,
            )
        )
        if legacy_options:
            inference_status.update(providers.runtime_status())
            inference_status["enabled"] = providers.effective_mode != "deterministic"
            inference_status["mode"] = providers.effective_mode
    except ValueError as error:
        _fail(str(error))

    def factory(store: SQLiteStore) -> Investigator:
        return Investigator(
            store=store,
            runtime=default_case_runtime(store),
            capabilities=default_capabilities(),
            decision=providers.decision,
            reasoning=providers.reasoning,
            knowledge=providers.knowledge,
            catalog_attention=providers.catalog_attention,
            frontier_ranker=providers.frontier_ranker,
        )

    try:
        prewarm_report: dict[str, str] | None = None
        reasoning_prewarm_report: dict[str, str] | None = None
        if prewarm_laya:
            try:
                providers.prewarm_laya(timeout_seconds=laya_timeout)
            except LayaRuntimeError as error:
                prewarm_report = {"status": "degraded", "detail": str(error)}
            else:
                prewarm_report = {"status": "ready"}
            inference_status["decision_prewarm"] = prewarm_report
        if prewarm_reasoning:
            result = providers.prewarm_reasoning(timeout_seconds=config.timeout_seconds)
            reasoning_prewarm_report = {"status": result.status}
            if result.reason is not None:
                reasoning_prewarm_report["reason"] = result.reason
            inference_status["reasoning_prewarm"] = reasoning_prewarm_report
        inference_status_source: dict[str, object] | Callable[[], dict[str, object]] = (
            inference_status
        )
        if execution_policy is not None and execution_policy.managed_gpu:

            def live_managed_status() -> dict[str, object]:
                return _managed_inference_status(inference_status, providers.runtime_status())

            inference_status_source = live_managed_status
        service = ApplicationService(
            _database_path(),
            factory=factory,
            inference_status=inference_status_source,
            passive_factory=default_passive_recorder,
        )
        try:
            server = serve(service, port)
            startup: dict[str, object] = {
                "url": f"http://127.0.0.1:{port}",
                "read_only": True,
                "inference_enabled": (
                    inference_status_source()["enabled"]
                    if callable(inference_status_source)
                    else inference_status["enabled"]
                ),
            }
            if prewarm_report is not None:
                startup["laya_prewarm"] = prewarm_report
            if reasoning_prewarm_report is not None:
                startup["reasoning_prewarm"] = reasoning_prewarm_report
            _emit(startup)
            try:
                server.serve_forever(poll_interval=0.2)
            except KeyboardInterrupt:
                pass
            finally:
                server.server_close()
        finally:
            service.close()
    finally:
        providers.close()


@app.command("record")
def record_context(
    cycles: Annotated[int, typer.Option(min=1, max=288)] = 1,
    interval_seconds: Annotated[int, typer.Option(min=5, max=3600)] = 30,
) -> None:
    """Record bounded local context; never installs a background service."""
    from systemsense.application.service import ApplicationService

    service = ApplicationService(
        _database_path(),
        factory=default_investigator,
        passive_factory=default_passive_recorder,
    )
    try:
        service.start_recorder(interval_seconds, cycles)
        try:
            service.wait_recorder()
        except KeyboardInterrupt:
            service.stop_recorder()
            service.wait_recorder()
        _emit(service.recorder_status())
    finally:
        service.close()


def _database_path() -> Path:
    override = os.environ.get("SYSTEMSENSE_DATA_DIR")
    if override:
        return Path(override) / "systemsense.db"
    return default_database_path()


def _managed_laya_admission(
    execution_policy: InferenceExecutionPolicy,
) -> ManagedLayaAdmission | None:
    if not execution_policy.managed_gpu:
        return None
    resources = execution_policy.managed_resources
    if resources is None:
        raise ValueError("managed CUDA policy has no pinned resources")
    # Keep the host ledger stable when case storage is redirected for testing.
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data or not Path(local_app_data).is_absolute():
        raise ValueError("managed GPU admission requires a per-user application data root")
    ledger_path = (Path(local_app_data) / "SystemSense" / "host-gpu-lease-v3.sqlite3").resolve()
    try:
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ValueError("managed GPU lease store is unavailable") from error
    ledger = HostInferenceLeaseLedger(
        ledger_path,
        LeaseBudget(
            cpu_slots=1,
            ram_bytes=resources.peak_ram_bytes,
            vram_bytes=resources.peak_vram_bytes,
            gpu_device_index=resources.gpu_device_index,
        ),
    )
    return ManagedLayaAdmission(
        ManagedLayaPolicy(
            gpu_device_index=resources.gpu_device_index,
            gpu_uuid=resources.gpu_uuid,
            peak_ram_bytes=resources.peak_ram_bytes,
            peak_vram_bytes=resources.peak_vram_bytes,
            ram_reserve_bytes=resources.ram_reserve_bytes,
            target_vram_reserve_bytes=resources.target_vram_reserve_bytes,
            max_telemetry_age_ms=resources.max_telemetry_age_ms,
            renew_interval_seconds=resources.renew_interval_seconds,
        ),
        ledger,
    )


def _v4_providers(profile: LocalInferenceProfile) -> AdvisoryProviders:
    """Select the explicit v4 strategy on one shared, fenced host ledger."""

    from systemsense.inference.factory import (
        load_sequential_v4_providers,
        load_warm_v4_providers,
    )

    if profile.schema_version != 4:
        raise ValueError("v4 provider requires a validated profile")
    resources = profile.managed_resources
    pin = profile.managed_reasoning
    if resources is None or pin is None:
        raise ValueError("v4 provider requires both managed resource pins")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data or not Path(local_app_data).is_absolute():
        raise ValueError("managed GPU admission requires a per-user application data root")
    ledger_path = (Path(local_app_data) / "SystemSense" / "host-gpu-lease-v3.sqlite3").resolve()
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    warm = profile.runtime_strategy == "warm-independent"
    if not warm and profile.runtime_strategy != "sequential":
        raise ValueError("v4 runtime strategy must be explicitly selected")
    ledger = TreeHostInferenceLeaseLedger(
        ledger_path,
        LeaseBudget(
            cpu_slots=2 if warm else 1,
            ram_bytes=(
                resources.peak_ram_bytes + pin.peak_ram_bytes
                if warm
                else max(resources.peak_ram_bytes, pin.peak_ram_bytes)
            ),
            vram_bytes=(
                resources.peak_vram_bytes + pin.peak_vram_bytes
                if warm
                else max(resources.peak_vram_bytes, pin.peak_vram_bytes)
            ),
            gpu_device_index=resources.gpu_device_index,
        ),
    )
    migration = ledger.migrate_from_v3()
    if migration != "migrated":
        raise ValueError(f"v4 host lease migration blocked: {migration}")
    if warm:
        providers = load_warm_v4_providers(profile, ledger)
        try:
            providers.prewarm_laya(timeout_seconds=profile.laya.timeout_seconds)
        except Exception as error:
            providers.close()
            raise ValueError(f"warm Laya startup failed: {error}") from error
        return providers
    return load_sequential_v4_providers(profile, ledger)


def _managed_inference_status(
    configured: dict[str, object], runtime: dict[str, object]
) -> dict[str, object]:
    return {
        **configured,
        **runtime,
        "configured_enabled": configured.get("enabled") is True,
        # Enabled means an admitted local provider may work, not that its
        # model has already answered a request. Readiness stays a separate
        # decision_status and must not be inferred from lease ownership.
        "enabled": runtime.get("decision_status") in ("admitted_not_proven", "ready", "leased"),
        "mode": runtime.get("effective_mode", configured.get("mode")),
    }


def _workspace(store: SQLiteStore) -> EvidenceWorkspace:
    case_service = CaseService(store, default_planner())
    return EvidenceWorkspace(
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
            result = SentinelRunner(sentinel).run(
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
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as error:
        raise RuntimeError(
            "MCP support is unavailable; install the optional 'mcp' extra"
        ) from error

    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "systemsense.mcp_server"],
        env={"SYSTEMSENSE_DATA_DIR": str(_database_path().parent)},
    )
    with open(os.devnull, "w", encoding="utf-8") as errlog:
        async with stdio_client(parameters, errlog=errlog) as streams:
            async with ClientSession(*streams) as session:
                initialized = await session.initialize()
                listed = await session.list_tools()

    tools = sorted(tool.name for tool in listed.tools)
    if initialized.instructions is None:
        raise RuntimeError("MCP server did not advertise agent instructions")
    if not tools or len(tools) != len(set(tools)):
        raise RuntimeError("MCP adapter did not register a non-empty, unique tool surface")
    return {
        "instructions": True,
        "protocol_version": initialized.protocol_version,
        "server": initialized.server_info.name,
        "status": "ready",
        "tool_count": len(tools),
        "tools": tools,
        "transport": "stdio",
    }


@app.command("mcp-check")
def mcp_check() -> None:
    """Verify the real stdio server handshake, instructions, and tool contract."""

    try:
        import anyio
    except ImportError as error:
        _fail(f"MCP support is unavailable; install the optional 'mcp' extra ({error})")

    try:
        _emit(anyio.run(_mcp_stdio_status))
    except Exception as error:
        _fail(f"MCP readiness check failed: {error}")


def main() -> None:
    app()


def mcp_main() -> None:
    """Launch the optional MCP adapter without coupling core CLI imports to MCP."""

    try:
        from systemsense.mcp_server import main as adapter_main
    except ModuleNotFoundError as error:
        if error.name not in {"anyio", "mcp"}:
            raise
        typer.echo(
            json.dumps(
                {"error": "MCP support is unavailable; install the optional 'mcp' extra"},
                separators=(",", ":"),
            ),
            err=True,
        )
        raise SystemExit(2) from None
    adapter_main()


if __name__ == "__main__":
    main()
