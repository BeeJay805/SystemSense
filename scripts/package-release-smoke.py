"""Exercise an installed SystemSense wheel without collectors or model providers."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.util
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import systemsense
from systemsense.application.passive import PassiveRecorder, PassiveRecorderConfig
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.inference.profile import load_inference_profile
from systemsense.knowledge import KnowledgeQuery, ReferenceKnowledgeGraph
from systemsense.orchestration.executor import CancellationSignal
from systemsense.orchestration.probes import ProbeObservation, ProbeRun, ProbeRunStatus
from systemsense.platform.windows.eventlog import EventQuery, QueryStatus
from systemsense.storage.sqlite_store import SQLiteStore


class _Manifest:
    version = 1


class _FixtureRunner:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def manifest(self, probe_id: str) -> _Manifest:
        del probe_id
        return _Manifest()

    def run(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> ProbeRun:
        del parameters
        if deadline_at is None or cancellation is None:
            raise AssertionError("passive fixture must receive a deadline and cancellation")
        self.calls.append(probe_id)
        now = datetime.now(UTC)
        return ProbeRun(
            execution_id=ExecutionId.new(),
            probe_id=probe_id,
            status=ProbeRunStatus.OK,
            started_at=now,
            finished_at=now,
            elapsed_ms=0,
            observation=ProbeObservation(
                summary=f"{probe_id} package fixture",
                facts={"probe_id": probe_id},
                observed_at=now,
                captured_at=now,
            ),
        )


class _NoEvents:
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> EventQuery:
        del channel, after_record_id, limit
        if deadline_at is None or cancellation is None:
            raise AssertionError("event fixture must receive a deadline and cancellation")
        return EventQuery(status=QueryStatus.OK)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--forbid-source-root", type=Path, required=True)
    parser.add_argument("--require-core-only", action="store_true")
    return parser.parse_args()


def _isolated_default_inference_status(*, parent: Path) -> dict[str, object]:
    """Load the implicit default without consulting the operator's real profile."""

    previous_data_dir = os.environ.get("SYSTEMSENSE_DATA_DIR")
    with tempfile.TemporaryDirectory(prefix="systemsense-package-profile-", dir=parent) as root:
        os.environ["SYSTEMSENSE_DATA_DIR"] = root
        try:
            return load_inference_profile().inference_status()
        finally:
            if previous_data_dir is None:
                os.environ.pop("SYSTEMSENSE_DATA_DIR", None)
            else:
                os.environ["SYSTEMSENSE_DATA_DIR"] = previous_data_dir


def main() -> int:
    args = _arguments()
    args.database.parent.mkdir(parents=True, exist_ok=True)
    package_path = Path(systemsense.__file__).resolve()
    source_root = args.forbid_source_root.resolve()
    if package_path.is_relative_to(source_root):
        raise AssertionError(f"imported the source checkout instead of the wheel: {package_path}")

    distribution = importlib.metadata.distribution("systemsense")
    entry_points = {
        item.name: item.value
        for item in distribution.entry_points
        if item.group == "console_scripts"
    }
    expected_entry_points = {
        "systemsense": "systemsense.cli:main",
        "systemsense-mcp": "systemsense.cli:mcp_main",
    }
    if entry_points != expected_entry_points:
        raise AssertionError(f"unexpected console entry points: {entry_points}")

    metadata = distribution.metadata
    extras = set(metadata.get_all("Provides-Extra") or ())
    if extras != {"local-models", "mcp"}:
        raise AssertionError(f"unexpected optional extras: {sorted(extras)}")

    optional_modules = {
        name: importlib.util.find_spec(name) is not None for name in ("mcp", "tokenizers", "torch")
    }
    if args.require_core_only and any(optional_modules.values()):
        raise AssertionError(f"base wheel pulled optional modules: {optional_modules}")

    graph = ReferenceKnowledgeGraph.load_default()
    first_relation = graph.pack.relations[0]
    packet = graph.query(KnowledgeQuery(node_ids=(first_relation.source_node_id,), max_relations=4))
    if not packet.relations or packet.disclaimer == "":
        raise AssertionError("bundled reference graph did not return a bounded cited packet")

    inference_status = _isolated_default_inference_status(parent=args.database.parent)
    if inference_status != {
        "enabled": False,
        "mode": "deterministic",
        "profile_id": "deterministic-default",
    }:
        raise AssertionError(f"unexpected default inference status: {inference_status}")

    runner = _FixtureRunner()
    with SQLiteStore(args.database) as store:
        result = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=_NoEvents(),
            config=PassiveRecorderConfig(interval_seconds=5),
        ).capture_once()
        database_status = {
            "integrity": store.integrity_check(),
            "schema_version": store.schema_version(),
            "probe_executions": store.probe_execution_count(case_id=str(result.case_id)),
        }

    if runner.calls != ["core.system", "core.resources"]:
        raise AssertionError(f"unexpected passive fixture calls: {runner.calls}")
    if (result.evidence_persisted, result.coverage_persisted) != (2, 4):
        raise AssertionError(f"unexpected passive persistence counts: {result}")
    if database_status != {"integrity": "ok", "schema_version": 5, "probe_executions": 4}:
        raise AssertionError(f"unexpected database status: {database_status}")

    print(
        json.dumps(
            {
                "database": database_status,
                "entry_points": entry_points,
                "graph": {
                    "nodes": len(graph.pack.nodes),
                    "relations": len(graph.pack.relations),
                    "selected_relations": len(packet.relations),
                    "sources": len(packet.sources),
                },
                "inference": inference_status,
                "optional_modules": optional_modules,
                "package_path": str(package_path),
                "passive_fixture": {
                    "calls": runner.calls,
                    "coverage_persisted": result.coverage_persisted,
                    "evidence_persisted": result.evidence_persisted,
                    "failure_count": result.failure_count,
                },
                "status": "ok",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
