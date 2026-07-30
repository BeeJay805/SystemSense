from pathlib import Path

from systemsense.storage.sqlite_store import SQLiteStore


def test_initial_migration_configures_durable_store(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"

    with SQLiteStore(database_path, busy_timeout_ms=250) as store:
        assert store.schema_version() == 1
        assert store.foreign_keys_enabled()
        assert store.journal_mode() == "wal"
        assert store.busy_timeout_ms() == 250
        assert store.integrity_check() == "ok"
        assert {
            "cases",
            "probe_manifests",
            "probe_executions",
            "evidence",
            "inventory_current",
            "inventory_history",
            "audit_events",
            "bookmarks",
            "artifacts",
            "artifact_cases",
        } <= store.table_names()
