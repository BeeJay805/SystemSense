"""Default passive collectors share case-probe capacity and exit custody."""

import sqlite3
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_passive_recorder
from systemsense.application.passive import PassiveRecorderConfig
from systemsense.platform.windows.eventlog import EventQuery, QueryStatus
from systemsense.storage.sqlite_store import SQLiteStore


def test_default_passive_core_probes_release_verified_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class EmptyEventLog:
        def __init__(self, *, managed: bool = False) -> None:
            assert managed
            self.requires_host_admission = True

        def query(self, *_args: object, **_kwargs: object) -> EventQuery:
            assert _kwargs.get("host_slot") is not None
            return EventQuery(status=QueryStatus.OK)

    monkeypatch.setattr(
        "systemsense.platform.windows.eventlog_runtime.IsolatedEventLogAdapter",
        EmptyEventLog,
    )
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = default_passive_recorder(store, PassiveRecorderConfig()).capture_once()
        assert cycle.failure_count == 0
        statuses = tuple(
            str(row[0])
            for row in store.connection.execute(
                "SELECT tree_exit_status FROM probe_executions "
                "WHERE case_id=? AND probe_id LIKE 'core.%' ORDER BY probe_id",
                (str(cycle.case_id),),
            )
        )
        assert statuses == ("verified_empty", "verified_empty")
    with sqlite3.connect(
        tmp_path / "LocalAppData" / "SystemSense" / "host-probe-capacity-v1.sqlite3"
    ) as capacity:
        assert capacity.execute("SELECT state, COUNT(*) FROM work GROUP BY state").fetchall() == [
            ("released", 4)
        ]
