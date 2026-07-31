from datetime import UTC, datetime
from pathlib import Path

from systemsense.domain.ids import CaseId
from systemsense.platform.windows.eventlog import (
    EventLogBackend,
    FixedEventLogAdapter,
    RawEventBatch,
)
from systemsense.sentinel import Sentinel, SentinelRunner
from systemsense.storage.sqlite_store import SQLiteStore

_CASE_ID = CaseId(root="case_0123456789abcdef0123456789abcdef")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


class EmptyBackend(EventLogBackend):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel, after_record_id, limit
        return RawEventBatch(xml_events=())


def _store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "systemsense.db")
    store.initialize()
    store.create_case(
        case_id=str(_CASE_ID),
        kind="general",
        symptom="sentinel fixture",
        created_at=_NOW.isoformat(),
    )
    return store


def test_sentinel_runner_stops_at_poll_limit_and_waits_between_polls(
    tmp_path: Path,
) -> None:
    waits: list[float] = []
    with _store(tmp_path) as store:
        runner = SentinelRunner(
            Sentinel(FixedEventLogAdapter(EmptyBackend()), store),
            wait=waits.append,
            now=lambda: _NOW,
        )

        result = runner.run(
            case_id=_CASE_ID,
            channels=("Application",),
            limit=10,
            max_polls=3,
            interval_seconds=0.25,
        )

    assert result.polls == 3
    assert result.inserted == 0
    assert result.stop_reason == "poll_limit"
    assert waits == [0.25, 0.25]


def test_sentinel_runner_honors_stop_before_polling(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        runner = SentinelRunner(
            Sentinel(FixedEventLogAdapter(EmptyBackend()), store),
            wait=lambda _seconds: None,
            now=lambda: _NOW,
        )

        result = runner.run(
            case_id=_CASE_ID,
            channels=("Application",),
            limit=10,
            max_polls=3,
            interval_seconds=0,
            stop_requested=lambda: True,
        )

    assert result.polls == 0
    assert result.stop_reason == "requested"
