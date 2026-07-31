import os
from collections.abc import Callable

import pytest

from systemsense.platform.windows.eventlog import (
    EventLogBackend,
    FixedEventLogAdapter,
    PyWin32EventLogBackend,
    QueryStatus,
    RawEventBatch,
    WindowsEvent,
)


def test_unknown_event_channel_is_rejected_before_backend_access() -> None:
    adapter = FixedEventLogAdapter(PyWin32EventLogBackend())

    with pytest.raises(ValueError, match="not registered"):
        adapter.query("Security", after_record_id=None, limit=10)


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


def test_subscription_uses_same_fixed_channel_boundary() -> None:
    received: list[WindowsEvent] = []
    callback: Callable[[WindowsEvent], None] = received.append
    adapter = FixedEventLogAdapter(EmptyBackend())

    result = adapter.subscribe(
        "Application",
        after_record_id=12,
        limit=2,
        on_event=callback,
    )

    assert result.status is QueryStatus.OK
    assert received == []


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to query fixed Windows channels",
)
def test_live_application_query_is_bounded() -> None:
    adapter = FixedEventLogAdapter(PyWin32EventLogBackend())

    result = adapter.query("Application", after_record_id=None, limit=2)

    assert result.status in {QueryStatus.OK, QueryStatus.DENIED}
    assert len(result.events) <= 2
