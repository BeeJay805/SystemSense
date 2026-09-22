import threading
from datetime import timedelta

import pytest
from pydantic import ValidationError

from systemsense.domain.time import utc_now
from systemsense.orchestration.scheduler import BlockingCancellationToken
from systemsense.platform.windows.eventlog import QueryStatus
from systemsense.platform.windows.eventlog_runtime import IsolatedEventLogAdapter


def test_eventlog_worker_rejects_free_form_channels_before_execution() -> None:
    with pytest.raises(ValidationError):
        IsolatedEventLogAdapter().query("System; arbitrary", after_record_id=None, limit=3)


def test_eventlog_worker_honors_expired_deadline_and_cancellation() -> None:
    adapter = IsolatedEventLogAdapter()
    expired = adapter.query(
        "Application",
        after_record_id=None,
        limit=3,
        deadline_at=utc_now() - timedelta(seconds=1),
    )
    assert expired.status is QueryStatus.FAILED
    assert expired.reason is not None and "deadline" in expired.reason
    event = threading.Event()
    event.set()
    cancelled = adapter.query(
        "System",
        after_record_id=None,
        limit=3,
        cancellation=BlockingCancellationToken(event),
    )
    assert cancelled.status is QueryStatus.FAILED
    assert cancelled.reason is not None and "cancel" in cancelled.reason
