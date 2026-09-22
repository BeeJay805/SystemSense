"""Hard-deadline adapter for fixed local Event Log queries."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from systemsense.orchestration.executor import (
    CancellationSignal,
    ProbeExecutor,
    WorkerExecutionStatus,
)
from systemsense.platform.windows.eventlog import EventQuery, QueryStatus


class EventLogQueryParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    channel: Literal["Application", "System", "Microsoft-Windows-WindowsUpdateClient/Operational"]
    after_record_id: int | None = Field(default=None, ge=0)
    limit: int = Field(default=50, ge=1, le=100)


class IsolatedEventLogAdapter:
    """Only the owned worker may block in native Event Log APIs."""

    def __init__(self, executor: ProbeExecutor | None = None) -> None:
        self._executor = executor or ProbeExecutor()

    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        deadline_at: datetime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> EventQuery:
        parameters = EventLogQueryParameters.model_validate(
            {
                "channel": channel,
                "after_record_id": after_record_id,
                "limit": limit,
            }
        )
        result = self._executor.execute(
            "eventlog.query",
            parameters.model_dump(mode="json"),
            timeout_ms=5000,
            deadline_at=deadline_at,
            cancellation=cancellation,
        )
        if result.status is not WorkerExecutionStatus.OK or len(result.evidence) != 1:
            return EventQuery(
                status=QueryStatus.FAILED,
                reason=result.error or "isolated Event Log query failed",
            )
        try:
            return EventQuery.model_validate(result.evidence[0].get("event_query"))
        except ValidationError:
            return EventQuery(status=QueryStatus.FAILED, reason="invalid Event Log worker result")
