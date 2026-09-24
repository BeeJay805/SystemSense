"""Hard-deadline adapter for fixed local Event Log queries."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from systemsense.orchestration.executor import (
    CancellationSignal,
    ProbeExecutor,
    WorkerExecutionStatus,
    WorkerTreeExitStatus,
)
from systemsense.orchestration.scheduler import HostWorkSlot
from systemsense.platform.windows.eventlog import EventQuery, QueryStatus


class EventLogQueryParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    channel: Literal["Application", "System", "Microsoft-Windows-WindowsUpdateClient/Operational"]
    after_record_id: int | None = Field(default=None, ge=0)
    limit: int = Field(default=50, ge=1, le=100)


class IsolatedEventLogAdapter:
    """Only the owned worker may block in native Event Log APIs.

    Direct callers may use the explicitly unmanaged adapter. The passive
    factory enables managed mode and supplies a host slot for every query.
    """

    def __init__(self, executor: ProbeExecutor | None = None, *, managed: bool = False) -> None:
        self._executor = executor or ProbeExecutor()
        self.requires_host_admission = managed

    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        deadline_at: datetime | None = None,
        cancellation: CancellationSignal | None = None,
        host_slot: HostWorkSlot | None = None,
    ) -> EventQuery:
        if self.requires_host_admission and host_slot is None:
            raise ValueError("managed Event Log query requires host admission")
        parameters = EventLogQueryParameters.model_validate(
            {
                "channel": channel,
                "after_record_id": after_record_id,
                "limit": limit,
            }
        )
        try:
            result = self._executor.execute(
                "eventlog.query",
                parameters.model_dump(mode="json"),
                timeout_ms=5000,
                deadline_at=deadline_at,
                cancellation=cancellation,
                custody=None if host_slot is None else host_slot.custody,
            )
        except Exception:
            if host_slot is not None:
                host_slot.quarantine("eventlog_worker_outcome_unknown")
            raise
        if result.tree_exit is WorkerTreeExitStatus.UNKNOWN and host_slot is not None:
            host_slot.quarantine("eventlog_child_tree_exit_unverified")
        if result.status is not WorkerExecutionStatus.OK or len(result.evidence) != 1:
            return EventQuery(
                status=QueryStatus.FAILED,
                reason=result.error or "isolated Event Log query failed",
            )
        try:
            return EventQuery.model_validate(result.evidence[0].get("event_query"))
        except ValidationError:
            return EventQuery(status=QueryStatus.FAILED, reason="invalid Event Log worker result")
