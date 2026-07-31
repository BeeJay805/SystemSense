"""Bounded listening and established endpoint observations."""

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel

_IN_SCOPE_STATUSES = frozenset({"LISTEN", "ESTABLISHED"})


class ConnectionObservation(FrozenModel):
    local_address: str = Field(min_length=1, max_length=255)
    local_port: int = Field(ge=0, le=65_535)
    remote_address: str | None = Field(default=None, max_length=255)
    remote_port: int | None = Field(default=None, ge=0, le=65_535)
    status: str = Field(min_length=1, max_length=64)
    pid: int | None = Field(default=None, gt=0)


def collect_connections(
    observations: tuple[ConnectionObservation, ...],
    *,
    max_records: int = 256,
) -> tuple[ConnectionObservation, ...]:
    if not 1 <= max_records <= 1024:
        raise ValueError("max_records must be between 1 and 1024")
    return tuple(
        observation
        for observation in observations
        if observation.status.upper() in _IN_SCOPE_STATUSES
    )[:max_records]


class PsutilNetworkConnectionBackend:
    def connections(self, *, max_records: int = 4096) -> tuple[ConnectionObservation, ...]:
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return ()
        observations: list[ConnectionObservation] = []
        for connection in connections:
            if not connection.laddr:
                continue
            observations.append(
                ConnectionObservation(
                    local_address=str(connection.laddr.ip),
                    local_port=int(connection.laddr.port),
                    remote_address=(None if not connection.raddr else str(connection.raddr.ip)),
                    remote_port=(None if not connection.raddr else int(connection.raddr.port)),
                    status=connection.status or "NONE",
                    pid=connection.pid if connection.pid and connection.pid > 0 else None,
                )
            )
            if len(observations) == max_records:
                break
        return tuple(observations)
