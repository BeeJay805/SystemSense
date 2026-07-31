"""Bounded occupancy for application-declared expected ports."""

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class NetworkConnection(FrozenModel):
    local_address: str = Field(min_length=1, max_length=255)
    local_port: int = Field(ge=0, le=65_535)
    remote_address: str | None = Field(default=None, max_length=255)
    remote_port: int | None = Field(default=None, ge=0, le=65_535)
    status: str = Field(min_length=1, max_length=64)
    pid: int | None = Field(default=None, gt=0)


def collect_expected_ports(
    connections: tuple[NetworkConnection, ...],
    *,
    expected_ports: frozenset[int],
    max_records: int = 64,
) -> tuple[NetworkConnection, ...]:
    if len(expected_ports) > 32:
        raise ValueError("at most 32 expected ports may be inspected")
    return tuple(
        connection for connection in connections if connection.local_port in expected_ports
    )[:max_records]


class PsutilConnectionBackend:
    def connections(self, *, max_records: int = 4096) -> tuple[NetworkConnection, ...]:
        records: list[NetworkConnection] = []
        for connection in psutil.net_connections(kind="inet"):
            if not connection.laddr:
                continue
            remote_address = str(connection.raddr.ip) if connection.raddr else None
            remote_port = int(connection.raddr.port) if connection.raddr else None
            records.append(
                NetworkConnection(
                    local_address=str(connection.laddr.ip),
                    local_port=int(connection.laddr.port),
                    remote_address=remote_address,
                    remote_port=remote_port,
                    status=connection.status or "NONE",
                    pid=connection.pid,
                )
            )
            if len(records) == max_records:
                break
        return tuple(records)
