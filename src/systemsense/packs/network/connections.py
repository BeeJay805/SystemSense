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
    process_name: str | None = Field(default=None, max_length=255)
    process_executable: str | None = Field(default=None, max_length=32_768)
    process_command_line: str | None = Field(default=None, max_length=4096)
    parent_pid: int | None = Field(default=None, gt=0)


def collect_connections(
    observations: tuple[ConnectionObservation, ...],
    *,
    max_records: int = 256,
) -> tuple[ConnectionObservation, ...]:
    if not 1 <= max_records <= 1024:
        raise ValueError("max_records must be between 1 and 1024")
    in_scope = (
        observation
        for observation in observations
        if observation.status.upper() in _IN_SCOPE_STATUSES
    )
    return tuple(sorted(in_scope, key=_priority))[:max_records]


class PsutilNetworkConnectionBackend:
    def connections(self, *, max_records: int = 256) -> tuple[ConnectionObservation, ...]:
        if not 1 <= max_records <= 1024:
            raise ValueError("max_records must be between 1 and 1024")
        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return ()
        observations: list[ConnectionObservation] = []
        for connection in connections:
            if not connection.laddr:
                continue
            pid = connection.pid if connection.pid and connection.pid > 0 else None
            observations.append(
                ConnectionObservation(
                    local_address=str(connection.laddr.ip),
                    local_port=int(connection.laddr.port),
                    remote_address=(None if not connection.raddr else str(connection.raddr.ip)),
                    remote_port=(None if not connection.raddr else int(connection.raddr.port)),
                    status=connection.status or "NONE",
                    pid=pid,
                )
            )
            if len(observations) == 4096:
                break
        bounded = collect_connections(tuple(observations), max_records=max_records)
        return tuple(_with_process_identity(item) for item in bounded)


def _with_process_identity(observation: ConnectionObservation) -> ConnectionObservation:
    if observation.status.upper() != "LISTEN":
        return observation
    name, executable, command_line, parent_pid = _process_identity(observation.pid)
    return observation.model_copy(
        update={
            "process_name": name,
            "process_executable": executable,
            "process_command_line": command_line,
            "parent_pid": parent_pid,
        }
    )


def _process_identity(pid: int | None) -> tuple[str | None, str | None, str | None, int | None]:
    if pid is None:
        return None, None, None, None
    try:
        process = psutil.Process(pid)
        with process.oneshot():
            name = process.name() or None
            executable = process.exe() or None
            command_line = " ".join(process.cmdline())[:4096] or None
            parent_pid = process.ppid() or None
        return name, executable, command_line, parent_pid
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return None, None, None, None


def _priority(
    observation: ConnectionObservation,
) -> tuple[int, str, int, str, int, int]:
    return (
        0 if observation.status.upper() == "LISTEN" else 1,
        observation.local_address,
        observation.local_port,
        observation.remote_address or "",
        observation.remote_port or 0,
        observation.pid or 0,
    )
