"""Bounded matching process observations."""

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class ProcessSnapshot(FrozenModel):
    pid: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=255)
    executable: str | None = Field(default=None, max_length=32_768)


def collect_matching_processes(
    snapshots: tuple[ProcessSnapshot, ...],
    *,
    executable_name: str,
    max_records: int = 64,
) -> tuple[ProcessSnapshot, ...]:
    if not 1 <= max_records <= 256:
        raise ValueError("max_records must be between 1 and 256")
    expected = executable_name.casefold()
    return tuple(snapshot for snapshot in snapshots if snapshot.name.casefold() == expected)[
        :max_records
    ]


class PsutilProcessBackend:
    def snapshots(self, *, max_records: int = 4096) -> tuple[ProcessSnapshot, ...]:
        records: list[ProcessSnapshot] = []
        for process in psutil.process_iter():
            try:
                name = process.name()
                if not name:
                    continue
                records.append(
                    ProcessSnapshot(
                        pid=process.pid,
                        name=name,
                        executable=process.exe() or None,
                    )
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                continue
            if len(records) == max_records:
                break
        return tuple(records)
