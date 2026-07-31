"""Installed update history and read-only reboot-pending facts."""

from collections.abc import Mapping

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class InstalledUpdate(FrozenModel):
    kb: str = Field(min_length=1, max_length=255)
    description: str = Field(max_length=1024)
    installed_on: str | None = Field(default=None, max_length=255)


class RebootPendingObservation(FrozenModel):
    pending: bool
    pending_sources: tuple[str, ...]
    checked_sources: tuple[str, ...]


def collect_update_history(
    updates: tuple[InstalledUpdate, ...],
    *,
    max_records: int = 256,
) -> tuple[InstalledUpdate, ...]:
    if not 1 <= max_records <= 1024:
        raise ValueError("max_records must be between 1 and 1024")
    ordered = sorted(
        updates,
        key=lambda update: update.installed_on or "",
        reverse=True,
    )
    return tuple(ordered[:max_records])


def assess_reboot_pending(
    sources: Mapping[str, bool],
) -> RebootPendingObservation:
    checked = tuple(sorted(sources))
    pending = tuple(name for name in checked if sources[name])
    return RebootPendingObservation(
        pending=bool(pending),
        pending_sources=pending,
        checked_sources=checked,
    )
