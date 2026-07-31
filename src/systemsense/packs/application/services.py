"""Registered Windows service state and dependency observations."""

from collections.abc import Mapping
from typing import cast

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import JsonValue


class ServiceObservation(FrozenModel):
    name: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=255)
    status: str = Field(min_length=1, max_length=64)
    start_type: str = Field(min_length=1, max_length=64)
    dependencies: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


def collect_services(
    observations: tuple[ServiceObservation, ...],
    *,
    registered_names: frozenset[str],
) -> tuple[ServiceObservation, ...]:
    if len(registered_names) > 32:
        raise ValueError("at most 32 registered services may be collected")
    names = {name.casefold() for name in registered_names}
    return tuple(item for item in observations if item.name.casefold() in names)


class PsutilServiceBackend:
    def observations(
        self,
        registered_names: frozenset[str],
    ) -> tuple[ServiceObservation, ...]:
        observations: list[ServiceObservation] = []
        for name in sorted(registered_names):
            try:
                service = psutil.win_service_get(name)
                data = cast(
                    "Mapping[str, JsonValue]",
                    service.as_dict(),
                )
            except (psutil.Error, OSError):
                continue
            observations.append(
                ServiceObservation(
                    name=str(data.get("name", name)),
                    display_name=str(data.get("display_name", name)),
                    status=str(data.get("status", "unknown")),
                    start_type=str(data.get("start_type", "unknown")),
                    limitations=("dependency enumeration unavailable through psutil",),
                )
            )
        return tuple(observations)
