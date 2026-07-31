"""Network adapter state and assigned address observations."""

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class AdapterObservation(FrozenModel):
    name: str = Field(min_length=1, max_length=1024)
    is_up: bool
    speed_mbps: int = Field(ge=0)
    mtu: int = Field(ge=0)
    addresses: tuple[str, ...]


def collect_adapters(
    observations: tuple[AdapterObservation, ...],
    *,
    max_records: int = 64,
) -> tuple[AdapterObservation, ...]:
    if not 1 <= max_records <= 256:
        raise ValueError("max_records must be between 1 and 256")
    return observations[:max_records]


class PsutilAdapterBackend:
    def adapters(self) -> tuple[AdapterObservation, ...]:
        statistics = psutil.net_if_stats()
        addresses = psutil.net_if_addrs()
        observations: list[AdapterObservation] = []
        for name in sorted(set(statistics) | set(addresses)):
            stats = statistics.get(name)
            assigned = tuple(address.address[:1024] for address in addresses.get(name, ())[:16])
            observations.append(
                AdapterObservation(
                    name=name,
                    is_up=False if stats is None else stats.isup,
                    speed_mbps=0 if stats is None else max(0, int(stats.speed)),
                    mtu=0 if stats is None else max(0, int(stats.mtu)),
                    addresses=assigned,
                )
            )
            if len(observations) == 256:
                break
        return tuple(observations)
