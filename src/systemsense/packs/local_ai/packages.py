"""Installed distribution metadata without package imports or index access."""

from importlib import metadata

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class PackageObservation(FrozenModel):
    name: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=255)


def collect_packages(
    packages: tuple[PackageObservation, ...],
    *,
    max_records: int = 2048,
) -> tuple[PackageObservation, ...]:
    if not 1 <= max_records <= 10_000:
        raise ValueError("max_records must be between 1 and 10000")
    ordered = sorted(packages, key=lambda package: package.name.casefold())
    return tuple(ordered[:max_records])


def current_packages(*, max_records: int = 2048) -> tuple[PackageObservation, ...]:
    packages: list[PackageObservation] = []
    for distribution in metadata.distributions():
        name = distribution.metadata.get("Name")
        if not name:
            continue
        packages.append(
            PackageObservation(
                name=name,
                version=distribution.version,
            )
        )
        if len(packages) == 10_000:
            break
    return collect_packages(tuple(packages), max_records=max_records)
