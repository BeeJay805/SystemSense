"""CUDA and framework version compatibility facts."""

import re

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class CudaCompatibility(FrozenModel):
    driver_supported_cuda: str | None = Field(default=None, max_length=255)
    framework: str = Field(min_length=1, max_length=255)
    framework_version: str | None = Field(default=None, max_length=255)
    framework_cuda: str | None = Field(default=None, max_length=255)
    compatible: bool | None
    limitation: str


def assess_cuda_compatibility(
    *,
    driver_supported_cuda: str | None,
    framework: str,
    framework_version: str | None,
    framework_cuda: str | None,
) -> CudaCompatibility:
    driver_version = _numeric_version(driver_supported_cuda)
    required_version = _numeric_version(framework_cuda)
    compatible = (
        None
        if driver_version is None or required_version is None
        else driver_version >= required_version
    )
    return CudaCompatibility(
        driver_supported_cuda=driver_supported_cuda,
        framework=framework,
        framework_version=framework_version,
        framework_cuda=framework_cuda,
        compatible=compatible,
        limitation="numeric version comparison only",
    )


def _numeric_version(value: str | None) -> tuple[int, ...] | None:
    if value is None:
        return None
    match = re.search(r"\d+(?:\.\d+)*", value)
    if match is None:
        return None
    return tuple(int(component) for component in match.group(0).split("."))
