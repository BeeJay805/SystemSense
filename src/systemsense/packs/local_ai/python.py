"""Current Python runtime identity without importing target packages."""

import platform
import struct
import sys

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class PythonEnvironment(FrozenModel):
    executable: str = Field(min_length=1, max_length=32_768)
    version: str = Field(min_length=1, max_length=255)
    implementation: str = Field(min_length=1, max_length=255)
    prefix: str = Field(min_length=1, max_length=32_768)
    base_prefix: str = Field(min_length=1, max_length=32_768)
    virtual_environment: bool
    architecture: str


def current_python_environment() -> PythonEnvironment:
    return PythonEnvironment(
        executable=sys.executable,
        version=platform.python_version(),
        implementation=platform.python_implementation(),
        prefix=sys.prefix,
        base_prefix=sys.base_prefix,
        virtual_environment=sys.prefix != sys.base_prefix,
        architecture=f"{struct.calcsize('P') * 8}-bit",
    )
