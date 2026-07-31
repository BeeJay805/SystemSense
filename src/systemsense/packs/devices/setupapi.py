"""Incremental bounded parsing of SetupAPI device-install logs."""

import re

from pydantic import Field

from systemsense.domain.evidence import FrozenModel

_SECTION_START = re.compile(r"^>>>\s+\[Device Install .* - (.+)\]$")


class SetupApiEntry(FrozenModel):
    device_instance: str = Field(min_length=1, max_length=4096)
    errors: tuple[str, ...]
    excerpt: str = Field(max_length=16_384)


class SetupApiIncrement(FrozenModel):
    entries: tuple[SetupApiEntry, ...]
    next_offset: int = Field(ge=0)
    truncated: bool


def parse_setupapi_increment(
    data: bytes,
    *,
    start_offset: int,
    max_bytes: int,
) -> SetupApiIncrement:
    if start_offset < 0 or start_offset > len(data):
        raise ValueError("start_offset is outside the supplied log")
    if not 1 <= max_bytes <= 1_048_576:
        raise ValueError("max_bytes must be between 1 and 1048576")
    end_offset = min(len(data), start_offset + max_bytes)
    text = data[start_offset:end_offset].decode("utf-8", errors="replace")

    entries: list[SetupApiEntry] = []
    current_device: str | None = None
    current_lines: list[str] = []
    current_errors: list[str] = []
    for line in text.splitlines():
        match = _SECTION_START.match(line)
        if match:
            if current_device is not None:
                entries.append(_entry(current_device, current_lines, current_errors))
            current_device = match.group(1).strip()
            current_lines = [line]
            current_errors = []
            continue
        if current_device is None:
            continue
        current_lines.append(line)
        if line.lstrip().startswith("!!!"):
            current_errors.append(line.strip())
    if current_device is not None:
        entries.append(_entry(current_device, current_lines, current_errors))

    return SetupApiIncrement(
        entries=tuple(entries),
        next_offset=end_offset,
        truncated=end_offset < len(data),
    )


def _entry(device: str, lines: list[str], errors: list[str]) -> SetupApiEntry:
    return SetupApiEntry(
        device_instance=device,
        errors=tuple(errors[:32]),
        excerpt="\n".join(lines)[:16_384],
    )
