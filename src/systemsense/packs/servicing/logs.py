"""Incremental bounded CBS and DISM log excerpts."""

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class ServicingLogIncrement(FrozenModel):
    error_lines: tuple[str, ...]
    next_offset: int = Field(ge=0)
    truncated: bool


def parse_servicing_log_increment(
    data: bytes,
    *,
    start_offset: int,
    max_bytes: int,
) -> ServicingLogIncrement:
    if start_offset < 0 or start_offset > len(data):
        raise ValueError("start_offset is outside the supplied log")
    if not 1 <= max_bytes <= 1_048_576:
        raise ValueError("max_bytes must be between 1 and 1048576")
    end_offset = min(len(data), start_offset + max_bytes)
    text = data[start_offset:end_offset].decode("utf-8", errors="replace")
    error_lines = tuple(
        line[:4096]
        for line in text.splitlines()
        if "error" in line.casefold() or line.lstrip().startswith("!!!")
    )[:128]
    return ServicingLogIncrement(
        error_lines=error_lines,
        next_offset=end_offset,
        truncated=end_offset < len(data),
    )
