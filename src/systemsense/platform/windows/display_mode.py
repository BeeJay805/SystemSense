"""Read-only observation of the calling desktop's current display mode."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, utc_now


class DisplayModeStatus(StrEnum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


class DisplayModeObservation(FrozenModel):
    schema_version: Literal[1] = 1
    source_api: str = "win32api.EnumDisplaySettings"
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    status: DisplayModeStatus
    width_pixels: int | None = Field(default=None, gt=0)
    height_pixels: int | None = Field(default=None, gt=0)
    refresh_hz: int | None = Field(default=None, gt=1)
    limitations: tuple[str, ...]


class _Mode(Protocol):
    PelsWidth: int
    PelsHeight: int
    DisplayFrequency: int


class DisplayModeBackend(Protocol):
    def EnumDisplaySettings(self, name: None, setting: int) -> _Mode: ...


_SCOPE_LIMITATION = (
    "Current calling-desktop display mode only; other displays and dynamic refresh changes "
    "are not observed. Display refresh is not game-produced FPS, frame pacing, or a cause."
)


def collect_display_mode(
    *,
    backend: DisplayModeBackend | None = None,
    clock: Callable[[], datetime] = utc_now,
) -> DisplayModeObservation:
    """Read ENUM_CURRENT_SETTINGS without accepting a caller-selected display or setting."""
    observed_at = clock()
    try:
        api = backend or cast("DisplayModeBackend", importlib.import_module("win32api"))
        mode = api.EnumDisplaySettings(None, -1)
        width = int(mode.PelsWidth)
        height = int(mode.PelsHeight)
        frequency = int(mode.DisplayFrequency)
    except ImportError:
        return DisplayModeObservation(
            observed_at=observed_at,
            captured_at=clock(),
            status=DisplayModeStatus.UNSUPPORTED,
            limitations=("Win32 display API unavailable", _SCOPE_LIMITATION),
        )
    except Exception as error:
        return DisplayModeObservation(
            observed_at=observed_at,
            captured_at=clock(),
            status=DisplayModeStatus.FAILED,
            limitations=(
                f"Current display-mode query failed ({type(error).__name__})",
                _SCOPE_LIMITATION,
            ),
        )

    dimensions_valid = width > 0 and height > 0
    limitations = [_SCOPE_LIMITATION]
    if not dimensions_valid:
        limitations.append("Display dimensions were unavailable or invalid")
    if frequency <= 1:
        limitations.append(
            "Windows reported the display hardware's default refresh, not a Hz value"
        )
    return DisplayModeObservation(
        observed_at=observed_at,
        captured_at=clock(),
        status=(
            DisplayModeStatus.AVAILABLE
            if dimensions_valid and frequency > 1
            else DisplayModeStatus.PARTIAL
        ),
        width_pixels=width if width > 0 else None,
        height_pixels=height if height > 0 else None,
        refresh_hz=frequency if frequency > 1 else None,
        limitations=tuple(limitations),
    )
