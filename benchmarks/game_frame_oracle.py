"""Bounded offline import of a user-supplied PresentMon v2 CSV.

This module never starts PresentMon or a game. Its output is untrusted imported
evidence, not an authenticated workload measurement or a cause determination.
"""

from __future__ import annotations

import csv
import hashlib
import io
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

type Phase = Literal["clean", "injected", "after_arm", "after_restore"]
type ParseStatus = Literal["available", "partial", "unavailable"]

_TRIAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SWAPCHAIN = re.compile(r"(?:0[xX])?[0-9A-Fa-f]{1,32}\Z")
_MAX_CSV_BYTES = 8 * 1024 * 1024
_MAX_CSV_ROWS = 100_000
_HEADERS = frozenset(
    {
        "Application",
        "ProcessID",
        "SwapChainAddress",
        "MsBetweenPresents",
        "MsBetweenDisplayChange",
        "DisplayedTime",
    }
)


@dataclass(frozen=True, slots=True)
class GameFrameImportSpec:
    trial_id: str
    phase: Phase
    csv_path: Path
    csv_sha256: str
    reported_pid: int
    reported_process_created_at: datetime
    reported_game_exe: str
    reported_presentmon_version: str
    scene: str
    settings: dict[str, str]
    settings_attested_at: datetime

    def validate(self) -> None:
        if _TRIAL.fullmatch(self.trial_id) is None:
            raise ValueError("invalid trial ID")
        if self.phase not in ("clean", "injected", "after_arm", "after_restore"):
            raise ValueError("invalid phase")
        if not self.csv_path.is_absolute() or self.csv_path.suffix.casefold() != ".csv":
            raise ValueError("CSV path must be absolute")
        if _HEX.fullmatch(self.csv_sha256) is None:
            raise ValueError("invalid CSV digest")
        if self.reported_pid <= 0:
            raise ValueError("reported PID must be positive")
        for instant in (self.reported_process_created_at, self.settings_attested_at):
            if instant.tzinfo is None or instant.utcoffset() != datetime.now(UTC).utcoffset():
                raise ValueError("reported timestamps must be UTC")
        if (
            not self.reported_game_exe.strip()
            or len(self.reported_game_exe) > 255
            or not self.reported_presentmon_version.strip()
            or len(self.reported_presentmon_version) > 80
            or not self.scene.strip()
            or len(self.scene) > 240
        ):
            raise ValueError("reported capture context is required and bounded")
        if len(self.settings) > 24 or any(
            not key or len(key) > 64 or len(value) > 240 for key, value in self.settings.items()
        ):
            raise ValueError("settings snapshot is not bounded")


@dataclass(frozen=True, slots=True)
class Distribution:
    count: int
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None


@dataclass(frozen=True, slots=True)
class SwapchainSummary:
    address: str
    presented: Distribution
    displayed: Distribution


@dataclass(frozen=True, slots=True)
class ParsedFrames:
    status: ParseStatus
    reason: str | None
    total_rows: int
    target_rows: int
    invalid_target_rows: int
    swapchains: tuple[SwapchainSummary, ...]


@dataclass(frozen=True, slots=True)
class ImportedGameFrames:
    schema_version: Literal[1]
    classification: Literal["untrusted_import_only"]
    trial_id: str
    phase: Phase
    imported_at: str
    status: ParseStatus
    reason: str | None
    source_label: Literal["operator_local_file"]
    csv_sha256: str
    csv_bytes: int
    reported_pid: int
    reported_process_created_at: str
    reported_game_exe: str
    reported_presentmon_version: str
    scene: str
    settings: dict[str, str]
    settings_source: Literal["user_attested"]
    settings_attested_at: str
    total_rows: int
    target_rows: int
    invalid_target_rows: int
    swapchains: tuple[SwapchainSummary, ...]
    limitations: tuple[str, ...]


def _quantile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low, high = math.floor(position), math.ceil(position)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (position - low), 4)


def _distribution(values: list[float]) -> Distribution:
    return Distribution(
        len(values),
        _quantile(values, 0.5),
        _quantile(values, 0.95),
        _quantile(values, 0.99),
    )


def _positive_metric(value: str | None) -> float | None:
    try:
        number = float(value) if value is not None else math.nan
    except ValueError:
        return None
    return number if math.isfinite(number) and number > 0 else None


def parse_presentmon_csv(
    text: str,
    *,
    target_pid: int,
    target_application: str | None = None,
    max_rows: int = _MAX_CSV_ROWS,
) -> ParsedFrames:
    """Summarize v2 frame intervals by swapchain, never averaging unrelated chains."""
    if target_pid <= 0 or not 1 <= max_rows <= _MAX_CSV_ROWS:
        raise ValueError("invalid parser bound")
    if len(text.encode("utf-8")) > _MAX_CSV_BYTES:
        return ParsedFrames("unavailable", "csv_size_limit", 0, 0, 0, ())
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    try:
        fieldnames = reader.fieldnames
    except csv.Error:
        return ParsedFrames("unavailable", "malformed_csv", 0, 0, 0, ())
    if (
        fieldnames is None
        or not _HEADERS.issubset(fieldnames)
        or any(not name for name in fieldnames)
        or len(fieldnames) != len(set(fieldnames))
    ):
        return ParsedFrames("unavailable", "unsupported_presentmon_csv_schema", 0, 0, 0, ())
    chains: dict[str, tuple[list[float], list[float]]] = {}
    total = target = invalid = 0
    truncated = False
    incomplete = False
    malformed_width = False
    while True:
        try:
            row = next(reader)
        except StopIteration:
            break
        except csv.Error:
            return ParsedFrames("unavailable", "malformed_csv", total, target, invalid, ())
        if total >= max_rows:
            truncated = True
            break
        total += 1
        if None in row or any(value is None for value in row.values()):
            malformed_width = True
            if row.get("ProcessID") == str(target_pid):
                target += 1
                invalid += 1
            continue
        if row.get("ProcessID") != str(target_pid):
            continue
        target += 1
        if (
            target_application is not None
            and (row.get("Application") or "").casefold() != target_application.casefold()
        ):
            invalid += 1
            continue
        address = row.get("SwapChainAddress") or ""
        presented = _positive_metric(row.get("MsBetweenPresents"))
        displayed = (
            _positive_metric(row.get("MsBetweenDisplayChange"))
            if _positive_metric(row.get("DisplayedTime")) is not None
            else None
        )
        if _SWAPCHAIN.fullmatch(address) is None or (presented is None and displayed is None):
            invalid += 1
            continue
        points = chains.setdefault(address, ([], []))
        if presented is not None:
            points[0].append(presented)
        else:
            incomplete = True
        if displayed is not None:
            points[1].append(displayed)
        else:
            incomplete = True
    summaries = tuple(
        SwapchainSummary(address, _distribution(values[0]), _distribution(values[1]))
        for address, values in sorted(chains.items())
    )
    if not summaries:
        status: ParseStatus = "partial" if truncated else "unavailable"
        reason = (
            "csv_row_limit"
            if truncated
            else "malformed_csv_row"
            if malformed_width
            else "no_valid_target_frames"
        )
    elif (
        truncated
        or malformed_width
        or invalid
        or incomplete
        or len(summaries) > 1
        or any(chain.displayed.count == 0 or chain.presented.count == 0 for chain in summaries)
    ):
        status = "partial"
        reason = "csv_row_limit" if truncated else "incomplete_or_multiple_swapchains"
    else:
        status = "available"
        reason = None
    return ParsedFrames(status, reason, total, target, invalid, summaries)


def import_presentmon_csv(spec: GameFrameImportSpec) -> ImportedGameFrames:
    """Read one bounded user-supplied file; verify bytes, not their real-world origin."""
    spec.validate()
    with spec.csv_path.open("rb") as source:
        data = source.read(_MAX_CSV_BYTES + 1)
    if len(data) > _MAX_CSV_BYTES:
        raise ValueError("CSV size limit exceeded")
    digest = hashlib.sha256(data).hexdigest()
    if digest != spec.csv_sha256:
        raise ValueError("CSV digest mismatch")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as error:
        raise ValueError("CSV encoding unsupported") from error
    parsed = parse_presentmon_csv(
        text,
        target_pid=spec.reported_pid,
        target_application=spec.reported_game_exe,
    )
    return ImportedGameFrames(
        1,
        "untrusted_import_only",
        spec.trial_id,
        spec.phase,
        datetime.now(UTC).isoformat(),
        parsed.status,
        parsed.reason,
        "operator_local_file",
        digest,
        len(data),
        spec.reported_pid,
        spec.reported_process_created_at.isoformat(),
        spec.reported_game_exe,
        spec.reported_presentmon_version,
        spec.scene,
        dict(spec.settings),
        "user_attested",
        spec.settings_attested_at.isoformat(),
        parsed.total_rows,
        parsed.target_rows,
        parsed.invalid_target_rows,
        parsed.swapchains,
        (
            "CSV origin, tool identity, game process creation, and settings are not verified.",
            "Presentation intervals and displayed intervals are distinct; neither proves cause.",
            "No live capture, game interaction, or ETW session is performed by this importer.",
        ),
    )
