"""Bounded parsing of related local Windows Error Reporting metadata."""

from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime

_MAX_REPORT_BYTES = 262_144


class WerReport(FrozenModel):
    report_name: str = Field(min_length=1, max_length=255)
    modified_at: UtcDateTime
    fields: dict[str, str]


def scan_wer_reports(
    roots: tuple[Path, ...],
    *,
    application_name: str,
    max_reports: int = 10,
) -> tuple[WerReport, ...]:
    if not 1 <= max_reports <= 50:
        raise ValueError("max_reports must be between 1 and 50")
    expected = application_name.casefold()
    candidates: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            candidates.extend(
                directory
                for directory in root.iterdir()
                if directory.is_dir() and expected in directory.name.casefold()
            )
        except PermissionError:
            continue
    candidates.sort(key=_modified_time, reverse=True)

    reports: list[WerReport] = []
    for directory in candidates[:max_reports]:
        report_path = directory / "Report.wer"
        try:
            raw = report_path.read_bytes()
        except (OSError, PermissionError):
            continue
        if len(raw) > _MAX_REPORT_BYTES:
            raw = raw[:_MAX_REPORT_BYTES]
        text = _decode_report(raw)
        fields: dict[str, str] = {}
        for line in text.splitlines():
            key, separator, value = line.partition("=")
            if separator and key and len(fields) < 64:
                fields[key[:255]] = value[:4096]
        reports.append(
            WerReport(
                report_name=directory.name,
                modified_at=datetime.fromtimestamp(_modified_time(directory), tz=UTC),
                fields=fields,
            )
        )
    return tuple(reports)


def _decode_report(raw: bytes) -> str:
    for encoding in ("utf-16", "utf-8"):
        try:
            return raw.decode(encoding)
        except UnicodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _modified_time(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0
