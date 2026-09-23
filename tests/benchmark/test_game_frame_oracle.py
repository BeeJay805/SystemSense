"""Offline, untrusted PresentMon CSV import contracts."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from benchmarks.game_frame_oracle import (
    GameFrameImportSpec,
    import_presentmon_csv,
    parse_presentmon_csv,
)

NOW = datetime(2026, 9, 23, 10, 0, tzinfo=UTC)
HEADER = (
    "Application,ProcessID,SwapChainAddress,MsBetweenPresents,"
    "MsBetweenDisplayChange,DisplayedTime\n"
)


@pytest.fixture
def csv_file(tmp_path: Path) -> Path:
    path = tmp_path / "pinned.csv"
    path.write_text(
        HEADER
        + "game.exe,123,0x1,80,83,83\n"
        + "game.exe,123,0x1,90,NA,NA\n"
        + "game.exe,123,0x2,16,17,17\n"
        + "other.exe,456,0x1,1,1,1\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def spec(csv_file: Path) -> GameFrameImportSpec:
    return GameFrameImportSpec(
        trial_id="game-clean-01",
        phase="clean",
        csv_path=csv_file,
        csv_sha256=hashlib.sha256(csv_file.read_bytes()).hexdigest(),
        reported_pid=123,
        reported_process_created_at=NOW,
        reported_game_exe="game.exe",
        reported_presentmon_version="2.x",
        scene="saved benchmark scene",
        settings={"resolution": "2560x1440", "fps_cap": "unknown"},
        settings_attested_at=NOW,
    )


def test_parser_separates_presented_displayed_and_swapchains(csv_file: Path) -> None:
    parsed = parse_presentmon_csv(csv_file.read_text(encoding="utf-8"), target_pid=123)
    assert parsed.status == "partial"
    assert parsed.total_rows == 4
    assert parsed.target_rows == 3
    assert len(parsed.swapchains) == 2
    assert parsed.swapchains[0].presented.count == 2
    assert parsed.swapchains[0].presented.p50_ms == 85
    assert parsed.swapchains[0].displayed.count == 1
    assert parsed.swapchains[0].displayed.p50_ms == 83
    assert parsed.swapchains[1].presented.p50_ms == 16


def test_parser_never_converts_missing_target_into_zero_fps() -> None:
    parsed = parse_presentmon_csv(HEADER + "other.exe,456,0x1,16,16,16\n", target_pid=123)
    assert parsed.status == "unavailable"
    assert parsed.swapchains == ()


def test_parser_rejects_unsafe_swapchain_value() -> None:
    parsed = parse_presentmon_csv(HEADER + "game.exe,123,=1+1,16,16,16\n", target_pid=123)
    assert parsed.status == "unavailable"
    assert parsed.swapchains == ()


def test_parser_reports_malformed_csv_as_unavailable() -> None:
    parsed = parse_presentmon_csv(HEADER + '"game.exe,123,0x1,16,16,16\n', target_pid=123)
    assert parsed.status == "unavailable"
    assert parsed.reason == "malformed_csv"


@pytest.mark.parametrize(
    "header",
    (
        HEADER.rstrip("\n") + ",ProcessID\n",
        HEADER.rstrip("\n") + ",\n",
    ),
)
def test_parser_rejects_duplicate_or_empty_headers(header: str) -> None:
    parsed = parse_presentmon_csv(header + "game.exe,123,0x1,16,16,16,123\n", target_pid=123)
    assert parsed.status == "unavailable"
    assert parsed.swapchains == ()


@pytest.mark.parametrize(
    "row",
    (
        "game.exe,123,0x1,16,16,16,extra\n",
        "game.exe,123,0x1,16,16\n",
    ),
)
def test_parser_never_accepts_wrong_width_row_as_complete(row: str) -> None:
    parsed = parse_presentmon_csv(HEADER + row, target_pid=123)
    assert parsed.status != "available"
    assert parsed.swapchains == ()


@pytest.mark.parametrize("displayed_time", ("bad", "-1", "nan", "inf", "0"))
def test_parser_does_not_count_invalid_displayed_time(displayed_time: str) -> None:
    parsed = parse_presentmon_csv(
        HEADER + f"game.exe,123,0x1,16,16,{displayed_time}\n", target_pid=123
    )
    assert parsed.status == "partial"
    assert parsed.swapchains[0].presented.count == 1
    assert parsed.swapchains[0].displayed.count == 0


def test_parser_marks_row_limit_and_malformed_target_as_partial() -> None:
    text = HEADER + "game.exe,123,0x1,16,16,16\n" * 3
    limited = parse_presentmon_csv(text, target_pid=123, max_rows=1)
    assert limited.status == "partial"
    assert limited.reason == "csv_row_limit"
    malformed = parse_presentmon_csv(
        HEADER + "game.exe,123,0x1,NA,NA,NA\n" + "game.exe,123,0x1,16,16,16\n",
        target_pid=123,
    )
    assert malformed.status == "partial"
    assert malformed.invalid_target_rows == 1


def test_parser_keeps_display_metric_when_present_metric_is_missing() -> None:
    parsed = parse_presentmon_csv(
        HEADER + "game.exe,123,0x1,NA,83,83\n" + "game.exe,123,0x1,90,NA,NA\n",
        target_pid=123,
    )
    assert parsed.status == "partial"
    assert parsed.swapchains[0].presented.count == 1
    assert parsed.swapchains[0].displayed.count == 1


def test_parser_marks_undisplayed_target_frames_partial() -> None:
    parsed = parse_presentmon_csv(
        HEADER + "game.exe,123,0x1,16,16,16\n" + "game.exe,123,0x1,17,NA,NA\n",
        target_pid=123,
    )
    assert parsed.status == "partial"
    assert parsed.swapchains[0].presented.count == 2
    assert parsed.swapchains[0].displayed.count == 1


def test_import_requires_reported_game_name_to_match_rows(spec: GameFrameImportSpec) -> None:
    result = import_presentmon_csv(replace(spec, reported_game_exe="different.exe"))
    assert result.status == "unavailable"
    assert result.swapchains == ()


def test_import_is_explicitly_untrusted_and_preserves_provenance(spec: GameFrameImportSpec) -> None:
    result = import_presentmon_csv(spec)
    assert result.classification == "untrusted_import_only"
    assert datetime.fromisoformat(result.imported_at).tzinfo is not None
    assert result.source_label == "operator_local_file"
    assert str(spec.csv_path) not in repr(result)
    assert result.status == "partial"
    assert result.csv_sha256 == spec.csv_sha256
    assert result.reported_pid == spec.reported_pid
    assert result.reported_process_created_at == NOW.isoformat()
    assert result.settings_source == "user_attested"
    assert result.swapchains[0].presented.p50_ms == 85
    assert "not verified" in " ".join(result.limitations).lower()


def test_import_rejects_digest_mismatch_and_unbounded_input(spec: GameFrameImportSpec) -> None:
    with pytest.raises(ValueError, match="digest"):
        import_presentmon_csv(replace(spec, csv_sha256="0" * 64))
    with pytest.raises(ValueError):
        replace(spec, reported_process_created_at=NOW.replace(tzinfo=None)).validate()
    with pytest.raises(ValueError):
        replace(spec, csv_path=Path("relative.csv")).validate()


def test_import_rejects_invalid_encoding(spec: GameFrameImportSpec) -> None:
    spec.csv_path.write_bytes(b"\xff\xfe")
    digest = hashlib.sha256(spec.csv_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="encoding"):
        import_presentmon_csv(replace(spec, csv_sha256=digest))


def test_import_does_not_modify_source(spec: GameFrameImportSpec) -> None:
    before = spec.csv_path.read_bytes()
    result = import_presentmon_csv(spec)
    assert spec.csv_path.read_bytes() == before
    assert result.classification == "untrusted_import_only"
