"""Contract tests for the independent visual PDF page-action witness."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest

import benchmarks.pdf_page_oracle as pdf_oracle
from benchmarks.pdf_page_oracle import (
    PdfPageSpec,
    PixelFrame,
    WindowsPageWindow,
    main,
    marker_fraction,
    measure_page_action,
)

NOW = datetime(2026, 9, 23, 10, 0, tzinfo=UTC)
RED = (240, 20, 20)
GREEN = (20, 240, 20)


def frame(rgb: tuple[int, int, int]) -> PixelFrame:
    red, green, blue = rgb
    return PixelFrame(16, 16, bytes((blue, green, red, 255)) * 256)


class FakeClock:
    def __init__(self) -> None:
        self.elapsed_ns = 0

    def monotonic_ns(self) -> int:
        return self.elapsed_ns

    def now_utc(self) -> datetime:
        return NOW + timedelta(microseconds=self.elapsed_ns / 1000)

    def sleep(self, seconds: float) -> None:
        self.elapsed_ns += int(seconds * 1e9)


class FakeWindow:
    def __init__(self, clock: FakeClock, *, transition_after: int = 1) -> None:
        self.clock = clock
        self.transition_after = transition_after
        self.actions = 0
        self.post_captures = 0
        self.problem: str | None = None
        self.final_problem: str | None = None
        self.validation_calls = 0

    def validate(self, spec: PdfPageSpec, *, full: bool) -> str | None:
        self.validation_calls += 1
        if self.actions and full and self.final_problem:
            return self.final_problem
        return self.problem

    def capture(self, spec: PdfPageSpec) -> PixelFrame:
        if not self.actions:
            return frame(RED)
        self.post_captures += 1
        return frame(GREEN if self.post_captures >= self.transition_after else RED)

    def next_page(self, spec: PdfPageSpec) -> None:
        self.actions += 1
        self.clock.sleep(0.004)


@pytest.fixture
def spec(tmp_path: Path) -> PdfPageSpec:
    return PdfPageSpec(
        trial_id="pdf-clean-01",
        phase="clean",
        pid=100,
        hwnd=200,
        process_created_at=NOW,
        viewer_exe=tmp_path / "reader.exe",
        viewer_sha256="a" * 64,
        document=tmp_path / "pinned.pdf",
        document_sha256="b" * 64,
        window_title="pinned.pdf - Reader",
        client_roi=(30, 30, 16, 16),
        before_rgb=RED,
        after_rgb=GREEN,
        poll_ms=20,
        timeout_ms=100,
    )


def test_visual_transition_is_interval_censored_not_exact_latency(spec: PdfPageSpec) -> None:
    clock = FakeClock()
    window = FakeWindow(clock, transition_after=2)
    result = measure_page_action(spec, window, clock=clock)
    assert result.outcome == "measured"
    assert result.classification == "pdf_visual_witness_only"
    assert result.action_started_at is not None
    assert result.action_dispatched_at is not None
    assert result.client_roi == spec.client_roi
    assert result.poll_ms == spec.poll_ms
    assert len(result.window_title_sha256) == 64
    assert result.latency_lower_bound_ms == 4
    assert result.latency_upper_bound_ms == 24
    assert len(result.before) == 2
    assert len(result.after) == 3
    assert window.actions == 1


def test_identity_failure_never_sends_action(spec: PdfPageSpec) -> None:
    clock = FakeClock()
    window = FakeWindow(clock)
    window.problem = "window_identity_or_title_changed"
    result = measure_page_action(spec, window, clock=clock)
    assert result.outcome == "unsupported"
    assert result.reason == "window_identity_or_title_changed"
    assert result.action_started_at is None
    assert window.actions == 0


def test_target_already_visible_never_sends_action(spec: PdfPageSpec) -> None:
    class WrongStart(FakeWindow):
        def capture(self, spec: PdfPageSpec) -> PixelFrame:
            return frame(GREEN)

    clock = FakeClock()
    window = WrongStart(clock)
    result = measure_page_action(spec, window, clock=clock)
    assert result.outcome == "unsupported"
    assert result.reason == "start_marker_not_stable_or_target_already_visible"
    assert window.actions == 0


def test_timeout_is_not_a_measured_slow_page(spec: PdfPageSpec) -> None:
    clock = FakeClock()
    window = FakeWindow(clock, transition_after=100)
    result = measure_page_action(spec, window, clock=clock)
    assert result.outcome == "timeout"
    assert result.latency_lower_bound_ms is None
    assert result.latency_upper_bound_ms is None
    assert window.actions == 1


def test_final_document_or_viewer_change_revokes_measurement(spec: PdfPageSpec) -> None:
    clock = FakeClock()
    window = FakeWindow(clock)
    window.final_problem = "document_digest_changed"
    result = measure_page_action(spec, window, clock=clock)
    assert result.outcome == "unsupported"
    assert result.reason == "document_digest_changed"
    assert result.latency_upper_bound_ms is None


def test_cancel_before_action_does_not_touch_viewer(spec: PdfPageSpec) -> None:
    clock = FakeClock()
    window = FakeWindow(clock)
    cancelled = Event()
    cancelled.set()
    result = measure_page_action(spec, window, clock=clock, cancel=cancelled)
    assert result.outcome == "cancelled"
    assert window.actions == 0


def test_focus_drift_after_action_withholds_latency(spec: PdfPageSpec) -> None:
    class FocusLost(FakeWindow):
        def next_page(self, spec: PdfPageSpec) -> None:
            super().next_page(spec)
            self.problem = "pinned_window_not_foreground"

    clock = FakeClock()
    result = measure_page_action(spec, FocusLost(clock), clock=clock)
    assert result.outcome == "unsupported"
    assert result.reason == "pinned_window_not_foreground"
    assert result.latency_upper_bound_ms is None


def test_transient_identity_flip_during_capture_withholds_latency(spec: PdfPageSpec) -> None:
    class FlipDuringCapture(FakeWindow):
        invalid_until_ns = -1

        def capture(self, spec: PdfPageSpec) -> PixelFrame:
            image = super().capture(spec)
            if self.actions and self.post_captures == 1:
                self.invalid_until_ns = self.clock.monotonic_ns() + 1_000_000
            return image

        def validate(self, spec: PdfPageSpec, *, full: bool) -> str | None:
            if self.clock.monotonic_ns() < self.invalid_until_ns:
                return "pinned_window_not_foreground"
            return super().validate(spec, full=full)

    clock = FakeClock()
    result = measure_page_action(spec, FlipDuringCapture(clock), clock=clock)
    assert result.outcome == "unsupported"
    assert result.reason == "pinned_window_not_foreground"
    assert result.latency_upper_bound_ms is None


def test_keyboard_interrupt_is_recorded_as_cancelled(spec: PdfPageSpec) -> None:
    class Interrupted(FakeWindow):
        def capture(self, spec: PdfPageSpec) -> PixelFrame:
            if self.actions:
                raise KeyboardInterrupt
            return super().capture(spec)

    clock = FakeClock()
    result = measure_page_action(spec, Interrupted(clock), clock=clock)
    assert result.outcome == "cancelled"
    assert result.reason == "keyboard_interrupt"
    assert result.latency_upper_bound_ms is None


def test_unexpected_capture_error_never_becomes_measurement(spec: PdfPageSpec) -> None:
    class FailedCapture(FakeWindow):
        def capture(self, spec: PdfPageSpec) -> PixelFrame:
            if self.actions:
                raise RuntimeError("backend failure")
            return super().capture(spec)

    clock = FakeClock()
    result = measure_page_action(spec, FailedCapture(clock), clock=clock)
    assert result.outcome == "error"
    assert result.reason == "RuntimeError"
    assert result.latency_upper_bound_ms is None


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 message contract")
def test_page_action_posts_only_to_exact_pinned_hwnd(
    spec: PdfPageSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    import win32con
    import win32gui

    class QualifiedWindow(WindowsPageWindow):
        def validate(self, spec: PdfPageSpec, *, full: bool) -> str | None:
            return None

    posts: list[tuple[int, int, int, int]] = []

    def record_post(hwnd: int, message: int, key: int, flags: int) -> None:
        posts.append((hwnd, message, key, flags))

    monkeypatch.setattr(win32gui, "PostMessage", record_post)
    QualifiedWindow().next_page(spec)
    assert posts == [
        (spec.hwnd, win32con.WM_KEYDOWN, win32con.VK_NEXT, 1),
        (spec.hwnd, win32con.WM_KEYUP, win32con.VK_NEXT, 0xC0000001),
    ]


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 message contract")
def test_page_action_skips_second_post_after_identity_drift(
    spec: PdfPageSpec, monkeypatch: pytest.MonkeyPatch
) -> None:
    import win32con
    import win32gui

    class WindowChangesAfterFirstPost(WindowsPageWindow):
        checks = 0

        def validate(self, spec: PdfPageSpec, *, full: bool) -> str | None:
            self.checks += 1
            return "window_identity_or_title_changed" if self.checks == 2 else None

    posts: list[tuple[int, int, int, int]] = []

    def record_post(hwnd: int, message: int, key: int, flags: int) -> None:
        posts.append((hwnd, message, key, flags))

    monkeypatch.setattr(win32gui, "PostMessage", record_post)
    with pytest.raises(ValueError, match="window_identity_or_title_changed"):
        WindowChangesAfterFirstPost().next_page(spec)
    assert posts == [(spec.hwnd, win32con.WM_KEYDOWN, win32con.VK_NEXT, 1)]


def test_spec_rejects_unbounded_or_ambiguous_measurement(spec: PdfPageSpec) -> None:
    for invalid in (
        replace(spec, timeout_ms=60_000),
        replace(spec, client_roi=(0, 0, 1024, 1024)),
        replace(spec, before_rgb=GREEN),
        replace(spec, process_created_at=NOW.replace(tzinfo=None)),
        replace(spec, document_sha256="made-up"),
        replace(spec, document=Path("relative.pdf")),
        replace(spec, document=spec.document.with_suffix(".txt")),
    ):
        with pytest.raises(ValueError):
            invalid.validate()


def test_marker_fraction_uses_rgb_not_bgra_order() -> None:
    assert marker_fraction(frame(RED), RED, 0) == 1
    assert marker_fraction(frame(RED), GREEN, 0) == 0


def cli_args(spec: PdfPageSpec, output: Path) -> list[str]:
    return [
        "--trial-id",
        spec.trial_id,
        "--phase",
        spec.phase,
        "--pid",
        str(spec.pid),
        "--hwnd",
        str(spec.hwnd),
        "--process-created-at",
        spec.process_created_at.isoformat(),
        "--viewer-exe",
        str(spec.viewer_exe),
        "--viewer-sha256",
        spec.viewer_sha256,
        "--document",
        str(spec.document),
        "--document-sha256",
        spec.document_sha256,
        "--window-title",
        spec.window_title,
        "--roi",
        "30,30,16,16",
        "--before-rgb",
        "240,20,20",
        "--after-rgb",
        "20,240,20",
        "--output",
        str(output),
    ]


def test_cli_without_both_opt_in_gates_creates_no_capture(
    spec: PdfPageSpec, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SYSTEMSENSE_PDF_ORACLE", raising=False)
    output = tmp_path / "would-be-trial.json"
    args = cli_args(spec, output)
    with pytest.raises(SystemExit):
        main(args)
    assert not output.exists()
    monkeypatch.setenv("SYSTEMSENSE_PDF_ORACLE", "1")
    with pytest.raises(SystemExit):
        main(args)
    assert not output.exists()


def test_cli_reserves_write_once_artifact_before_window_action(
    spec: PdfPageSpec, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "trial.json"

    class ReservedWindow(FakeWindow):
        def validate(self, spec: PdfPageSpec, *, full: bool) -> str | None:
            reservation = json.loads(
                output.with_name(output.name + ".reservation").read_text(encoding="utf-8")
            )
            assert reservation["status"] == "reserved"
            assert output.with_name(output.name + ".staged").exists()
            assert not output.exists()
            return super().validate(spec, full=full)

    window = ReservedWindow(FakeClock())
    monkeypatch.setattr(pdf_oracle, "WindowsPageWindow", lambda: window)
    monkeypatch.setenv("SYSTEMSENSE_PDF_ORACLE", "1")
    assert main([*cli_args(spec, output), "--confirm-page-input", "--focus-wait-ms", "0"]) == 0
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["outcome"] == "measured"
    assert saved["trial_id"] == spec.trial_id
    assert window.actions == 1
    assert output.with_name(output.name + ".reservation").exists()
    assert not output.with_name(output.name + ".staged").exists()
    with pytest.raises(FileExistsError):
        main([*cli_args(spec, output), "--confirm-page-input", "--focus-wait-ms", "0"])
    assert window.actions == 1


def test_final_path_is_absent_if_atomic_publish_fails(
    spec: PdfPageSpec, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "trial.json"
    monkeypatch.setattr(pdf_oracle, "WindowsPageWindow", lambda: FakeWindow(FakeClock()))
    monkeypatch.setenv("SYSTEMSENSE_PDF_ORACLE", "1")

    def fail_link(source: Path, target: Path) -> None:
        raise OSError("publish failed")

    monkeypatch.setattr(pdf_oracle.os, "link", fail_link)
    with pytest.raises(OSError, match="publish failed"):
        main([*cli_args(spec, output), "--confirm-page-input", "--focus-wait-ms", "0"])
    assert not output.exists()
    assert output.with_name(output.name + ".reservation").exists()
    staged = json.loads(output.with_name(output.name + ".staged").read_text(encoding="utf-8"))
    assert staged["outcome"] == "measured"


def test_final_readback_failure_removes_only_new_final_link(
    spec: PdfPageSpec, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "trial.json"
    monkeypatch.setattr(pdf_oracle, "WindowsPageWindow", lambda: FakeWindow(FakeClock()))
    monkeypatch.setenv("SYSTEMSENSE_PDF_ORACLE", "1")

    def bad_final_readback(path: Path) -> str:
        return "0" * 64 if path == output else hashlib.sha256(path.read_bytes()).hexdigest()

    monkeypatch.setattr(pdf_oracle, "_digest", bad_final_readback)
    with pytest.raises(OSError, match="final result readback failed"):
        main([*cli_args(spec, output), "--confirm-page-input", "--focus-wait-ms", "0"])
    assert not output.exists()
    assert output.with_name(output.name + ".reservation").exists()
    assert output.with_name(output.name + ".staged").exists()
