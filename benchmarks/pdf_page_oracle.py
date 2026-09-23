"""Opt-in Windows visual witness for one pinned PDF page action.

This process is outside the investigator. It never launches a viewer or repairs
anything. A measured result is a bounded visual-transition interval, not proof
of why a PDF is slow or an authenticated VM oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Literal, Protocol

import psutil

type Rgb = tuple[int, int, int]
type Rect = tuple[int, int, int, int]
type Phase = Literal["clean", "injected", "after_arm", "after_restore"]
type Outcome = Literal["measured", "unsupported", "timeout", "cancelled", "error"]


@dataclass(frozen=True, slots=True)
class PdfPageSpec:
    trial_id: str
    phase: Phase
    pid: int
    hwnd: int
    process_created_at: datetime
    viewer_exe: Path
    viewer_sha256: str
    document: Path
    document_sha256: str
    window_title: str
    client_roi: Rect
    before_rgb: Rgb
    after_rgb: Rgb
    color_tolerance: int = 24
    min_marker_fraction: float = 0.80
    timeout_ms: int = 5000
    poll_ms: int = 20

    def validate(self) -> None:
        if not self.trial_id or len(self.trial_id) > 80:
            raise ValueError("trial_id is required and limited to 80 characters")
        if self.phase not in ("clean", "injected", "after_arm", "after_restore"):
            raise ValueError("invalid phase")
        if self.pid <= 0 or self.hwnd <= 0:
            raise ValueError("positive pid and hwnd are required")
        if self.process_created_at.utcoffset() != datetime.now(UTC).utcoffset():
            raise ValueError("process_created_at must be UTC")
        if not self.viewer_exe.is_absolute() or not self.document.is_absolute():
            raise ValueError("viewer and document paths must be absolute")
        if self.document.suffix.casefold() != ".pdf":
            raise ValueError("document path must name a PDF")
        if not self.window_title:
            raise ValueError("an exact nonempty window title is required")
        if any(value < 0 for value in self.client_roi[:2]) or any(
            not 16 <= value <= 128 for value in self.client_roi[2:]
        ):
            raise ValueError("ROI must have nonnegative origin and be 16..128 pixels per side")
        if any(not 0 <= value <= 255 for rgb in (self.before_rgb, self.after_rgb) for value in rgb):
            raise ValueError("RGB channels must be 0..255")
        if self.before_rgb == self.after_rgb:
            raise ValueError("before and after marker colors must differ")
        if not 0 <= self.color_tolerance <= 48 or not 0.50 <= self.min_marker_fraction <= 1:
            raise ValueError("invalid marker threshold")
        if all(
            abs(before - after) <= 2 * self.color_tolerance
            for before, after in zip(self.before_rgb, self.after_rgb, strict=True)
        ):
            raise ValueError("marker colors overlap at the configured tolerance")
        if not 100 <= self.timeout_ms <= 10000 or not 5 <= self.poll_ms <= 100:
            raise ValueError("timeout/poll limits exceeded")
        if self.poll_ms >= self.timeout_ms:
            raise ValueError("poll must be shorter than timeout")
        for digest in (self.viewer_sha256, self.document_sha256):
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValueError("SHA-256 values must be lowercase hex")


@dataclass(frozen=True, slots=True)
class PixelFrame:
    width: int
    height: int
    bgra: bytes

    def __post_init__(self) -> None:
        if self.width < 1 or self.height < 1 or len(self.bgra) != self.width * self.height * 4:
            raise ValueError("invalid 32-bit BGRA frame")


@dataclass(frozen=True, slots=True)
class VisualSample:
    capture_started_at: str
    observed_at: str
    capture_started_ns: int
    monotonic_ns: int
    frame_sha256: str
    before_fraction: float
    after_fraction: float


@dataclass(frozen=True, slots=True)
class PdfPageResult:
    schema_version: Literal[1]
    classification: Literal["pdf_visual_witness_only"]
    trial_id: str
    phase: Phase
    outcome: Outcome
    reason: str | None
    viewer_pid: int
    viewer_hwnd: int
    viewer_created_at: str
    viewer_sha256: str
    document_sha256: str
    window_title_sha256: str
    client_roi: Rect
    before_rgb: Rgb
    after_rgb: Rgb
    color_tolerance: int
    min_marker_fraction: float
    timeout_ms: int
    poll_ms: int
    action_started_at: str | None
    action_dispatched_at: str | None
    latency_lower_bound_ms: float | None
    latency_upper_bound_ms: float | None
    before: tuple[VisualSample, ...]
    after: tuple[VisualSample, ...]
    finished_at: str

    def as_json(self) -> dict[str, object]:
        return asdict(self)


class PageWindow(Protocol):
    def validate(self, spec: PdfPageSpec, *, full: bool) -> str | None: ...

    def capture(self, spec: PdfPageSpec) -> PixelFrame: ...

    def next_page(self, spec: PdfPageSpec) -> None: ...


class TimeSource(Protocol):
    def monotonic_ns(self) -> int: ...

    def now_utc(self) -> datetime: ...

    def sleep(self, seconds: float) -> None: ...


class SystemTime:
    def monotonic_ns(self) -> int:
        return time.perf_counter_ns()

    def now_utc(self) -> datetime:
        return datetime.now(UTC)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def marker_fraction(frame: PixelFrame, color: Rgb, tolerance: int) -> float:
    """Fraction of pixels matching a deliberately large solid page marker."""
    red, green, blue = color
    matched = 0
    pixels = frame.width * frame.height
    for index in range(0, len(frame.bgra), 4):
        b, g, r = frame.bgra[index : index + 3]
        if abs(r - red) <= tolerance and abs(g - green) <= tolerance and abs(b - blue) <= tolerance:
            matched += 1
    return matched / pixels


def measure_page_action(
    spec: PdfPageSpec,
    window: PageWindow,
    *,
    clock: TimeSource | None = None,
    cancel: Event | None = None,
) -> PdfPageResult:
    """Measure one action with two stable pre- and post-action visual samples.

    The observed transition is interval-censored by sampling. No result is
    credited if identity, focus, or markers are ambiguous at any point.
    """
    spec.validate()
    clock = clock or SystemTime()
    cancel = cancel or Event()
    before: list[VisualSample] = []
    after: list[VisualSample] = []
    action_started_at: str | None = None
    action_dispatched_at: str | None = None
    lower: float | None = None
    upper: float | None = None
    outcome: Outcome = "unsupported"
    reason: str | None = None

    def checked_sample(*, full: bool) -> VisualSample:
        problem = window.validate(spec, full=full)
        if problem:
            raise ValueError(problem)
        started_at = clock.now_utc().isoformat()
        started = clock.monotonic_ns()
        frame = window.capture(spec)
        # The target can drift during BitBlt. Validate again immediately after
        # capture, before hashing or interpreting even one pixel.
        problem = window.validate(spec, full=False)
        if problem:
            raise ValueError(problem)
        return VisualSample(
            capture_started_at=started_at,
            observed_at=clock.now_utc().isoformat(),
            capture_started_ns=started,
            monotonic_ns=clock.monotonic_ns(),
            frame_sha256=hashlib.sha256(frame.bgra).hexdigest(),
            before_fraction=marker_fraction(frame, spec.before_rgb, spec.color_tolerance),
            after_fraction=marker_fraction(frame, spec.after_rgb, spec.color_tolerance),
        )

    try:
        if cancel.is_set():
            outcome, reason = "cancelled", "cancelled_before_action"
        else:
            before.append(checked_sample(full=True))
            clock.sleep(spec.poll_ms / 1000)
            before.append(checked_sample(full=False))
            if any(
                row.before_fraction < spec.min_marker_fraction
                or row.after_fraction >= 1 - spec.min_marker_fraction
                for row in before
            ):
                reason = "start_marker_not_stable_or_target_already_visible"
            elif cancel.is_set():
                outcome, reason = "cancelled", "cancelled_before_action"
            else:
                problem = window.validate(spec, full=True)
                if problem:
                    reason = problem
                else:
                    action_started_at = clock.now_utc().isoformat()
                    started_ns = clock.monotonic_ns()
                    window.next_page(spec)
                    action_dispatched_at = clock.now_utc().isoformat()
                    last_negative_ns = started_ns
                    deadline = started_ns + spec.timeout_ms * 1_000_000
                    while clock.monotonic_ns() < deadline:
                        if cancel.is_set():
                            outcome, reason = "cancelled", "cancelled_after_action"
                            break
                        sample = checked_sample(full=False)
                        after.append(sample)
                        target = sample.after_fraction >= spec.min_marker_fraction
                        if target and sample.before_fraction < 1 - spec.min_marker_fraction:
                            if len(after) >= 2 and (
                                after[-2].after_fraction >= spec.min_marker_fraction
                                and after[-2].before_fraction < 1 - spec.min_marker_fraction
                            ):
                                first = after[-2]
                                lower = round(max(0, last_negative_ns - started_ns) / 1e6, 3)
                                upper = round((first.monotonic_ns - started_ns) / 1e6, 3)
                                outcome, reason = "measured", None
                                break
                        else:
                            last_negative_ns = sample.capture_started_ns
                        clock.sleep(spec.poll_ms / 1000)
                    else:
                        outcome, reason = "timeout", "target_marker_not_observed_before_deadline"
    except ValueError as error:
        outcome, reason = "unsupported", str(error)
    except KeyboardInterrupt:
        outcome, reason = "cancelled", "keyboard_interrupt"
    except (OSError, psutil.Error) as error:
        outcome, reason = "error", type(error).__name__
    except Exception as error:
        # pywin32 raises pywintypes.error (not OSError). Any unexpected
        # adapter failure must remain a failed witness, never a measurement.
        outcome, reason = "error", type(error).__name__
    if outcome == "measured":
        try:
            problem = window.validate(spec, full=True)
        except KeyboardInterrupt:
            outcome, reason, lower, upper = "cancelled", "keyboard_interrupt", None, None
            problem = None
        except Exception as error:
            outcome, reason, lower, upper = "error", type(error).__name__, None, None
            problem = None
        if problem:
            outcome, reason, lower, upper = "unsupported", problem, None, None
    return PdfPageResult(
        schema_version=1,
        classification="pdf_visual_witness_only",
        trial_id=spec.trial_id,
        phase=spec.phase,
        outcome=outcome,
        reason=reason,
        viewer_pid=spec.pid,
        viewer_hwnd=spec.hwnd,
        viewer_created_at=spec.process_created_at.isoformat(),
        viewer_sha256=spec.viewer_sha256,
        document_sha256=spec.document_sha256,
        window_title_sha256=hashlib.sha256(spec.window_title.encode("utf-8")).hexdigest(),
        client_roi=spec.client_roi,
        before_rgb=spec.before_rgb,
        after_rgb=spec.after_rgb,
        color_tolerance=spec.color_tolerance,
        min_marker_fraction=spec.min_marker_fraction,
        timeout_ms=spec.timeout_ms,
        poll_ms=spec.poll_ms,
        action_started_at=action_started_at,
        action_dispatched_at=action_dispatched_at,
        latency_lower_bound_ms=lower,
        latency_upper_bound_ms=upper,
        before=tuple(before),
        after=tuple(after),
        finished_at=clock.now_utc().isoformat(),
    )


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


class WindowsPageWindow:
    """Existing foreground window only; no launch or focus-stealing."""

    def validate(self, spec: PdfPageSpec, *, full: bool) -> str | None:
        if sys.platform != "win32":
            return "windows_desktop_required"
        import win32gui  # type: ignore[import-untyped]
        import win32process  # type: ignore[import-untyped]

        if not win32gui.IsWindow(spec.hwnd) or not win32gui.IsWindowVisible(spec.hwnd):
            return "window_missing_or_hidden"
        if win32gui.GetForegroundWindow() != spec.hwnd:
            return "pinned_window_not_foreground"
        _, window_pid = win32process.GetWindowThreadProcessId(spec.hwnd)
        if window_pid != spec.pid or win32gui.GetWindowText(spec.hwnd) != spec.window_title:
            return "window_identity_or_title_changed"
        left, top, right, bottom = win32gui.GetClientRect(spec.hwnd)
        x, y, width, height = spec.client_roi
        if left != 0 or top != 0 or x + width > right or y + height > bottom:
            return "marker_region_outside_client"
        center = win32gui.ClientToScreen(spec.hwnd, (x + width // 2, y + height // 2))
        hit = win32gui.WindowFromPoint(center)
        if not hit or (hit != spec.hwnd and not win32gui.IsChild(spec.hwnd, hit)):
            return "marker_region_occluded_or_not_owned"
        _, hit_pid = win32process.GetWindowThreadProcessId(hit)
        if hit_pid != spec.pid:
            return "marker_region_occluded_or_not_owned"
        process = psutil.Process(spec.pid)
        if abs(process.create_time() - spec.process_created_at.timestamp()) > 0.01:
            return "process_creation_changed"
        if full:
            if Path(process.exe()).resolve() != spec.viewer_exe.resolve():
                return "viewer_executable_changed"
            if _digest(spec.viewer_exe) != spec.viewer_sha256:
                return "viewer_digest_changed"
            with spec.document.open("rb") as stream:
                if stream.read(5) != b"%PDF-":
                    return "document_is_not_pdf"
            if _digest(spec.document) != spec.document_sha256:
                return "document_digest_changed"
            # A title alone does not bind the displayed document. Require an
            # exact command-line argument naming the pinned local PDF.
            document = str(spec.document.resolve()).casefold()
            if not any(
                str(Path(arg).resolve()).casefold() == document for arg in process.cmdline()[1:]
            ):
                return "viewer_command_does_not_pin_document"
        return None

    def capture(self, spec: PdfPageSpec) -> PixelFrame:
        import win32con  # type: ignore[import-untyped]
        import win32gui  # type: ignore[import-untyped]
        import win32ui  # type: ignore[import-untyped]

        x, y, width, height = spec.client_roi
        screen_x, screen_y = win32gui.ClientToScreen(spec.hwnd, (x, y))
        from typing import cast

        screen_dc_handle = cast(int, win32gui.GetDC(0))  # type: ignore[reportUnknownMemberType]
        screen_dc = win32ui.CreateDCFromHandle(screen_dc_handle)
        memory_dc = screen_dc.CreateCompatibleDC()
        bitmap = win32ui.CreateBitmap()
        try:
            bitmap.CreateCompatibleBitmap(screen_dc, width, height)
            memory_dc.SelectObject(bitmap)
            memory_dc.BitBlt(
                (0, 0), (width, height), screen_dc, (screen_x, screen_y), win32con.SRCCOPY
            )
            bits = bitmap.GetBitmapBits(True)
            return PixelFrame(width, height, bytes(bits))
        finally:
            memory_dc.DeleteDC()
            screen_dc.DeleteDC()
            win32gui.ReleaseDC(0, screen_dc_handle)
            win32gui.DeleteObject(bitmap.GetHandle())

    def next_page(self, spec: PdfPageSpec) -> None:
        import win32con  # type: ignore[import-untyped]
        import win32gui  # type: ignore[import-untyped]

        if problem := self.validate(spec, full=False):
            raise ValueError(problem)
        # A numeric HWND cannot be atomically locked against reuse. Callers
        # must confine this action to a disposable VM; this CLI cannot attest
        # that isolation. Recheck between posts and skip the second on drift.
        win32gui.PostMessage(spec.hwnd, win32con.WM_KEYDOWN, win32con.VK_NEXT, 1)
        if problem := self.validate(spec, full=False):
            raise ValueError(problem)
        win32gui.PostMessage(spec.hwnd, win32con.WM_KEYUP, win32con.VK_NEXT, 0xC0000001)
        if problem := self.validate(spec, full=False):
            raise ValueError(problem)


def _parse_rgb(value: str) -> Rgb:
    parts = value.split(",")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("RGB must be R,G,B")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError as error:
        raise argparse.ArgumentTypeError("RGB must contain integers") from error


def _parse_rect(value: str) -> Rect:
    parts = value.split(",")
    if len(parts) != 4:
        raise argparse.ArgumentTypeError("ROI must be X,Y,W,H")
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
    except ValueError as error:
        raise argparse.ArgumentTypeError("ROI must contain integers") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trial-id", required=True)
    parser.add_argument(
        "--phase", choices=("clean", "injected", "after_arm", "after_restore"), required=True
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--hwnd", type=int, required=True)
    parser.add_argument("--process-created-at", required=True)
    parser.add_argument("--viewer-exe", type=Path, required=True)
    parser.add_argument("--viewer-sha256", required=True)
    parser.add_argument("--document", type=Path, required=True)
    parser.add_argument("--document-sha256", required=True)
    parser.add_argument("--window-title", required=True)
    parser.add_argument("--roi", type=_parse_rect, required=True)
    parser.add_argument("--before-rgb", type=_parse_rgb, required=True)
    parser.add_argument("--after-rgb", type=_parse_rgb, required=True)
    parser.add_argument("--color-tolerance", type=int, default=24)
    parser.add_argument("--min-marker-fraction", type=float, default=0.80)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    parser.add_argument("--poll-ms", type=int, default=20)
    parser.add_argument("--focus-wait-ms", type=int, default=3000)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--confirm-page-input", action="store_true")
    args = parser.parse_args(argv)
    if not args.confirm_page_input or os.environ.get("SYSTEMSENSE_PDF_ORACLE") != "1":
        parser.error("requires --confirm-page-input and SYSTEMSENSE_PDF_ORACLE=1")
    if not 0 <= args.focus_wait_ms <= 10000:
        parser.error("focus wait must be 0..10000 ms")
    spec = PdfPageSpec(
        trial_id=args.trial_id,
        phase=args.phase,
        pid=args.pid,
        hwnd=args.hwnd,
        process_created_at=datetime.fromisoformat(args.process_created_at),
        viewer_exe=args.viewer_exe,
        viewer_sha256=args.viewer_sha256,
        document=args.document,
        document_sha256=args.document_sha256,
        window_title=args.window_title,
        client_roi=args.roi,
        before_rgb=args.before_rgb,
        after_rgb=args.after_rgb,
        color_tolerance=args.color_tolerance,
        min_marker_fraction=args.min_marker_fraction,
        timeout_ms=args.timeout_ms,
        poll_ms=args.poll_ms,
    )
    spec.validate()
    if not args.output.is_absolute():
        parser.error("output path must be absolute")
    if args.output.exists():
        raise FileExistsError("final output already exists")
    reservation = args.output.with_name(args.output.name + ".reservation")
    staging = args.output.with_name(args.output.name + ".staged")
    with reservation.open("xb") as receipt, staging.open("xb+") as stage:
        # Both names are exclusively reserved before UI interaction. Only a
        # complete, fsynced staged result can become the final file.
        reserved = json.dumps(
            {
                "schema_version": 1,
                "classification": "pdf_visual_witness_only",
                "trial_id": spec.trial_id,
                "phase": spec.phase,
                "status": "reserved",
                "reserved_at": datetime.now(UTC).isoformat(),
            },
            sort_keys=True,
        ).encode("utf-8")
        receipt.write(reserved)
        receipt.flush()
        os.fsync(receipt.fileno())
        if args.focus_wait_ms:
            print(
                "Focus the already-open pinned viewer now; no window will be launched.",
                file=sys.stderr,
            )
            time.sleep(args.focus_wait_ms / 1000)
        result = measure_page_action(spec, WindowsPageWindow())
        payload = json.dumps(result.as_json(), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        stage.write(payload)
        stage.flush()
        os.fsync(stage.fileno())
    if _digest(staging) != hashlib.sha256(payload).hexdigest():
        raise OSError("staged result readback failed")
    # Hard-link creation fails if a final path already exists and exposes only
    # the completed bytes; unlike rename it never replaces another trial.
    os.link(staging, args.output)
    try:
        final_valid = _digest(args.output) == hashlib.sha256(payload).hexdigest()
    except OSError:
        final_valid = False
    if not final_valid:
        # The final name was just created as a hard link to our staged inode.
        # Remove it only while it still names that same inode; a different
        # file appearing at the path belongs to somebody else.
        if args.output.exists() and os.path.samefile(staging, args.output):
            args.output.unlink()
        raise OSError("final result readback failed")
    staging.unlink()
    print(payload.decode("utf-8"))
    return 0 if result.outcome == "measured" else 2


if __name__ == "__main__":
    raise SystemExit(main())
