# Slow-PDF page-action episode: visual witness qualification

The first PDF lane must measure the user's actual visible page interaction, not
substitute CPU utilization, Poppler render time, or a model's impression of
slowness. `benchmarks/pdf_page_oracle.py` is an **opt-in host-side visual witness**
for one already-open, pinned local viewer and document. It is outside
SystemSense's investigator and never launches a viewer, changes a setting,
inserts a fault, or performs a repair. **Page Down is a consented benchmark
navigation action, not read-only investigation.** It posts the message to an
exact window handle only after checking process creation time, executable path
and digest, document digest, exact document command-line argument, window title,
foreground state, and a visible start-page color marker.

The benchmark document needs two deliberately large, distinct solid-color
markers in the same small client-area region on consecutive pages. The witness
samples a 16-128 pixel square ROI twice before action, then polls for two
consecutive samples of the target marker. Raw screenshots are not persisted;
each sample retains a frame digest, marker fractions, UTC capture bounds and a
process-local monotonic time. The result also records the ROI, colors,
thresholds, polling period, timeout, and a hash of the exact window title, so
the measurement configuration is reviewable without exposing the title. Since
monotonic values are process-local, compare interval durations rather than
subtracting raw counters from different trials. Because the visual transition
may happen between captures, the
result reports **lower and upper latency bounds**, not an exact page-turn time.
Timeout, focus/identity drift, an ambiguous marker, a missing target, or an
interrupted trial cannot count as a measured slow page. The requested output
path has separate `.reservation`, `.staged`, and final files. The reservation
is exclusively created and synced before action. The staged result is written,
synced, and read back; an atomic hard-link publishes those complete bytes at
the final path without replacing an existing file. The harness removes only
its own redundant stage after final readback. A crash before publication leaves
no final file, plus a reservation and possibly a partial or complete stage;
neither sidecar alone is a successful trial. The reservation remains as an
immutable record of the attempted run. This is crash-safe publication, not
cryptographic custody or authenticated sensor origin. The output directory
must support same-directory hard links (normally local NTFS); if it does not,
publication fails with no final result and the staged bytes remain for review.
If final readback fails, the harness removes the final name only if it still
points to its staged inode; reservation and stage remain for examination. A
different file observed at that check is not deleted. The path check and unlink
are not atomic against a hostile concurrent writer, so use an isolated guest
artifact directory and do not interpret this as adversarial tamper protection.

The witness only navigates an existing target window with `PostMessage`, which
may be ignored by a viewer. This avoids global `SendInput`, which could race
with focus and send Page Down to an unrelated foreground application. However,
the numeric HWND cannot be atomically locked to a process identity while
posting two messages. Another window could reuse the value between a check and
a post. **Operate it only in a disposable interactive VM.** The CLI cannot
attest that it is in one: its environment variable and confirmation flag are
operator opt-in, not a sandbox or host-action permission proof. Running it on
the personal host is possible and risks navigating an unrelated window. The
witness rechecks after the first post and skips the second on drift, but that
narrows rather than eliminates the race. Microsoft's
[PostMessage documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagew)
states that delivery to the window queue is not guaranteed to make an app act;
the visual transition, not a successful post, is the outcome check.
[BitBlt](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-bitblt)
copies the visible pixel region. Foreground and
[WindowFromPoint](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-windowfrompoint)
owner checks before and immediately after each capture reject many occlusions,
but cannot authenticate the display pipeline, catch every transparent overlay,
or prove that the viewer's internal page number changed. An exact command-line document argument excludes common
browser multi-tab processes; no Chrome PDF episode is qualified by this path.

## Qualification and invocation

Use a disposable, interactive VM with an existing dedicated viewer that names
the exact PDF path in its process command line, a locally stored and hashed
two-page test PDF, a fixed window size/zoom/ROI, and a fixed display scale. The
independent rig must pin and record viewer version, executable and document
SHA-256, PID plus UTC creation time, exact HWND/title, screenshot-marker colors,
the full clean/fault/recovery configuration, and host/guest clock state. Before
each trial, reset the viewer to the marked start page outside the investigator,
verify the start marker, and then run the same action. Use different write-once
output paths for clean, injected, after-arm, and after-restore phases. No phase
or ratio may be inferred from the filename alone; the result carries its phase.

```powershell
$env:SYSTEMSENSE_PDF_ORACLE = '1'
uv run --frozen python -m benchmarks.pdf_page_oracle `
  --confirm-page-input --trial-id pdf-clean-01 --phase clean `
  --pid $PdfRigPid --hwnd $PdfRigHwnd `
  --process-created-at $PdfRigProcessCreatedAt `
  --viewer-exe $PdfRigViewerExe --viewer-sha256 $PdfRigViewerSha256 `
  --document $PdfRigDocument --document-sha256 $PdfRigDocumentSha256 `
  --window-title $PdfRigWindowTitle --roi 40,40,64,64 `
  --before-rgb 240,20,20 --after-rgb 20,240,20 `
  --timeout-ms 5000 --poll-ms 20 --focus-wait-ms 3000 `
  --output $PdfRigNewOutputPath
```

The operator starts the command, then focuses the already-open viewer during
the bounded focus wait. `--confirm-page-input` and the environment variable
must both be present. The command will not overwrite a prior trial artifact.
Do not run it on a personal host desktop, an unrelated foreground window, or a
personal document. Color markers, ROI, viewer behavior, and visual
sample overhead need empirical calibration on the exact guest setup. The
interval may be too wide to resolve a fast page turn; such a configuration
cannot support a 2x latency threshold even if the code reports `measured`.

## Admission and missing evidence

This is `pdf_visual_witness_only`, not an authenticated oracle or a diagnostic
score. It does not prove the displayed pixels came from the pinned PDF rather
than an overlay, that the injected CPU contention caused the delay, that a
reviewer was blinded, or that a repair helped. The independent VM controller
still needs to prove clean reset, injected fault, viewer/document ownership,
same page action and cache/warm state per arm, monotonic and UTC clock sanity,
and repeatability. Store sealed fault labels apart from investigator evidence;
run matched A/B/C arms, independent before/after oracle captures, and collateral
checks. If the PDF is slow, compare page-action intervals to simultaneous
viewer-thread ready time, CPU/disk waits, page faults, and process identity
before asserting a cause. Any production claim also needs diverse held-out
episodes with healthy and external controls.

On the current development host, only Chrome was found; no pinned dedicated
PDF viewer/document or qualified VM guest session was available. No live PDF
trial or slowdown measurement was run. The fake-backed tests validate the
contract and fail-closed paths, not viewer compatibility or measured page
latency. The next gate is to qualify one dedicated viewer and a marker PDF in
the isolated guest, then verify a clean trial's raw visual interval and reset
repeatability before injecting contention.
