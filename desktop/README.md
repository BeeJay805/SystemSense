# Dyad desktop

A Windows desktop client for the existing read-only investigator. Product contracts remain in [the canonical architecture](../docs/ARCHITECTURE.md) and [current state](../docs/CURRENT_STATE.md). This directory owns only the desktop shell, renderer, packaging wrapper and its tests.

## Run and build

The Windows installer bundles Python and the investigator. End users do not need Python or Node; the optional Laya + Sol mode requires pinned local Laya files and a signed-in Codex ChatGPT subscription. The build is unsigned and is a private-alpha candidate, not a signed public release. No updater, browser extension, repair executor or tray service is included.

Developer prerequisites: Windows x64, Node 22.12+, npm, and `uv` (which supplies Python 3.12). From this directory:

```powershell
npm ci --legacy-peer-deps
./scripts/build-backend.ps1
npm run build
npm start
```

`build-backend.ps1` exports the repository's frozen runtime lock, installs the existing package into a desktop-only virtual environment, and creates a PyInstaller folder at `backend/dist/investigator`. Its entrypoint dispatches only the fixed isolated-worker invocation; it does not accept arbitrary Python modules. The model mode uses pinned per-user local files and the installed Codex subscription login, never a separately billed API key.

```powershell
npm test
npm run test:e2e
npm run typecheck
npm run lint
npm run format:check
npm run installer
```

The resulting installer is `release/Dyad Setup 0.1.0.exe`; the directly runnable folder is `release/win-unpacked`. Keep that folder intact. Packaging intentionally disables signing, and makes no certificate or publishing request. The Electron/Chromium bundle increases distribution size compared with Tauri. A local Rust compile failed because the Microsoft linker was unavailable; A approved Electron rather than installing system build tools.

## Controls and their purpose

| Control                              | Behavior and reason                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| What’s not working? / Investigate    | Submit one problem description directly after reading the inline limitations. Enter submits, Shift+Enter adds a new line, and IME composition never submits. The capability contract is rechecked before starting; unsupported or missing read-only catalogs stay blocked.                                                                                                       |
| Inline capability limits             | Relevant browser-page or app-selection limitations appear with the problem description. The general helper copy is omitted; the read-only catalog guard and backend authorization remain enforced.                                                                                                                                                                               |
| Stop investigation                   | Request cancellation and preserve saved evidence. “Stopping” persists until the engine reports a terminal status.                                                                                                                                                                                                                                                                |
| Show details                         | One expansion reveals observations with source IDs and timestamps, coverage, interpretation, and actual activity. Advisory text is separated from supported observations.                                                                                                                                                                                                        |
| History                              | A visible labeled control opens saved problems with date, truthful reported outcome and elapsed case time. Elapsed time comes from case creation and saved update timestamps, includes pauses between runs, and is not active execution time. Reopening never resumes a case. The dialog traps focus and supports Escape.                                                        |
| Settings                             | Select basic checks or Laya + Sol. A change restarts the owned backend, checks readiness, and blocks starting a model case when setup fails. The panel traps keyboard focus, restores focus on close, and fits normal and 150% display scales. |
| Activity                             | Chronological reported events and captured evidence use durable state versions/evidence IDs and original event/capture timestamps. Pending checks have no invented start time. New incoming entries reveal once; polling and history reopen do not replay old entries. Unknown event kinds stay recorded, not promoted to success. The bounded view is not a complete audit log. |
| Continue investigation               | Explicitly resume a cancelled, interrupted or failed case through the existing API. Never resume automatically.                                                                                                                                                                                                                                                                  |
| Export evidence                      | Available inside details. Save the existing bounded report using a native Save dialog. The renderer cannot choose arbitrary file paths.                                                                                                                                                                                                                                          |
| Minimize / Quit Dyad or window close | Minimize leaves the owned engine running. Quit, inside saved investigations, closes its private stdin pipe and waits for `ApplicationService.close()` to stop and save. Reopen recovers saved cases.                                                                                                                                                                             |

For an independently observed affected-task result, describe one exact `http://127.0.0.1:<49152-65535>/health/<32-lowercase-hex-nonce>` endpoint. Dyad makes one bounded GET to that local endpoint. After a timeout, the model route may select a source-bound check that repeats only the same GET while sampling the verified listener owner's CPU. This can compare active process work with near-idle waiting at the repeated GET's time; it does not establish the handler cause or the initial request's internal path. General websites and application complaints remain reports unless another supported observer measures their outcome.

A direct question about whether one named `.exe` is running can also receive an evidence-cited answer when the saved process inventory is complete. It describes the sampled time only; asking why a process stopped remains unresolved without causal evidence. This Windows inventory uses a bundled WMI client in the current installer.

The landing screen keeps intake and labeled History and Settings controls. Empty, unfocused input types short gray examples at 90 milliseconds per character with a 14-second readable dwell, then erases and rotates. Typing or focus pauses it; Windows reduced motion shows one static example. The decorative example is hidden from assistive technology while the field keeps its stable accessible name and example description. It does not announce each character. A subtle CSS border light is decorative, not progress. A selected case replaces intake with the actual problem, state and evidence. New investigation returns to intake after a terminal case; stopped cases can also continue. Terminal cases have no active spinner. One active case blocks new submissions. Lost responses never automatically replay a mutation. Missing, denied, stale, failed, truncated and unsupported data stay visible. No repair controls, fabricated percentages or browser-access claims are enabled.

## Local security and lifecycle

The renderer is sandboxed, with Node integration off, context isolation on, a restrictive CSP, no network permission and no general IPC/URL/filesystem/command method. The main process checks both web contents and the exact top-level frame URL for every IPC invocation. It accepts only fixed API methods and validates case/process handles and intake bounds again.

The owned investigator binds an OS-assigned loopback port. Native code obtains the existing HTTP-only session cookie and CSRF token from its root page and sends the original same-origin headers for mutations. No CORS bypass or server security changes are introduced. Tokens never enter the renderer. Navigations, popups and browser permissions are blocked.

Dyad retains the shipped `org.systemsense.desktop` app ID and `systemsense-desktop` package/storage identity. Before native startup, `electron/identity.cjs` fixes the default user data path to `app.getPath("appData")/systemsense-desktop`, preserving the existing `cases.db` and local browser storage. Explicit `--user-data-dir` test overrides remain respected. This is a display/product branding change, not a database move or backend-module rename. Single-instance locking and the Python database lease still prevent duplicate coordinators. The parent-child stdin pipe signals shutdown, including EOF on parent failure; shutdown waits for actual service close. An unexpected parent exit saves the active case as interrupted. Named Windows Job custody allows a later backend to release a stranded read-only probe slot only after exact owner, worker and Job-tree exit proof; older unnamed claims remain occupied without that proof.

## Branding assets

`assets/dyad.svg` is an original split-D mark. `scripts/build-icon.py` reproducibly renders the committed PNG and seven-resolution ICO using Pillow. `build.win.icon`, the installer/uninstaller icon options, and native `BrowserWindow.icon` all use this ICO. `signExecutable: false` keeps packaging unsigned while the installed Electron Builder still edits executable icon and product metadata. `node scripts/verify-branding.cjs` reads the built executable and installer and compares all embedded icon payloads against the original asset. It also records the product metadata and hashes under `artifacts/`.

## Verification boundaries

`tests/desktop.spec.ts` uses the real bundled investigator with a new private temporary database and ephemeral port per run. Tests cover intake/inline limitations, direct start, cancellation, history reopen, real observations while minimized, and explicit quit/recovery. The integrated `fe9e16d` build passed these real-backend tests and the separate fixture harness; neither exercises a diagnosed fault or establishes diagnostic accuracy. At `6299d95`, a private installed-app run independently checked a test-owned process before stop, after stop, and after restoration; the app cited all three sampled-state findings and left the causal question unresolved. The process and app exited and the private installation was removed. The full desktop E2E run at this revision had 18 passes, three opt-in skips, and one repeated 150% landing-page overflow failure before the Settings check. See the [acceptance record](../docs/BENCHMARKS_AND_ACCEPTANCE.md) for the current installer hash and open gates.

At `86f213d`, the packaged app was force-stopped during a private case and reopened with two saved evidence rows and an interrupted result. Its named-Job worker claim was independently reconciled, and a fresh CPU case completed. The final private installer passed Basic healthy/HTTP 503, direct process-state, CPU, and blocked-model-readiness checks, then uninstalled without changing the prior user database hash. See the [acceptance record](../docs/BENCHMARKS_AND_ACCEPTANCE.md#private-alpha-acceptance-snapshot-2026-09-29) for measured misses and the installer hash. The current full desktop E2E set still has the 150% landing overflow failure; no UI change was made under this task's constraint.

`tests/states.spec.ts` uses a separate test-only Electron harness. Every screenshot has a **DEVELOPMENT FIXTURE** banner; simulated cases are never written to a real case database. Fixtures exercise empty, denied, supported-observation, uncertain, failed, waiting-target and disconnected screens. `tests/visual.spec.ts` checks the separate landing/case layouts, direct keyboard submission, start/stop/resume/history and normal/150% native captures without launching the backend. `tests/ux.spec.ts` additionally verifies IME/newline handling, last-moment capability revocation, model mode selection and readiness, Windows reduced motion, character-by-character examples with readable dwell and focus/typing pauses, truthful duration/outcomes, and one-time activity arrivals. It captures normal/150% views and reduced-motion preferences without a backend. Tests and fixture harnesses are excluded from the package.

With `DYAD_MODEL_E2E=1`, `tests/model-desktop.spec.ts` starts the actual desktop and pinned Laya–subscription Sol route against an owned high-port health fixture. It checks an independently healthy task and then HTTP 503, the saved in-product GET outcome, nondegraded provider calls, displayed result and History reopen, and independent restoration. `DYAD_PACKAGED_E2E=1` repeats that path in `release/win-unpacked`. The installed-executable test is separate and uses a private user-data directory. These checks establish the local package path and bounded task slice, not clean-machine or broader diagnostic qualification.

Screenshots and traces are local ignored artifacts under `artifacts/` and `test-results/`. They may contain local computer evidence; do not publish them without review. The final handoff records exact tested revisions and package hashes. Installation on a clean Windows machine, signing and broad device qualification remain separate release gates.

`tests/branding.spec.ts` verifies native default history-path preservation in an isolated fixture. With `DYAD_TEST_PACKAGE=1`, its separate packaged branding check launches the built app against a temporary user-data directory, checks its actual name/title and production path calculation, reads the native window icon directly from Windows, and confirms zero cases without requesting collection. The full live investigation suite remains a separate admitted gate.
