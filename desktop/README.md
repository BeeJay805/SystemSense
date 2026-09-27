# SystemSense desktop

A Windows desktop client for the existing read-only investigator. Product contracts remain in [the canonical architecture](../docs/ARCHITECTURE.md) and [current state](../docs/CURRENT_STATE.md). This directory owns only the desktop shell, renderer, packaging wrapper and its tests.

## Run and build

The Windows installer bundles Python and the investigator. End users do not need Python, Node or an account. The build is unsigned and is a development candidate, not a signed public release. No updater, browser extension, cloud inference, repair executor or tray service is included.

Developer prerequisites: Windows x64, Node 22.12+, npm, and `uv` (which supplies Python 3.12). From this directory:

```powershell
npm ci --legacy-peer-deps
./scripts/build-backend.ps1
npm run build
npm start
```

`build-backend.ps1` exports the repository's frozen runtime lock, installs the existing package into a desktop-only virtual environment, and creates a PyInstaller folder at `backend/dist/investigator`. Its entrypoint dispatches only the existing fixed `-m systemsense.worker` invocation used by the isolated executor; it does not accept arbitrary Python modules. Optional inference dependencies are not bundled.

```powershell
npm test
npm run test:e2e
npm run typecheck
npm run lint
npm run format:check
npm run installer
```

The resulting installer is `release/SystemSense Setup 0.1.0.exe`; the directly runnable folder is `release/win-unpacked`. Keep that folder intact. Packaging intentionally disables signing, and makes no certificate or publishing request. The Electron/Chromium bundle increases distribution size compared with Tauri. A local Rust compile failed because the Microsoft linker was unavailable; A approved Electron rather than installing system build tools.

## Controls and their purpose

| Control | Behavior and reason |
| --- | --- |
| Get started / Do this later | Leave a short privacy introduction. Browser connection is explicitly unavailable, with no store link or simulated connection. |
| What’s not working? / Investigate | Accept one problem description, then review available capabilities before collection. The explicit button is keyboard accessible. |
| Start investigation | Start only after the readiness limitations are visible. Registered checks are not a permission guarantee. No target preflight API exists yet; process selection can occur later. |
| Stop investigation | Request cancellation and preserve saved evidence. “Stopping” persists until the engine reports a terminal status. |
| Investigation details | One expansion reveals observations with source IDs and timestamps, coverage, interpretation, and actual activity. Advisory text is separated from supported observations. |
| Saved investigations | Reopen the same durable case without resuming it. A modal dialog traps keyboard focus and supports Escape. |
| Continue investigation | Explicitly resume a cancelled, interrupted or failed case through the existing API. Never resume automatically. |
| Export evidence | Save the existing bounded report using a native Save dialog. The renderer cannot choose arbitrary file paths. |
| Minimize / Quit or window close | Minimize leaves the owned engine running. Quit closes its private stdin pipe and waits for `ApplicationService.close()` to stop and save. Reopen recovers saved cases. |

One active case blocks new submissions. Lost responses never automatically replay a mutation: reconnect reconciles the engine's actual state. Missing, denied, stale, failed, truncated and unsupported data stay visible. A supported observed answer does not claim the root cause is proven. There are no enabled repair controls, fabricated percentages, ETAs, model-confidence meters or implied browser access.

## Local security and lifecycle

The renderer is sandboxed, with Node integration off, context isolation on, a restrictive CSP, no network permission and no general IPC/URL/filesystem/command method. The main process checks both web contents and the exact top-level frame URL for every IPC invocation. It accepts only fixed API methods and validates case/process handles and intake bounds again.

The owned investigator binds an OS-assigned loopback port. Native code obtains the existing HTTP-only session cookie and CSRF token from its root page and sends the original same-origin headers for mutations. No CORS bypass or server security changes are introduced. Tokens never enter the renderer. Navigations, popups and browser permissions are blocked.

Cases use the app's `userData/cases.db`. Single-instance locking prevents duplicate coordinators. The Python service also owns its existing database lease. The parent-child stdin pipe is the lifecycle signal, including EOF on parent failure. Shutdown waits for the actual service; it never reports a successful save after force-killing it. A hung third-party Windows call could delay closing. Startup and connection failures are visible and do not start a replacement engine automatically.

## Verification boundaries

`tests/desktop.spec.ts` uses the real bundled investigator with a new private temporary database and ephemeral port per run. Tests cover intake/readiness, start, cancellation, history reopen, real observations while minimized, and explicit quit/recovery. They do not exercise a diagnosed fault or claim diagnostic accuracy.

`tests/states.spec.ts` uses a separate test-only Electron harness. Every screenshot has a **DEVELOPMENT FIXTURE** banner; simulated cases are never written to a real case database. Fixtures exercise empty, denied, supported-observation, uncertain, failed, waiting-target and disconnected screens. Tests and fixture harnesses are excluded from the package.

Screenshots and traces are local ignored artifacts under `artifacts/` and `test-results/`. They may contain local computer evidence; do not publish them without review. The final handoff records exact tested revisions and package hashes. Installation on a clean Windows machine, signing and broad device qualification remain separate release gates.
