# Dyad

Dyad is a local-first Windows investigator. It collects bounded read-only evidence, preserves provenance and coverage gaps, and uses replaceable advisory models to decide what to inspect and explain. Deterministic code retains machine authority. The product goal is a fast path from a symptom to a supported cause and, only with separate approval, a verified software repair. The repository, Python package, CLI and existing data paths retain their `systemsense` names for compatibility.

The present application is **not** a qualified autonomous fixer. The default install is deterministic; concurrent local-model operation is opt-in and development-only. Read [Current state](docs/CURRENT_STATE.md) before relying on a capability claim.

## Authoritative documents

1. [North star](docs/NORTH_STAR.md): short product purpose and non-negotiable boundaries.
2. [Architecture](docs/ARCHITECTURE.md): component authority and intended active loop, with target behavior labeled.
3. [Current state](docs/CURRENT_STATE.md): what committed HEAD implements and does not prove.
4. [Training plan](docs/TRAINING_PLAN.md): exact-runtime pilot and later fine-tuning gates.
5. [Benchmarks and acceptance](docs/BENCHMARKS_AND_ACCEPTANCE.md): measurable integration and product gates.

[Build history](docs/BUILD_HISTORY.md) records dated engineering evidence and
retrospectives; the five documents above remain the current product guidance.

Older plans, audits, episode notes, qualification reports, and technical design records are preserved in `docs/archive/` for historical investigation. They are not current guidance and need not be read for ordinary development.

## Local use

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```powershell
uv sync --frozen
.\.venv\Scripts\systemsense.exe doctor
.\.venv\Scripts\systemsense.exe investigate "why did this application stop?"
.\.venv\Scripts\systemsense.exe investigate "A browser page fails to open" --task-kind browser_navigation --task-action "open the page" --task-reported-outcome "failed to load"
.\.venv\Scripts\systemsense.exe serve --port 18765
```

Evidence defaults to `%LOCALAPPDATA%\SystemSense\systemsense.db`. Set `SYSTEMSENSE_DATA_DIR` to an absolute directory for an isolated store. `investigate` runs a bounded read-only case; `serve` opens a loopback interface at `http://127.0.0.1:18765`. Optional local models require `uv sync --frozen --extra local-models` and explicit admission; no model download, cloud inference, or paid fallback is automatic. MCP remains an optional transport adapter.

A separately enabled development trial can run actual Laya with GPT-6 Sol through the logged-in Codex subscription on synthetic observations. It requires an explicit installed Codex executable and fresh artifact directory; it does not reconfigure the desktop. See [subscription trial and limits](docs/BENCHMARKS_AND_ACCEPTANCE.md#subscription-investigator-trial) for the command and acceptance boundaries.

The optional task flags record a user report, not a verified browser result or target binding; terminal reports state when no independent affected-task result is bound. `investigate --no-scout-prefetch` disables the bounded one-step prefetch for a controlled comparison; it does not change probe permissions.
An unsigned Dyad desktop development candidate is described in [Desktop use and build](desktop/README.md). It bundles the default read-only deterministic investigator, retains existing local cases, and shows saved History, a minimal Settings shell, and reported activity. It is not a qualified diagnostic release.
The investigator can follow registered probes named by typed hypotheses through the normal read-only admission gate. Its deep reasoning view labels required evidence that was omitted, unavailable, or quality limited; these labels do not prove a cause. Later deep responses retain custodied competing hypotheses and timed predictions while reporting citation or capacity loss. See [Current state](docs/CURRENT_STATE.md) for exercised behavior and remaining pilot gaps.
For version-6 local reasoning, a categorical prediction must name a finite value that the exact registered probe version can emit; later contradictory evidence must come from that same collector version. The bounded prompt may omit an optional prediction menu, in which case no prediction from it is accepted.
In synthetic qualification fixtures, the deep view can also receive an exact bound task observation and receipt-backed selected frontier source; their target/window match is advisory context, not causal proof.
Bounded retrieval keeps explicit requests and a selected source while prioritizing live rivals' cited evidence for later deep turns. The [frozen synthetic before/after scorecard](docs/BENCHMARKS_AND_ACCEPTANCE.md#overnight-measured-result-2026-09-28) records actual model-selected measurements, accepted follow-up review, remaining rival gaps and the limits on diagnostic claims. [Reversible local Windows checks](docs/BENCHMARKS_AND_ACCEPTANCE.md#reversible-local-windows-checks-2026-09-28) measure current probe routing and process coverage.
Exact detail requests are bounded and any pending-queue overflow is reported; a requested lookup is not itself a verified observation.

Development checks and interpretation rules are in [Benchmarks and acceptance](docs/BENCHMARKS_AND_ACCEPTANCE.md). The [security policy](SECURITY.md) describes disclosure and reporting. Licensed under [MIT](LICENSE).
