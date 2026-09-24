# SystemSense

SystemSense is a local-first Windows investigator. It collects bounded read-only evidence, preserves provenance and coverage gaps, and uses replaceable advisory models to decide what to inspect and explain. Deterministic code retains machine authority. The product goal is a fast path from a symptom to a supported cause and, only with separate approval, a verified software repair.

The present application is **not** a qualified autonomous fixer or a fully concurrent two-brain investigator. The default install is deterministic. Read [Current state](docs/CURRENT_STATE.md) before relying on a capability claim.

## Authoritative documents

1. [North star](docs/NORTH_STAR.md): short product purpose and non-negotiable boundaries.
2. [Architecture](docs/ARCHITECTURE.md): component authority and intended active loop, with target behavior labeled.
3. [Current state](docs/CURRENT_STATE.md): what committed HEAD implements and does not prove.
4. [Training plan](docs/TRAINING_PLAN.md): exact-runtime pilot and later fine-tuning gates.
5. [Benchmarks and acceptance](docs/BENCHMARKS_AND_ACCEPTANCE.md): measurable integration and product gates.

Older plans, audits, episode notes, qualification reports, and technical design records are preserved in `docs/archive/` for historical investigation. They are not current guidance and need not be read for ordinary development.

## Local use

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).

```powershell
uv sync --frozen
.\.venv\Scripts\systemsense.exe doctor
.\.venv\Scripts\systemsense.exe investigate "why did this application stop?"
.\.venv\Scripts\systemsense.exe serve --port 18765
```

Evidence defaults to `%LOCALAPPDATA%\SystemSense\systemsense.db`. Set `SYSTEMSENSE_DATA_DIR` to an absolute directory for an isolated store. `investigate` runs a bounded read-only case; `serve` opens a loopback interface at `http://127.0.0.1:18765`. Optional local models require `uv sync --frozen --extra local-models` and explicit admission; no model download, cloud inference, or paid fallback is automatic. MCP remains an optional transport adapter.

Development checks and interpretation rules are in [Benchmarks and acceptance](docs/BENCHMARKS_AND_ACCEPTANCE.md). The [security policy](SECURITY.md) describes disclosure and reporting. Licensed under [MIT](LICENSE).
