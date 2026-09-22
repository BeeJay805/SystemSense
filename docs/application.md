# Local application

SystemSense ships an active local, read-only investigation application. It keeps one
active investigation per workspace, persists each round to SQLite, and exposes the
same bounded case service through the CLI and a loopback browser interface.

## Run one investigation

```powershell
.\.venv\Scripts\systemsense.exe investigate "why did this application stop?" --budget-ms 30000 --max-rounds 4
```

The command waits for the bounded coordinator, then prints the cited case report as
JSON. Ctrl+C requests cancellation and preserves the durable checkpoint. A later
resume does not silently replay probes already recorded as attempted.

## Open the browser interface

```powershell
.\.venv\Scripts\systemsense.exe serve --port 18765
```

Open `http://127.0.0.1:18765`. The server binds only to loopback, limits request
bodies and sessions, checks Origin and CSRF tokens for mutations, and permits one
active case worker. The UI supports case start, inspection, cancellation, resume,
and bounded redacted export. It does not expose a command, filesystem, SQL,
registry-path, or arbitrary URL tool.

## Record bounded passive context

```powershell
.\.venv\Scripts\systemsense.exe record --cycles 1 --interval-seconds 30
```

The CLI defaults to one foreground cycle at a 30-second interval and never installs
a background service. Browser recording is also explicit opt-in, bounded to at most
120 cycles at 30 seconds, and cancelled during application shutdown. Passive Event
Log collection runs in a fixed isolated worker with a five-second hard deadline.
Its first query reads a bounded newest tail, then presents those records in ascending
order; older history outside that tail is explicitly excluded rather than implied
absent.

## Optional local inference

The dual-brain runtime can be persisted as an explicit versioned profile. The
default location is `%LOCALAPPDATA%\SystemSense\inference-profile.json`; if it is
absent, SystemSense remains deterministic and does not create the file. An
explicit profile path works for both entry points:

```powershell
uv sync --frozen --extra local-models
.\scripts\install-laya-runtime.ps1 -PythonPath C:\path\to\python.exe -Device cuda
```

The first command installs the locked tokenizer used for bounded reasoner context.
The second is the separate, explicit networked setup for Laya; normal application
startup never installs or downloads a model.

```powershell
.\.venv\Scripts\systemsense.exe investigate "why did this application stop?" --profile C:\path\to\inference-profile.json
.\.venv\Scripts\systemsense.exe serve --profile C:\path\to\inference-profile.json
```

Example schema (paths and digest must identify locally admitted artifacts):

```json
{
  "schema_version": 1,
  "profile_id": "local-dual-brain",
  "investigation_budget_ms": 180000,
  "inference": {
    "enabled": true,
    "endpoint": "http://127.0.0.1:11435/api/chat",
    "reasoning_model": "qwen3.8:27b",
    "reasoning_digest": "<64 lowercase hex characters>",
    "allow_gpu": true,
    "keep_alive_seconds": 300,
    "timeout_seconds": 90,
    "context_tokens": 8192,
    "output_tokens": 1200,
    "cpu_threads": 4,
    "thinking": false,
    "tokenizer_path": "C:\\Users\\me\\AppData\\Local\\SystemSense\\runtimes\\qwen38-tokenizer\\tokenizer.json",
    "tokenizer_sha256": "0997f410c57a1f4e53b09e4be8f4a172d90edd9564368fb0847030937229b9f3"
  },
  "laya": {
    "enabled": true,
    "interpreter_path": "C:\\Users\\me\\AppData\\Local\\SystemSense\\runtimes\\laya-0.3.5\\venv\\Scripts\\python.exe",
    "model_path": "C:\\Users\\me\\AppData\\Local\\SystemSense\\runtimes\\laya-0.3.5\\model",
    "device": "cuda",
    "precision": "float16",
    "cuda_device_index": 0,
    "min_free_vram_mb": 2048,
    "threads": 2,
    "max_candidates_per_batch": 4,
    "timeout_seconds": 60
  }
}
```

Profile loading is read-only. It validates the loopback endpoint, pinned reasoning
digest, and Laya's admitted install manifest, but never installs a runtime, starts
Ollama, downloads a model, or selects a cloud alias. The Laya subprocess is lazy:
one owned offline worker is shared by all investigators in a CLI invocation and is
closed after the application service stops. CUDA is used only when the profile
explicitly requests it and the configured free-VRAM admission floor passes; CPU is
the explicit fallback placement. `precision` defaults to `float32`; the measured
CUDA-only `float16` mode lowers resident and peak VRAM at the documented small
ordinal-ranking drift. One reasoning provider and one curated reference
graph are shared on the same lifecycle. The profile budget is used only when
`investigate` has no explicit `--budget-ms` override.

Laya ranks every admitted evidence fragment in bounded batches, reports partial
coverage and state omissions, and uses actual-tokenizer fitting so the complete
bounded goal, preferred probe frontier, best fact, one graph mechanism, and one
prior hypothesis remain visible. Its scores are ordinal attention signals, not
diagnostic probabilities. The measured host envelope and remaining accuracy gate
are documented in [Laya local runtime qualification](LAYA_QUALIFICATION.md).

The older one-command Ollama flags remain available for compatibility:

Inference is disabled unless explicitly requested with model names:

```powershell
.\.venv\Scripts\systemsense.exe serve --enable-inference --decision-model <installed-local-model> --reasoning-model <installed-local-model>
```

The adapter uses CPU by default. `--allow-gpu` is a separate explicit choice. It
does not start Ollama, pull or download a model, or fall back to a cloud/paid model.
Before each chat, it queries the fixed loopback `/api/tags` and `/api/show` routes.
The configured name must match exactly one positive-size local artifact with a
digest and format, and neither response may identify a `remote_model` or
`remote_host`. Missing or ambiguous locality metadata degrades to the deterministic
providers before chat. Requests use fixed loopback routes, no ambient proxy, no
redirects, bounded JSON-schema bodies, bounded responses, bounded keep-alive, and
one monotonic deadline across locality checks and chat. A slow-trickle response
cannot extend that total deadline.

Cancelling a case stops further probe admission and cancels owned Laya work.
The Ollama transport checks cancellation between bounded reads and stops accepting
the response; remote-runtime compute may take longer to notice the closed request.
CPU-only is a request to the trusted local Ollama runtime, not proof
of workload isolation. A model/runtime configuration must be qualified before
sharing a host with critical work.

Decision and reasoning models receive compact evidence that was already redacted,
plus evidence-grounded relationships and the registered read-only probe catalog.
They return advisory proposal bodies only. Trusted code supplies case identity,
deadlines, permissions, costs, resource classes, and response envelopes.

## Interpretation limits

The coordinator reports observations, coverage gaps, and unresolved hypotheses.
A graph edge, temporal correlation, resource snapshot, or model proposal is not
confirmed causality. The current deterministic rules are deliberately small, and
no local model or overall product configuration has production diagnostic
qualification. Repairs and experiments remain outside this read-only application.
