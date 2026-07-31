# Testing guide

Use a non-production Windows account or VM and a fresh data directory for the first
MVP test.

For the controlled ChatGPT repair experiment, use the separate
[A/B testing protocol](ab-testing.md). It adds VM parity, hidden-oracle, paid-call,
and paired-analysis gates that are not part of ordinary MCP smoke testing.

## Automated release gate

```powershell
$env:SYSTEMSENSE_DATA_DIR = "$env:TEMP\SystemSense-test"
$env:SYSTEMSENSE_LIVE_WINDOWS = "1"
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m benchmarks.runner
.\.venv\Scripts\python.exe -m benchmarks.resources
.\.venv\Scripts\python.exe -m build
```

Expected result: every command exits zero, the six fixture cases remain
quality-valid, and both wheel and source archive appear in `dist`.

## CLI smoke test

```powershell
.\.venv\Scripts\systemsense.exe doctor
.\.venv\Scripts\systemsense.exe case create `
  --kind general `
  --symptom "MVP smoke test"
.\.venv\Scripts\systemsense.exe inventory show
```

Verify:

- `doctor` reports SQLite integrity `ok`;
- the case status is `ready`;
- the common plan contains `core.system` and `core.resources`;
- inventory contains two distinct core records;
- all output is JSON and contains no secret supplied only through an environment
  variable.

## Six-family MCP test matrix

Run each prompt in a fresh Claude conversation after connecting SystemSense.

| Kind | Test symptom | Expected selected optional probe |
|---|---|---|
| `application` | Application crashes on startup | `application.snapshot` |
| `devices_audio` | Audio device has a driver error | `devices.snapshot` |
| `network` | DNS and proxy connections fail | `network.snapshot` |
| `servicing` | Windows Update requests a reboot | `servicing.snapshot` |
| `local_ai` | CUDA is unavailable in Python | `local_ai.snapshot` |
| `general` | General system resource pressure | Common probes only unless terms match |

For every case verify:

- Claude first receives a cited brief rather than a raw data dump;
- each citation can be expanded with `get_evidence` or `inspect_more`;
- unavailable sources appear in `get_coverage_map`;
- the brief makes no diagnosis or repair declaration;
- Claude, not SystemSense, states the diagnosis;
- a repeated optional case within its freshness TTL can reuse static inventory.

## Sentinel replay test

Create a case, then run:

```powershell
.\.venv\Scripts\systemsense.exe sentinel run `
  --case-id CASE_ID `
  --channel Application `
  --polls 1 `
  --limit 20
```

Run the same command again. The bookmark should advance or remain stable, and stable
source identity must prevent duplicate evidence.

## Safety checks

- Enter symptom text containing a fake shell command or probe ID. Confirm it remains
  symptom text and creates no new tool or probe.
- Request an arbitrary file, registry path, SQL query, URL, or executable through
  the MCP tools. Confirm no tool schema accepts it.
- Run the no-network security test with networking available. It must still pass
  while sockets are blocked inside the process.
- Inspect Task Manager during the resource benchmark. The process should exit and
  leave no worker process behind.
- Test a denied WMI source under a standard account. The case should become ready
  with explicit coverage rather than fail startup.

## Reporting a test result

Include:

- commit SHA and Windows build;
- Python and Claude model versions;
- case kind and redacted symptom;
- selected probes and coverage states;
- brief character count;
- input tokens, wall time, and tool calls if measuring savings;
- the exact failing command and error;
- only synthetic or redacted evidence.
