# SystemSense

[![Windows CI](https://github.com/BeeJay805/SystemSense/actions/workflows/ci.yml/badge.svg)](https://github.com/BeeJay805/SystemSense/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

SystemSense is a local, read-only Windows diagnostic evidence system for AI agents.
It gives Claude and other MCP clients a compact, cited case workspace instead of
making the model repeatedly hunt through commands, logs, drivers, processes, and
settings.

SystemSense collects and organizes evidence. The AI diagnoses. It does not run
arbitrary commands, accept arbitrary paths or queries, change Windows state, make
outbound network requests, or emit a diagnosis.

Status: pre-release MVP, ready for controlled local Windows testing.

## What it collects

- Windows identity, CPU, memory, and disk state
- Bounded process and registered service snapshots
- Device problem codes and signed driver metadata
- Local adapters and bounded endpoint metadata
- Installed Windows updates and reboot-pending state
- GPU, Python, package, and CUDA-related metadata
- Incremental Windows Event Log evidence with persistent bookmarks
- Timestamped current inventory plus change-only history

Every result carries provenance, observation and capture timestamps, collector
identity, limitations, and a stable source identity. Missing, denied, stale,
truncated, failed, and unsupported sources remain visible as coverage states.

## Install on Windows

SystemSense requires Python 3.12 or newer and
[uv](https://docs.astral.sh/uv/getting-started/installation/).

```powershell
git clone https://github.com/BeeJay805/SystemSense.git
cd SystemSense
uv sync --frozen --no-dev
.\.venv\Scripts\systemsense.exe doctor
```

By default, evidence is stored at
`%LOCALAPPDATA%\SystemSense\systemsense.db`. Set `SYSTEMSENSE_DATA_DIR` to an
absolute directory to use a separate test database.

## Connect Claude Desktop

Open Claude Desktop, go to **Settings > Developer > Edit Config**, and add an
absolute executable and data path. This follows the official
[local MCP server guide](https://modelcontextprotocol.io/docs/develop/connect-local-servers):

```json
{
  "mcpServers": {
    "systemsense": {
      "command": "C:\\absolute\\path\\to\\SystemSense\\.venv\\Scripts\\systemsense-mcp.exe",
      "env": {
        "SYSTEMSENSE_DATA_DIR": "C:\\Users\\you\\AppData\\Local\\SystemSense"
      }
    }
  }
}
```

Fully quit and restart Claude Desktop. The server exposes exactly six bounded
tools:

| Tool | Purpose |
|---|---|
| `open_case` | Plan and collect a bounded evidence case |
| `get_case_brief` | Return the compact, cited, diagnosis-free brief |
| `query_case_evidence` | Page through filtered evidence summaries |
| `get_evidence` | Read one case-owned evidence record |
| `inspect_more` | Page through additional normalized facts |
| `get_coverage_map` | Inspect denied, missing, stale, failed, or truncated sources |

The MCP server uses local standard input/output only. It has no HTTP listener.
Use absolute paths because MCP clients may start local servers from an undefined
working directory.

Example request to Claude:

> Open a SystemSense network case for intermittent DNS failures. Read the brief,
> inspect cited evidence only where needed, and diagnose the most likely cause.

## Local CLI

```powershell
# Create and collect a case
.\.venv\Scripts\systemsense.exe case create `
  --kind network `
  --symptom "DNS fails after resume" `
  --trait network

# Render a case brief
.\.venv\Scripts\systemsense.exe case show CASE_ID

# Inspect timestamped static inventory
.\.venv\Scripts\systemsense.exe inventory show --category devices

# Poll fixed Event Log channels for an existing case
.\.venv\Scripts\systemsense.exe sentinel run `
  --case-id CASE_ID `
  --channel Application `
  --channel System `
  --polls 3

# Run the deterministic engineering benchmark
.\.venv\Scripts\systemsense.exe benchmark
```

Commands emit machine-readable JSON except the Markdown benchmark report.

## Test the MVP

Install the development gates from the checked-in lockfile:

```powershell
uv sync --frozen
```

Run the release checks:

```powershell
$env:SYSTEMSENSE_LIVE_WINDOWS = "1"
.\.venv\Scripts\ruff.exe format --check .
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\pyright.exe
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m benchmarks.runner
.\.venv\Scripts\python.exe -m benchmarks.resources
.\.venv\Scripts\python.exe -m build
```

See [Testing](docs/testing.md) for the manual Claude and six-family test matrix.

## Measured savings

The checked-in six-case engineering fixtures currently show:

- 72.36% median context-character savings
- 68.09% median fixture token-field savings
- 75.54% median elapsed-time savings
- 66.67% median tool-call savings
- equal fixture quality in 6 of 6 cases

These figures validate the benchmark math and quality gate. They are not measured
Claude savings. A paired, recorded Claude A/B run is the next external validation
step. The protocol is in [Benchmarking](docs/benchmarking.md).

## Design and safety

- [Architecture](docs/architecture/overview.md)
- [Evidence packs](docs/packs.md)
- [Threat model](docs/threat-model.md)
- [Performance and offline boundary](docs/performance.md)
- [Acceptance matrix](docs/acceptance.md)
- [Security policy](SECURITY.md)
- [Project status](docs/STATUS.md)

SystemSense is licensed under the [MIT License](LICENSE).
