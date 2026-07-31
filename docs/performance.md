# Performance and offline boundaries

SystemSense has deterministic resource and no-network gates. Run them with:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\performance\test_idle_budget.py tests\security\test_no_network.py
.\.venv\Scripts\python.exe -m benchmarks.resources
```

## Current measured baseline

Measured on 2026-07-30 with Windows 11 build 26200, AMD64, and Python 3.12.13:

| Measurement | Result |
|---|---:|
| Idle window | 500.25 ms |
| Average idle CPU | 0.00% |
| Idle peak RSS | 68,919,296 bytes (65.73 MiB) |
| Case open plus initial brief | 19.29 ms |
| Case peak RSS | 70,164,480 bytes (66.91 MiB) |
| Process reads | 105,107 bytes |
| Process writes | 259,516 bytes |
| Database growth | 98,304 bytes |

The case operation creates the SQLite store, opens a deterministic case, plans its
registered probes, and generates the initial bounded brief. It does not pretend to
measure every optional Windows collector or an external AI model.

The automated idle gate allows at most 10% average process CPU and 128 MiB peak RSS.
The wide margin absorbs CI and instrumentation overhead while still catching a
material regression from the measured baseline.

## Network boundary

The security test blocks Python `socket.socket`, `socket.create_connection`, and
`urllib.request.urlopen`, then exercises local collectors, capability detection,
benchmark loading, case creation, and brief generation. Any application-level socket
attempt fails the test.

This monkeypatch cannot prove the internals of Windows COM/WMI, pywin32, psutil, or
kernel APIs. Those adapters can inspect local network configuration and endpoint
tables through operating-system APIs. SystemSense contains no DNS lookup, packet
capture, HTTP client, remote endpoint, or active connectivity probe.
