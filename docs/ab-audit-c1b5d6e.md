# Bounded ChatGPT debugger audit at `c1b5d6e`

## Verdict

Weak. The treatment repaired the injected fault, passed the hidden health oracle,
and caused no collateral change or benchmark leakage. It still exceeded the frozen
12-call limit by one call, so the run is invalid and cannot support a savings claim.
A baseline was not run after this failed gate.

## Audited setup

- Requested model: `gpt-5.6-sol` through the ChatGPT-authenticated Codex CLI
- Product commit: `c1b5d6e05858415297c3064f60519d029153ca36`
- Wheel SHA-256: `6fae446a3085bb6d7ffb2e7e55c03c1013b4d068fd49c52f3838cd6c445e1dac`
- Prompt SHA-256: `336232cf84307524a3bfd2c94e8dd0c0728ba6eaedf886eaeaa2c0bc63b989ae`
- Frozen config SHA-256: `2642c8a3205b1558c653c239ed26401248627567696927a3d4c530b2a93bf618`
- Baseline snapshot: `AB-Runtime-c1b5d6e-Prepared`, UUID
  `c30f769f-3fe5-48f2-8e00-0338c0be77f7`
- Treatment snapshot: `AB-Runtime-c1b5d6e-Prepared`, UUID
  `8ad903a7-5eaf-4668-a78f-59a5572af46c`
- Artifact root:
  `D:\SystemSense-AB\artifacts\codex-cli-c1b5d6e-bounded-workspace`

Both guest wheel hashes matched the host. A live guest smoke check proved that a
bounded listener observation included its process name and command line. The two
faulted arm fingerprints and the baseline restore proof matched across all ten
categories with comparison hash
`21888f5ea71560652c07965c72c1688a863c391756d416c9eb3cbf81797a23e1`.

Qualification passed all gates: 3 of 3 fault reproductions, reference repair,
hidden oracle, expected SystemSense signal and coverage, SQLite health, case audit,
usage recorder calibration, and discovery of exactly six MCP tools. The resulting
canary readiness digest was
`075d1e1ff3542c12166f553804e1370915a7281879187e280b19045b00801761`.

Local verification before VM execution passed 288 tests with 12 intentional
live-Windows skips. Ruff lint, Ruff formatting, strict Pyright, and package build
also passed.

## Treatment canary

| Measure | Result |
| --- | ---: |
| Hidden repair oracle | Pass |
| Collateral change | None |
| Benchmark leakage | None |
| Tool calls | 13, limit 12 |
| Total tokens | 291,668 |
| Input tokens | 288,643 |
| Cached input tokens | 244,992 |
| Output tokens | 3,025 |
| Reasoning tokens | 784 |
| Agent execution | 154,532 ms |
| End-to-end trace | 168,098 ms |

The trace SHA-256 is
`4fc525d860f2d63a695a9973d1611691706c126f21ac28cd8e83ee37d7b66302`.
The machine-readable outcome SHA-256 is
`66cb5b598353dc559bdc52a908f6c01aa6a43cb99688e69e296b6ff7ef5b65b8`.

The first case brief contained the actionable listener facts directly:
`127.0.0.1:8000`, PID `4596`, `python.exe`, the `python -m http.server`
command, and parent PID `792`. The model still fetched the full evidence record and
queried the same process through CIM. It also attempted unavailable `rg`, recovered
from one rejected compound shell command, opened an unnecessary second SystemSense
case after repair, and repeated a health verification that had already passed.

## Directional comparison with the prior invalid canary

This comparison is diagnostic only. Both treatment canaries violated the same
12-call cap, they are unpaired stochastic runs, and neither has a baseline mate.

| Measure | Prior `d166d28` | Current `c1b5d6e` | Change |
| --- | ---: | ---: | ---: |
| Tool calls | 14 | 13 | 7.143% fewer |
| Total tokens | 293,674 | 291,668 | 0.683% fewer |
| Input tokens | 291,049 | 288,643 | 0.827% fewer |
| Output tokens | 2,625 | 3,025 | 15.238% more |
| Agent execution | 147,249 ms | 154,532 ms | 4.946% slower |
| End-to-end trace | 160,706 ms | 168,098 ms | 4.600% slower |

The listener-owner change coincided with one fewer evidence-detail call, but this
single run cannot establish causality. It moved the call count toward validity while
leaving the run invalid and did not improve elapsed time.

## Decision

Do not publish a live savings percentage from this run. Before another paid trial,
remove duplicate MCP result representation where the protocol permits it, ensure
the shared VM shell has the commands the agent predictably selects, and reduce
redundant evidence and verification calls without weakening the hidden oracle. Run
one treatment canary first. Run baseline only if treatment satisfies every frozen
quality and resource gate.

After artifact export, both VMs were powered off and restored to their clean
`AB-Runtime-c1b5d6e-Prepared` snapshots. The temporary subscription credential,
fault, database, and agent workspace changes are therefore absent.
