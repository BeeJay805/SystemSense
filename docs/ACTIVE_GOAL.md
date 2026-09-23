# Active delivery record

Objective: a Windows investigator that rapidly finds a supported cause, proposes
an exact safe fix, obtains appropriate permission, and independently measures
recovery. It must handle common software faults while honestly identifying
hardware, external, unsupported, and unknown cases. A fully local edition and
an ordinary-laptop fast-brain profile remain product goals. **This objective is
not yet met.**

## Scope and decisions

- The deterministic layer owns read-only measurements, source times, graph
  provenance, probe admission, permissions, writes, and independent verification.
  Models advise; no model may invent a measurement or execute a command.
- Laya and Qwen3.8 27B are replaceable local adapters, not a fixed or qualified
  best pair. Keyword planning is the baseline/fallback. A typed-feature CPU
  challenger is opt-in and must beat the baseline on reviewed outcomes before
  promotion. Cloud inference is outside the current implementation stage.
- Repairs require exact authenticated human approval. The existing WinINet
  foundation is unmounted, fake-tested, and must remain unable to write the host
  until its endpoint, policy, crash, consent, and VM gates pass.

## Baseline checkpoint

Branch `codex/windows-investigator`, published commit `aec3aad` (2026-09-23).
The application has 17 bounded Windows probes, parallel collection, persisted
source-timed evidence, separate observed/reference graph layers, an active
two-brain read-only loop, local case UI, and optional MCP adapter. The current
controlled owned-port episode persists target-side Winsock 10048 failure plus
full listener snapshots before and after it. A deterministic assessor can cite
those three records for one narrow `owned_tcp_bind_conflict` explanation. The
harness, not the product, stops only its disposable blocker and verifies a new
target bind and HTTP response. This is not independent VM injection, a consumer
repair, or general diagnostic accuracy.

The unmounted WinINet path has immutable proposal/review and one-shot execution
claims bound to a canonical current-user SID target. The runner must commit its
exact prewrite recheck before its native writer. Targets remain locked even
after a result; [terminal reconciliation](REPAIR_RECONCILIATION.md) is a design,
not an implemented unlock. No host native write or browser approval route ran.
Held-out attention label v2 hashes provider-visible inputs and candidate
catalogs, but has no authenticated expert field labels or product-quality score.

Published checkpoint verification: 1,097 non-MCP tests passed with 15
environment-gated skips; 14 opt-in owned-port tests passed. Strict Pyright,
Ruff lint/format, offline source/wheel build, and Git whitespace checks passed.
These are software and narrow integration gates, not field outcomes.

## Follow-on slice and blockers

This slice adds an opt-in CPU-only typed-feature decision challenger, a
frozen-request decision-component profiler, and terminal reconciliation design.
The integrated non-MCP suite passed 1,122 tests with 15 environment-gated
skips and one MCP deselection; Pyright, Ruff lint/format and offline
source/wheel build passed. A separate 54-preview/17-probe synthetic desktop
profile returned 20/20 valid warm decisions for both keyword and typed
providers, but did not measure investigative quality or laptop suitability.
A synthetic
54-preview/17-probe desktop Laya CPU sweep took roughly 102-105 seconds warm,
far above the proposed three-second p95 attention target. It did not measure
diagnostic quality or a laptop.

The disposable VM clone `SystemSense-Investigator-Qualification-20260922`
(`82bab24b-e3b2-4b17-9d55-8c9198c53766`) is powered off with disconnected
NIC, no snapshot and no verified guest login or independent oracle. The
read-only preflight reports `can_begin_episode=false`. No measured held-out
Windows fault or repair trial has run. Guest access and a restorable reset are
the next external prerequisites; do not send credentials in chat.

## Next acceptance gates

1. Establish authenticated, restorable VM episodes with independently injected
   faults, healthy and external controls, and before/after affected-task
   oracles. Freeze equal probe catalogs, time budgets, and review rubrics.
2. Qualify an owned non-loopback HTTPS affected/direct WinINet oracle, managed
   policy coverage, same-user interactive consent, cross-process writer
   exclusion, and terminal crash reconciliation. Keep the native route disabled
   until the full chain passes.
3. Compare deterministic, deep-only, and two-brain arms on blinded held-out
   episodes. Report unsupported diagnoses, false fixes, coverage, end-to-end
   p50/p95 time-to-answer/recovery, recurrence and observer overhead, not just
   successful examples.
4. Test the CPU challenger, optimized Laya and any trained compact ranker on
   identical reviewed requests and ordinary 8/16 GB laptops. Reject options
   that are fast but lose useful-probe recall or increase unsupported answers.
5. Expand complete journeys for Wi-Fi, slow PDF, and low-FPS gaming only with
   reproducible affected-workload measurements and safe, specific repair gates.

See [product roadmap](PRODUCT_ROADMAP.md), [architecture](architecture/local-two-brain.md),
[benchmark protocol](BENCHMARK_PROTOCOL.md), and [build evidence](APPLICATION_BUILD.md)
for detailed design, measured checks, and limitations.
