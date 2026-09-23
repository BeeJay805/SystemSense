# Active delivery record

Objective: rapidly find a supported cause for common Windows symptoms, propose
an exact safe software fix when one exists, obtain appropriate human authority,
and independently verify that the affected task recovered. For hardware,
external, unsupported, and unknown cases, explain the evidence and uncertainty.
A fully local edition and an ordinary-laptop fast-brain profile are product
goals. **The objective is not yet met.**

## Decisions and scope

- Deterministic code owns read-only measurements, source/collection timestamps,
  probe admission, graph provenance, permissions, any future write, and recovery
  verification. Laya and Qwen3.8 27B are replaceable local advisory adapters,
  not proven best models. Keyword routing remains a measured baseline/fallback.
- The current browser is read-only. Repair consent and the WinINet runner are
  unmounted; no native host repair may be inferred from a harness action.
- Cloud reasoning is a future separately gated provider, not an implementation
  stage or fallback in this checkpoint.

## Revision and completed work

Branch `codex/windows-investigator`; last published base before this pass was
`b49faa13cd339102c04f3a20eb084391a152a40d`. This pass corrected the
remaining pre-read timestamps in multi-step deep Windows collectors and their
worker envelopes; separated listener-table query time from later owner lookup;
and made temporal listener assessments use those strict query bounds. A
bounded bind-failure association explicitly disclaims exact ownership at the
failure instant. Listener owner findings describe the read interval and reject
process identities created afterward.

The controlled lab harness now records randomized, replayable arm order and
marks over-budget returns `ARM_TIMEOUT`. VM admission rejects fabricated
timeout recovery credit, and the reviewed scorecard cannot relabel VM timeouts
as generic failures. These are benchmark accounting contracts, not real
diagnostic performance. The current architecture and ordered next gates are
documented in [status](STATUS.md), [architecture](architecture/local-two-brain.md),
[benchmark protocol](BENCHMARK_PROTOCOL.md), and [next steps](NEXT_STEPS.md).

## Verification and limits

The final non-MCP suite passed 1,209 tests with 15 gated skips and one MCP
deselection. The opt-in owned-port tests passed 14/14 after the temporal
assessment change. Strict Pyright, Ruff lint/format, the offline source/wheel
build, and Git whitespace checks passed. These establish code/integration
behavior, not field accuracy, laptop suitability, or
a consumer repair. No diagnostic-performance or percent-savings claim exists.

A desktop-only warm synthetic 54-preview/17-probe Laya CPU request took roughly
102–105 seconds in prior measurements, far above the proposed three-second
attention-cycle target. The Qwen3.8 27B Q4 local profile used about 17.3 GB of
RTX 4090 memory at 8K context. There are no authenticated expert field labels
or held-out Windows action-quality results. Do not fine-tune or promote a model
from synthetic timing alone.

The disposable VM clone `SystemSense-Investigator-Qualification-20260922`
(`82bab24b-e3b2-4b17-9d55-8c9198c53766`) is powered off, NIC disconnected,
and lacks a snapshot, verified guest login, and independent oracle. Read-only
preflight returned `can_begin_episode=false` on 2026-09-23. No qualified VM
episode or real repair trial has run; guest credentials should not be sent in
chat.

## Remaining gates

1. Authenticate and reset the isolated VM; independently inject proxy/PDF
   faults, external/healthy controls, and affected-task before/after oracles.
2. Run equal-budget held-out deterministic, deep-only, and dual-brain arms with
   blinded adjudication, false-fix controls, complete overhead, and p50/p95
   time-to-answer/recovery reporting.
3. Prove one exact WinINet repair through owned-route evidence, same-user
   interactive consent, policy checks, one-shot execution, independent retry,
   collateral checks, and crash/terminal reconciliation before exposing a writer.
4. Measure local fast-brain candidates on ordinary Windows laptops. Require
   useful-probe quality and resource/latency floors; train only on admitted
   reviewed labels with grouped held-out tests.
5. Expand Wi-Fi and gaming with separate physical rigs and workload oracles.
