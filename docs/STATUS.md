# SystemSense status

SystemSense is a read-only, local-first Windows investigator under development.
It is not yet an automatic fixer, a general IT replacement, or a qualified
diagnostic product. The product target and ordered acceptance gates are in
[next steps](NEXT_STEPS.md); the live implementation is described in
[the architecture](architecture/local-two-brain.md).

## Current architecture

1. A deterministic coordinator opens an incident, schedules bounded parallel
   read-only probes, stores versioned observations and coverage, and controls
   budgets, cancellation, audit, and case recovery. Its execution graph is not
   the diagnostic evidence graph.
2. Seventeen registered Windows probes cover core resources, applications,
   devices, network, storage, security, events, power, and related samples.
   Source event times remain separate from collection and audit times. Multi-step
   deep collectors now report collection intervals; listener-table query bounds
   are separate from later process-owner lookups.
3. The evidence layer retains redacted facts, provenance, limitations, temporal
   machine relationships, and a separate sourced conditional reference graph.
   Reference links guide inquiry but do not prove a cause on this machine.
4. Replaceable advisory providers run the active loop. Optional Laya ranks
   evidence and registered next probes; optional local Qwen3.8 27B compares
   hypotheses and asks for focused detail. Keyword/deterministic routing is the
   baseline and degraded fallback. No model owns a measurement or permission.
5. A deterministic assessor may return exact narrow observations, such as a
   reported listener owner, and one bounded temporal association between a
   target-side Winsock 10048 failure and matching listener reads around it.
   That association does not prove socket ownership at the failure instant or
   authorize an action. Unresolved is an ordinary terminal outcome.
6. The loopback browser and CLI expose read-only cases. MCP is optional. Repair
   proposals, one-shot authorization storage, and a fake-tested WinINet runner
   remain disconnected groundwork. The application has no enabled host repair.

## Verification and what it means

The current integrated non-MCP suite and opt-in owned-port rehearsal have been
run on this development host; exact counts and commands are in
[the active record](ACTIVE_GOAL.md). The owned-port rehearsal uses a disposable
harness-owned blocker and target. It exercises persisted listener and bind
evidence, then the harness alone removes its blocker and checks a new bind/HTTP
response. It is not a consumer repair, an independent VM oracle, or measured
general diagnostic accuracy.

The lab harness records a random arm-order seed and actual executed order. A
late synchronous arm is marked timed out and receives no recovery credit;
the harness still cannot interrupt a hung callback. VM protocol checks and the
reviewed scorecard are consistency/accounting tools, not authenticators of a
rig, reviewer, injected fault, or recovery. Synthetic fixtures and five local
coordinator journeys do not establish product-performance percentages.

Current local model measurements are device-specific: a warm synthetic
54-preview/17-probe Laya CPU sweep on this desktop took roughly 102–105 seconds;
the pinned Qwen3.8 27B Q4 profile used about 17.3 GB of RTX 4090 memory at an
8K context. Neither is ordinary-laptop qualification or diagnostic accuracy.
There are no admitted expert next-probe labels and no Windows-specific
fine-tuned fast brain.

The disposable Windows VM clone is powered off with disconnected NIC, no
snapshot, and no verified guest login or independent oracle. Its read-only
preflight says `can_begin_episode=false`; no qualified Windows fault or repair
trial has run. No cloud inference or automatic paid fallback is implemented.

## Immediate gates

- Establish authenticated, restorable VM episodes and independent affected-task
  oracles for proxy, slow PDF, external, and healthy controls.
- Compare equal-budget randomized deterministic, deep-only, and two-brain arms
  on held-out cases, including latency, false claims, uncertainty, overhead, and
  symptom recovery.
- Qualify an ordinary-laptop fast brain on actual 8/16 GB Windows machines;
  fine-tune only after reviewed labels and grouped held-out splits exist.
- Keep the WinINet writer unmounted until independent route proof, same-user
  consent, policy coverage, crash reconciliation, and VM recovery checks pass.
- Add physical Wi-Fi and 4090 gaming journeys only with their own repeatable
  workload oracles; a VM cannot qualify either.
