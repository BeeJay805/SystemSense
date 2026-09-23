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
2. Seventeen model-visible Windows probes cover core resources, applications,
   devices, network, storage, security, events, power, and related samples.
   Source event times remain separate from collection and audit times. Multi-step
   deep collectors now report collection intervals; listener-table query bounds
   are separate from later process-owner lookups. The passive Wi-Fi view now
   joins WLAN, IP-adapter, IPv4-default-route, and recent event stages by exact
   interface identifiers. Missing, malformed, ambiguous, or omitted identities
   remain incomplete rather than borrowing a route or event from another adapter.
   These stages do not measure target reachability or establish a cause.
   The version-3 connectivity probe also asks Windows for its selected local
   route to at most two IPv4 DNS servers observed in adapter configuration. It
   sends no packet and cannot take a model-supplied destination. Each query has
   its own time and status; incomplete adapter or DNS-list coverage makes the
   aggregate partial even when a queried route succeeds. See
   [route observation](NETWORK_ROUTE_OBSERVATION.md).
   An additional runner-only process-pressure probe accepts an exact PID plus
   creation time and is not visible to model planning. For a slow-PDF objective,
   the loopback browser can pause after a current-case application snapshot,
   show bounded process candidates, and resume only after a user selects one.
   The runtime revalidates its evidence binding and records either read-only
   counters or explicit unavailable coverage. This does not measure PDF page
   latency or establish that the selected process caused the slowdown.
3. The evidence layer retains redacted facts, provenance, limitations, temporal
   machine relationships, and a separate sourced conditional reference graph.
   Reference links guide inquiry but do not prove a cause on this machine. The
   reference pack now includes a PDF page-action-to-viewer dependency and a CPU
   interference screening link. Neither is a measured page-turn critical path;
   a storage-wait link is deferred until the document read path and per-volume
   latency can be observed.
   Explicit Wi-Fi symptoms seed sourced, conditional network hypotheses and
   normalize the WiFi spelling for attention routing. A wireless peripheral
   alone does not assert Wi-Fi. Missing IPv4 can be raised only for a connected
   Wi-Fi path joined to a unique complete adapter; another adapter's address
   cannot satisfy it. This remains a hypothesis, not a proven cause.
   A complete configured-DNS route that selects a different interface is also
   an unresolved clue. Partial, stale, or denied route rows remain coverage
   gaps; neither the clue nor a successful route proves DNS reachability.
4. Replaceable advisory providers run the active loop. Optional Laya ranks
   evidence and registered next probes; optional local Qwen3.8 27B compares
   hypotheses and asks for focused detail. A schema-2 profile can explicitly
   substitute the CPU typed-feature router for Laya while retaining a pinned
   local reasoner. It is a deterministic challenger, not a second AI model or
   a qualified default. Keyword routing remains the baseline and degraded
   fallback. No model owns a measurement or permission. Validated Qwen
   distinguishing probes now persist in the case checkpoint and receive first
   claim on the next bounded read-only batch; Laya fills spare slots. Stale
   requests retire. A model citation listed as both support and contradiction
   is retained only as contradiction and labeled contested.
   When validated deep-brain requests fill every available probe slot, the
   coordinator omits the redundant fast routing call for that batch. It keeps
   post-collection fast attention, deep reasoning, admission checks, and a
   durable supersession trace. Call-count tests do not establish a real-model
   latency or answer-quality gain.
5. A deterministic assessor may return exact narrow observations, such as a
   reported listener owner, and one bounded temporal association between a
   target-side Winsock 10048 failure and matching listener reads around it.
   That association does not prove socket ownership at the failure instant or
   authorize an action. Unresolved is an ordinary terminal outcome.
6. The loopback browser and CLI expose read-only cases; process-target selection
   is currently a browser/API workflow, not a CLI command. MCP is optional. Repair
   proposals, one-shot authorization storage, and a fake-tested WinINet runner
   remain disconnected groundwork. The unmounted runner now fails closed without
   independently verified affected/DIRECT route proof bound to one registered
   endpoint. Its final prewrite and readback freshness checks cover tested
   callback delays and stale snapshots, but cross-process read/write atomicity
   is not yet established.
   A cross-component test confirms the real lab route oracle cannot produce
   the runner's required proof: it fails closed with zero writes.
   The current approval prototype trusts an injected `human:*` identity label;
   that is not authenticated interactive Windows consent and must not be mounted
   as a writer. The owned endpoint, independent affected-task retry, and
   restorable VM qualification are also missing.
   A separate read-only reconciliation assessor
   can distinguish observed setting from observed symptom only with injected
   trusted stop and evidence verifiers; its results are always unqualified and
   cannot release a target lock. The application has no enabled host repair.

## Verification and what it means

The current integrated non-MCP suite and opt-in owned-port rehearsal have been
run on this development host; exact counts and commands are in
[the active record](ACTIVE_GOAL.md). The owned-port rehearsal uses a disposable
harness-owned blocker and target. It exercises persisted listener and bind
evidence, then the harness alone removes its blocker and checks a new bind/HTTP
response. It is not a consumer repair, an independent VM oracle, or measured
general diagnostic accuracy.

An offline benchmark binder can check the schema, timing, and readback of raw
host captures, a typed arm-result summary, and independent reviewer judgments. It reports
`host_evidence_binding_only`: it neither authenticates a VM rig nor invokes an
oracle. The scorecard does not automatically invoke this binder and cannot
turn caller-supplied digests into measured outcomes.
An episode-level binder requires distinct A/B/C review captures in one
qualification capture and returns `host_episode_binding_only`; it still does
not authenticate a rig or produce a score. Its schema-2 arm-result readback
does not verify the underlying probe/model trace. An opt-in visual PDF page-action
witness has fake-backed identity/capture tests, but no qualified live episode.
Its opt-in flags do not attest VM origin or make a host input action safe.

The lab harness records a random arm-order seed and actual executed order. A
late synchronous arm is marked timed out and receives no recovery credit;
the harness still cannot interrupt a hung callback. VM protocol checks and the
reviewed scorecard are consistency/accounting tools, not authenticators of a
rig, reviewer, injected fault, or recovery. Synthetic fixtures and five local
coordinator journeys do not establish product-performance percentages.

Current local model measurements are device-specific: a warm synthetic
54-preview/17-probe Laya CPU sweep on this desktop took roughly 102–105 seconds;
even a two-preview/four-probe warm CPU call took about ten seconds. The optional
typed-feature router handled the broad synthetic request in submillisecond
provider-only timing, but its useful-probe quality is unmeasured. These are not
matched diagnostic outcomes. The pinned Qwen3.8 27B Q4 profile used about
17.3 GB of RTX 4090 memory at an 8K context. None of this is ordinary-laptop
qualification or diagnostic accuracy.
After warm-admission and conflicting-citation fixes, one explicit-profile live
read-only case completed four ready Laya calls and six ready Qwen calls in
82.556 seconds. A later case with a new-fact gate on immediate Qwen follow-up
completed four ready Laya and five ready Qwen calls in 75.688 seconds. Both
exhausted two rounds with no supported game cause. They had different probe
mixes and are not a paired speed or diagnostic comparison. No game task or
live frame-time oracle was present. An operator-only offline PresentMon v2 CSV
importer can summarize per-swapchain frame distributions, but imported bytes
and operator-attested settings do not prove capture origin, game cause, or
recovery; see [game episode limits](GAME_EPISODE.md).
There are no admitted expert next-probe labels and no Windows-specific
fine-tuned fast brain.

The disposable Windows VM clone is powered off with disconnected NIC, no
snapshot, and no verified guest login or independent oracle. Its read-only
preflight says `can_begin_episode=false`; no qualified Windows fault or repair
trial has run. VirtualBox protocol records now require a same-UUID, recent
preflight binding, but that caller-supplied consistency link is not host
attestation or episode qualification. No cloud inference or automatic paid
fallback is implemented.

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
