# SystemSense status

SystemSense is a read-only, local-first Windows investigator under development.
It is not yet an automatic fixer, a general IT replacement, or a qualified
diagnostic product. The product target and ordered acceptance gates are in
[next steps](NEXT_STEPS.md); the live implementation is described in
[the architecture](architecture/local-two-brain.md).

The latest host-only checkpoint adds private, versioned next-probe snapshots
and a separately reviewed, weak local-teacher draft contract. One synthetic
Qwen3.8 teacher call passed its structured-output smoke test, but there are
still no admitted real training labels, tuned checkpoints, ordinary-laptop
measurements, or diagnostic/recovery performance results. The disposable VM
trial remains inadmissible until its guest, reset, origin, and independent
recovery custody gates are met. See the [fine-tuning decision](LAYA_FINETUNING.md).

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
   When an initial packet omits evidence, the runtime can follow a bounded
   one-hop observed machine relation from visible current-incident evidence and
   prioritize its linked records within the same 48-record packet. It admits a
   link only when all cited evidence is current and retained together; an
   indexed source-entity lookup prevents a whole-graph adjacency scan. This
   is selective retrieval, not exhaustive graph search or causal proof.
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
   callback delays and stale snapshots. A canonical-target named mutex now
   excludes cooperating writer processes; refusal leaves the durable execution
   interrupted and non-retryable. Native read/check/write is still not atomic
   against unrelated Windows writers.
   A cross-component test confirms the real lab route oracle cannot produce
   the runner's required proof: it fails closed with zero writes.
   An unmounted approval prototype now uses a local desktop dialog, checks the
   active user's SID, logon and session identity, and consumes a one-use
   proposal-bound witness before the durable claim. Its prompt is fake-tested,
   not live-qualified or a secure desktop; it cannot defend against malware in
   the user's session. The owned endpoint, independent affected-task retry,
   terminal-reconciliation composition, and restorable VM qualification are
   also missing.
   A separate read-only reconciliation assessor
   can distinguish observed setting from observed symptom only with injected
   trusted stop and evidence verifiers; its results are always unqualified and
   cannot release a target lock. The unmounted terminal-release primitive uses
   the same concrete target mutex as the writer, but still lacks production
   stop, journal, evidence, and approval verifiers. The application has no
   enabled host repair.

## Verification and what it means

The current integrated non-MCP suite and opt-in owned-port rehearsal have been
run on this development host; exact counts and commands are in
[the active record](ACTIVE_GOAL.md). The owned-port rehearsal uses a disposable
harness-owned blocker and target. It exercises persisted listener and bind
evidence, then the harness alone removes its blocker and checks a new bind/HTTP
response. It is not a consumer repair, an independent VM oracle, or measured
general diagnostic accuracy.

An offline benchmark binder can check the schema, timing, and readback of raw
host captures, a typed arm-result summary, optional typed coordinator-event
projections, and independent reviewer judgments. It reports
`host_evidence_binding_only`: it neither authenticates a VM rig nor invokes an
oracle. The bare scorecard does not automatically invoke this binder. An optional
`score_host_bound_episodes` entry point checks a supplied episode binding
against each reviewed VM episode before scoring; it cannot authenticate who
produced the binding or turn caller-supplied digests into measured outcomes.
An episode-level binder requires distinct A/B/C review captures in one
qualification capture and returns `host_episode_binding_only`; it still does
not authenticate a rig or produce a score. Schema-3 event projections are
checked against the submitted episode's counts and times, but neither schema
authenticates the underlying probe/model trace. An opt-in visual PDF page-action
witness has fake-backed identity/capture tests, but no qualified live episode.
Its opt-in flags do not attest VM origin or make a host input action safe.
Fresh recorded cases now have an append-only coordinator event journal. Probe,
evidence, and coverage events are committed with their source rows; provider
completions and one terminal result are recorded separately. The recorder checks
its episode summary against a reopened, bounded case trace before returning it.
This is durable host consistency, not authenticated guest execution. Resumed
interrupted cases deliberately fail trace export until run generations are
represented explicitly. Deleting linked raw evidence under retention also
closes the export window; the journal alone is not a long-term proof artifact.
An opt-in write-once sidecar can capture the bounded validated trace and exact
episode artifact digest before retention. It is host-only, outside the fixed
trial sequence, and not an authenticated runtime/guest trace.
An opt-in same-request CPU fast-brain profiler now counts cold construction,
distinct warm calls, soft-deadline misses, reported attention gaps, and degraded
fallback for keyword, typed-feature, and explicitly enabled CPU Laya. It has
not run on an ordinary laptop; its shared-process resource samples cannot rank
provider RAM, and it measures neither useful-probe quality nor full diagnosis.
An offline host-side proxy witness can read an accepted TCP CONNECT header,
seal the bytes once, and bind them to supplied trial, worker/socket, and origin
records. Its `host_route_binding_only` result does not authenticate those
supplied identities, prove actual origin TLS or affected-app recovery, or emit
the `RouteProof` required by the still-unmounted repair runner.
An opt-in loopback-only producer now owns one listener, records that CONNECT,
and returns a fixed 502 without tunneling. Its separate denial receipt is
`host_proxy_denial_only`; it has no VM-facing interface or guest attribution.

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
