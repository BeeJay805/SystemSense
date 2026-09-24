# Managed local deep brain: admission design (proposed)

Status: design gate, not an active execution mode. Astra independently reviewed
the current managed GPU boundary on 2026-09-24. Today, managed CUDA Laya runs
with deterministic reasoning. Historical pinned Qwen3.8 27B experiments do not
qualify shared residency, a managed server, or a useful two-brain diagnosis.

## Decision and alternatives

The next local deep-brain slice should own a dedicated loopback Qwen service
and its complete process tree. It should not point the managed profile at an
already-running Ollama endpoint. The shared endpoint cannot prove who owns its
model load, runner children, generation after HTTP cancellation, or GPU memory
release. CPU-only Qwen is an explicit separate fallback profile, not an
implicit substitute for managed GPU reasoning. The model/provider choice stays
replaceable; the ownership and advisory contracts do not.

Add a versioned joint profile rather than relaxing schema-v3's prohibition on
neural reasoning. The profile pins the executable, model artifact digest,
context and output budgets, GPU UUID, measured or conservatively bounded peak
RAM/VRAM, and finite call/idle limits. Loading the profile is not permission to
load a model. A separate admission decision must bind a service process
incarnation and reserve its full lifetime demand in the existing same-user
cross-process inference ledger before any model-load token is issued.

## Lifetime and call states

```text
configured -> starting_unloaded -> leased -> ready -> closing -> exited
                        |              |          |           |
                        +---- denied --+-- lost --+-- unknown -> quarantined
```

`ready` requires a fresh source-timed host sample, the pinned GPU identity,
matching model digest, an owned loopback endpoint, and a live service tree.
The reservation remains held while Qwen is warm, not merely during an HTTP
request. A watchdog renews it while idle. The existing lease ledger reclaims an
expired lease when its single bound PID exits; that is insufficient when a GPU
runner child survives its server. Before activation, add a versioned tree-aware
lease and reclamation contract. Every automatic reclaim path, including one
invoked by another process, must respect tree custody; legacy readers must not
reclaim a joint-runtime lease from parent-PID exit alone. Only verified exit of
the complete owned tree permits release; a surviving runner, stale PID,
inaccessible process, or lost lease quarantines capacity. The host resource
controller must account
for Laya and Qwen together, reserve headroom for their bounded request
workspaces, and never evict an unrelated process.

Initially serialize neural GPU calls even when both models are resident. Give
pending fast attention a turn between deep requests, while every deep request
has a finite deadline. This avoids assuming concurrent generation is faster
or safe on a 24 GiB GPU. Later overlap requires measured latency, memory, and
affected-task interference evidence. Laya's advisory candidate IDs and Qwen's
advisory hypothesis/test requests still pass through deterministic validation;
neither obtains Windows, shell, registry, filesystem, network, or repair
authority.

Cancellation first rejects late advice at the case/epoch boundary. Closing a
client socket alone is insufficient evidence that generation stopped. If the
owned server cannot prove cancellation, retire its entire process tree and
retain/quarantine the lifetime lease until exit is verified. A composite
provider owner closes and reports each role independently. Failure to admit
Qwen visibly leaves managed Laya with deterministic reasoning; fast-brain
failure visibly degrades attention. No silent role substitution or success
status is allowed.

## Acceptance before activation

1. Unit and process tests prove that no preload or generation occurs before
   ownership and resource admission; wrong digest, endpoint, GPU UUID, stale
   telemetry, or insufficient headroom fails closed.
2. Two SystemSense processes cannot overbook the same GPU. Timeout, client
   crash, server crash, surviving child, and PID reuse cannot release capacity
   early. In particular: server exits, GPU runner survives, lease expires, a
   second client attempts acquisition, and capacity remains unavailable. A
   lost lease prevents another model call.
3. Legacy profiles retain their present deterministic degradation. The joint
   profile reports both actual role states, exact model digests, and explicit
   reasons for fallback; factory construction and close are idempotent.
4. A bounded local smoke proves real pinned Laya and Qwen calls, actual peak
   residency and call workspace, a clean owned shutdown, and no unrelated
   process interruption. Historical coexistence figures are not admission
   evidence for this build.
5. A controlled ambiguous Windows episode proves a complete loop: competing
   hypotheses, at least two useful registered read-only tests, Laya selection,
   new cited evidence, deep-brain revision or redirect, and independently
   verified affected-task outcome or explicit uncertainty. Record useful-
   progress latency, wrong-branch recovery, redundant probes, and memory
   interference. This is the first diagnostic-performance gate, not a fixture
   contract test or training label by itself.

The existing `HostResourceAdmission` is only an in-process arithmetic helper;
the durable `HostInferenceLeaseLedger` and owned process-tree proof are the
cross-process lifetime boundary. Existing `OllamaChatClient` validates local
responses but does not own the server. Existing `DeepWorkerLane` can reject a
late answer but cannot by itself stop server-side GPU generation. These
boundaries must be composed rather than bypassed.
