# Active local investigation

The product is an investigator, not an MCP report generator. The two advisory
providers are replaceable. Their current local implementations are Laya typed
decisions and standard Qwen3.8 27B; neither model owns measurements or permissions.

```mermaid
flowchart TD
    Goal[Symptom and incident window] --> Baseline[Bounded parallel baseline]
    Baseline --> Store[Immutable observations and temporal machine edges]
    Store --> Attention[Laya attention over bounded fact previews]
    Knowledge[Conditional reference knowledge] --> Attention
    Attention --> Probes[Rank registered unused read-only probes]
    Probes --> Scheduler[Dependency and resource admission]
    Scheduler --> Store
    Attention --> Focus[Focused map plus preserved hypothesis citations]
    Focus --> Deep[Qwen competing hypotheses]
    Knowledge --> Deep
    Deep -->|Redirect investigations| Attention
    Deep -->|Request exact local detail| Store
    Deep --> Gate[Deterministic completion and uncertainty policy]
    Gate --> Report[Cited observation or explicit uncertainty]
```

This diagram is the **current read-only runtime**. The intended product loop
extends it with a versioned causal claim, an exact repair proposal, trusted
human review, a single-use execution claim, live target recheck, constrained
adapter write, independent affected-task retry, and durable success/failure
report. None of those stages may be collapsed into a model response. The
proposal store and narrow WinINet runner exist as disconnected groundwork, not
an enabled path from the browser to a native write.

## Responsibilities

`Investigator` owns the durable state machine. Baseline collectors run before the
first model call. Laya ranks evidence and eligible actions; a second attention
pass evaluates newly collected facts before Qwen receives them. The coordinator
checks provider identity, state version, correlation, deadlines, budgets, probe
IDs and citations. A model output is not an executable command.

Qwen receives a bounded evidence map, not the raw computer state. It can redirect
the next probe frontier, request another observation, or issue a literal search
inside one already admitted observation. Detail searches cannot access arbitrary
paths, SQL, URLs or other cases. Completed requests are tracked and a reasoning
round has at most two retrieval-only follow-ups.

The execution graph and diagnostic graph are different structures. The former
coordinates dependencies between jobs. The latter records sourced relationships
between machine components. Traversal selects relevant information but does not
establish causality.

When Laya or another fast provider has no eligible proposal, the coordinator
may use a registered distinguishing probe from a relevant conditional reference
relation. This is a bounded fallback, not a generic cheapest-probe sweep or a
claim that a relation holds on the current machine. An irrelevant or exhausted
reference frontier yields explicit insufficient observability.

The current connectivity collector illustrates the evidence boundary. One
read-only call records separately timed WLAN, IP/DNS, default-route, WinINet
proxy, and recent WLAN-event stages. A compact preview keeps stage statuses,
times, counts, and omissions inside the inference fact budget; the full redacted
snapshot remains available as a separate local fact. Deterministic assessment
requires fresh source times and sufficient coverage before making absence
statements, and issues only unresolved hypotheses. Configured DNS, a route, or
a proxy does not prove endpoint reachability, affected-app scope, or root cause.

## Memory and context correctness

- Source time, capture time, incident window and case deadline are independent.
- Fact paging retains original values and identifies excerpts as parts of the
  same observation, not independent supporting measurements.
- An active hypothesis retains the exact facts it previously saw. Keeping its
  evidence ID while substituting a different page would change the meaning of
  its citation, so the coordinator persists the admitted context.
- Exact endpoint/PID retrieval supplements model attention. It is a scoped lookup,
  not a keyword-based investigation planner or an inferred dependency.
- Required citations and coverage gaps survive ranking. Token admission uses a
  pinned local tokenizer. Optional background reference text is reduced before
  observed facts; every omission remains explicit.
- General documentation stays separate from machine observations. An error-code
  description or possible mechanism does not prove that condition occurred.

The next evidence contract must distinguish four kinds of result: an observed
fact (for example, an exact listener owner), a supported causal diagnosis
(target-side failure correlated to contemporaneous owner evidence), a proposed
action, and independently verified recovery. The controlled port harness has
target failure and retry observations, but they are outside the case store; its
case cannot honestly promote them to a diagnosis. Each promotion requires its
own source, timestamp, coverage and contradiction checks. Unknown is a valid
terminal state when any required link is missing.

## Model and resource choices

The standard Qwen3.8 27B Q4_K_M artifact is pinned by digest. Its measured 8K-context
GPU residency is about 17.30 GB on this RTX 4090. An 8K context preserves headroom
for Laya. Larger advertised context capacity is not a reason to allocate it on a
shared 24 GB GPU. The previous Qwen3.5 runner was explicitly unloaded for testing;
no unrelated model weights were deleted.

Laya's CPU implementation was too slow for the measured broad attention workload.
The separately pinned CUDA runtime uses batches of four, releases unused scratch
allocation between requests, and retains warm model weights. Its small encoder
requires token-aware instruction splitting and complete-field state admission.
Ordinal scores are attention rankings, not probabilities of a Windows diagnosis.

The Ollama provider checks available system RAM and GPU memory before its local
requests. Laya separately requires at least 5 GiB of available host RAM before
starting or restarting its worker; its CUDA worker also checks free VRAM at load.
Unknown or insufficient capacity declines the optional worker and visibly falls
back to deterministic attention without unloading another workload. These are
admission floors, not running memory caps or ordinary-laptop qualification: a
warm Laya worker does not recheck host RAM on every request. The current measured
single-GPU profile has tight headroom. Model acquisition is a separate explicit
setup operation, not a side effect of investigation. There is no cloud or paid
fallback.

Observer effects matter: local inference itself consumes CPU/GPU capacity.
Follow-up measurements include that activity. The case and reasoning packet state
this limitation; a busy GPU during investigation is not proof of the original
complaint.

## Completion and permission boundary

The system may answer a narrowly verified observation question, such as exact
listener ownership, without claiming a broader root cause. The deterministic
assessment generates that answer from typed current facts, not from model prose.
Other cases end with supported uncertainty, exhausted budget, cancellation or an
explicit observability gap. Repeated probes and repeated detail searches cannot
masquerade as progress.

Read-only investigation does not imply consent for a repair. Existing proposal
and consent contracts are not an enabled executor. A production repair boundary
still needs typed operation adapters, independently evaluated preconditions,
durable single-use consent, an action journal and independent outcome verification.
Successful collection or a valid model response must never be labeled a verified
repair or a measured diagnostic-accuracy result.

There is a fake-tested WinINet proxy repair runner and a native adapter with
active-interactive-session, primary-token, non-impersonation, and read-only
managed-policy checks. A fixed-descriptor lab oracle contract records separate
current-user WinINet and direct-control evidence without accepting model-supplied
destinations. The isolated native transport implements separate PRECONFIG and
DIRECT access types with a bounded child-process request. The journal binds a
single-use token to the case, target and authorization and persists the failed
affected path, passing direct control, and post-change affected path. These
contracts are groundwork, not an enabled automatic fixer: there is no owned
external endpoint, trusted application approval route, VM qualification, or
independently demonstrated recovery. The registry policy checks do not cover
all MDM, GPP, VPN or application-level restrictions. PRECONFIG plus a passing
DIRECT check alone does not prove the request used the proxy; routing needs an
independent controlled oracle or per-request route evidence.

Crash inspection can compare the current proxy state with the exact journaled
proposal without writing or unlocking the target. An observed intended setting
is not a verified recovery. The loopback browser's session and CSRF token also
do not prove a human approved an action: another local process can request them.
A separate, unmounted SQLite admission store now keeps canonical immutable
repair proposals, an exact active proposal ID/digest per case, and at most one
review claim per proposal. It rejects a superseded proposal even if the case
version and procedure revision string did not change. That claim is not proof
of a verified reviewer or one-time execution: the existing runner still uses
the weaker case-version/procedure-revision tuple and a separate journal. A
production route must bind the exact active proposal at the write boundary,
atomically claim execution with approval in one durable store, and reconcile
crashes without replay. The head can also be expired or already claimed; it is
not by itself an eligible repair offer.
A future repair route must retrieve an immutable server-owned proposal and use
an interactive same-user confirmation outside browser-supplied JSON before
minting the one-use authorization. Headless and unqualified-policy cases stay
read-only.

## Qualification boundary

Unit and integration tests establish contracts and failure behavior. Synthetic
real-inference cases establish model protocol behavior. Live cases establish
end-to-end runtime and observations. None alone establishes general root-cause
accuracy, Laya's diagnostic action quality, or the safety of fine-tuning data.
Those require reviewed held-out incidents and separately evaluated action labels.
The new VM protocol validator only admits internally consistent, rig-claimed
reset/injection/oracle records. No VM controller or measured Windows fault run is
present, and its result explicitly forbids accuracy or repair-success claims.

## Next measured improvements

First establish the independently controlled VM lane, owned external endpoint,
and one exact WinINet repair journey, so outcome quality and time-to-recovery
have a real denominator. Add an approval route and crash reconciliation before
the action can be offered through the application.
Then compare equal-budget deterministic, deep-only, and dual-brain arms on
blinded fault, healthy, and external cases. Use the traces to identify wasted
probes, stale branches, excess model latency, and false causal leaps before
changing attention prompts, batching, or fine-tuning Laya. A compact local
decision model is a candidate for ordinary laptops only after measured latency,
memory, power, and diagnostic quality there; a future cloud reasoner should
remain a replaceable, export-gated advisory provider, not a prerequisite for
the fully local edition.
