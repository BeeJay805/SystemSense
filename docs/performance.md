# Performance and resource boundaries

Performance is a product constraint, not a substitute for diagnostic quality.
Collection and inference must be bounded, observable, and cancellable.

## Current guarantees and foundations

- Probe manifests declare deadlines, maximum bytes, and maximum records.
- All 17 registered Windows probes run in one-shot workers. Custom trusted
  in-process handlers are cooperatively cancelled; a non-cooperative call can delay
  case return after its timeout outcome is recorded because Python cannot safely
  kill its thread.
- The scheduler foundation declares global and per-resource concurrency limits,
  task deadlines, cancellation, deduplication, and stale state checks.
- Probe runs record start, finish, elapsed, source observation, and local capture
  times independently.
- Queue, retention, artifact, and brief outputs are bounded.
- The default investigation path has no active network request or remote inference.

The current adaptive investigator invokes the scheduler for each bounded probe plan and
persists per-attempt outcomes. Scheduler deadlines bound admission and result
classification, but they are not a hard wall-time bound for non-isolated,
non-cooperative custom handlers. End-to-end latency, passive-history benefit, and host impact require
measured episodes rather than inference from unit tests.

The pinned CUDA Laya + Qwen3.8 27B 8K profile completed a narrow live endpoint-owner
case in 52.72 seconds: 25.36 seconds cold attention, 10.13 seconds follow-up
attention, and 10.88 seconds deep reasoning, plus read-only collection/coordinator
overhead. This is one runtime observation, not a latency percentile or diagnostic
accuracy claim. Broad cases expose different context and resource pressure and
must be qualified separately. See [Laya qualification](LAYA_QUALIFICATION.md).

The explicit FP16 Laya profile subsequently completed a broad live host journey
in 179.625 seconds with all 15 probes, seven successful Laya calls and nine
successful Qwen3.8 calls, without fallback. Six generic evidence requests were
delivered and retired; the final result was insufficient observability because
no slowdown was reproduced. The last attention pass disclosed its 512/549
fragments before its evidence deadline, rather than claiming full coverage. This single run is
runtime and resource-fit evidence, not a measured time to diagnose a known fault.

Earlier broad attempts remain failures in the acceptance record: oversized
context/schema rejection, two low-VRAM admissions with FP32 Laya, and an FP16
attempt with the dedicated Ollama server unavailable. The successful run does
not erase those results or establish a latency distribution.

The final implementation repeat completed a narrow owner/PID/creation-time case
in 104.657 seconds (14 probes, four Laya and four Qwen calls). Its deterministic
observed answer matched an independent Windows process readback. A separate broad
repeat took 153.297 seconds (15 probes, seven Laya and seven Qwen calls), with no
provider fallback and all 550 fragments covered in the final attention pass.
It explicitly ended with insufficient observability. Different goals, process
state and investigation branches make these observations unsuitable for a speedup
comparison. They do not establish diagnostic accuracy or a latency percentile.

## Measurements to report

Separate warm/cold startup, existing/new evidence, passive/active collection, and
provider availability. Report p50/p95 task and case latency, useful versus
redundant probes, queue tails, cancellation/deadline rates, CPU, memory/VRAM,
storage, and measurement disturbance. Include collection overhead in all case
comparisons.

## Offline boundary

Local collection may inspect local adapters and endpoint metadata through Windows
APIs. It must not perform DNS lookups, packet capture, active connectivity tests,
HTTP requests, or arbitrary socket calls. A future cloud advisory provider belongs
behind an explicit export gate and is not part of the default offline runtime.

The no-network tests exercise application-level entry points. They cannot prove
that every Windows COM, WMI, driver, or kernel implementation is incapable of
external behavior; that remains a residual platform risk.
