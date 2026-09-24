# SystemSense application build record

## Scope and revision

September 22, 2026. Developed from base `812f00e72223` on branch
`codex/windows-investigator`. The user's two-brain goals supersede
the old MCP scope. Handoff architecture/model choices remain replaceable proposals.
This is the broad local read-only milestone, not verified intervention or production
diagnostic qualification. Cloud inference and paid experiments are excluded.

## Architecture decisions

- One deterministic coordinator owns case state, observation times, execution,
  permissions, budgets, redaction, audit and verified fact promotion.
- Laya repeatedly ranks evidence fragments and read-only probe candidates. Qwen
  maintains competing explanations, requests exact details and redirects work.
- Typed provider results bind to case/version/correlation/deadline and known IDs.
  Model prose, relevance scores and graph connectivity never establish causality.
- Independent probes use bounded parallel scheduling and isolated workers.
  SQLite WAL stores durable evidence, graph relations, checkpoints and history.
- Current collection and the incident-history window are separate. Resumes do not
  silently replay completed probes or relabel old observations as fresh.
- MCP is optional. The loopback browser has origin/token protection, no shell/query
  surface, explicit degraded states, citations, coverage and redacted report export.
- Legacy paid-model A/B code and client setup were removed from the active product;
  tracked originals remain recoverable from Git history.
- Repair proposals/consent contracts exist; no repair executor is enabled.

## Implemented and reviewed

- Fifteen broad Windows probes, including pressure, GPU telemetry and listener
  identity follow-ups. Missing counters, identities and coverage are not fabricated.
- CPU sampling uses a real 0.2-second interval with start/end/capture timestamps;
  unavailable/capped filesystem records are disclosed. Older non-blocking CPU
  zeros in earlier acceptance artifacts are not valid host-idleness evidence.
- Exact fact paging, source-preserving field paths, grounded dependency traversal,
  token-aware context admission, omission accounting and durable hypothesis history.
- Generic/detail requests retire only after their actual facts reach a successful
  reasoning call. Unmet requests stay explicit through bounded follow-up.
- Full-string narrow observation intent gates prevent an ownership/status answer
  from falsely completing a causal or mixed-action question.
- Cited assessed excerpts rehydrate within authorized case/collection scopes and
  retain source, collector and execution identity. History returns compact summaries.
- Internal assessed-context caches never leave the report boundary. Authorized
  citations are rehydrated separately; coverage cards and late evicted citations
  preserve incident-window qualifications. Whole-payload privacy regressions pass.
- Migration v5 repairs legacy v4's missing execution-state column without losing
  rows or valid audit chains. Normal workspace migrated successfully, integrity ok.
- Failures record safe exception/code locations without dumping private payloads.
- Separate reference graph: 66 nodes, 102 conditional relations, 18 primary sources.
  Windows runtime catalog adds 3,116 error codes, explicitly reference data.
  A live broad case persisted 403 machine relations across service dependencies,
  service/process identities, device/driver links and volume/disk mappings.

## Local models and resource evidence

Selected host profile: pinned standard Qwen3.8 27B Q4_K_M, 8K context, 1,200 output
tokens, plus pinned Laya 0.3.5 on CUDA with explicitly selected FP16 parameters.
Old Qwen3.5 was unloaded with user authorization; no weights were deleted.

Laya's measured FP16 peak allocation was 874 MiB versus FP32's 2,346 MiB.
Ordinal-parity checks are not Windows ranking qualification. Runtime admission
retains a 2 GiB GPU reserve and never evicts unrelated workloads.
See [model selection](LOCAL_MODELS.md) and [Laya qualification](LAYA_QUALIFICATION.md).

## Verification evidence

- Final-code narrow live case: `case_15159bd1ec7b4ce0af2442e7c647e2a8`,
  104.657 seconds, all 8 model calls valid, 14 probe audit entries verified,
  SQLite integrity ok. Exact owner/PID/creation-time answer independently read back;
  `root_cause_proven=false`. Artifact: `tmp/dual-brain-final-owner.json`.
- Prior FP16 broad journey: 179.625 seconds, all 15 probes, 7 Laya + 9 Qwen calls,
  no fallback, explicit insufficient observability. Last attention pass disclosed
  512/549 fragments before its deadline. No slowdown was reproduced.
- Final-code broad repeat: `case_089a38b8f4cf4d50baf4b364735ed765`, 153.297
  seconds, all 15 probes and 14 model calls (7 Laya, 7 Qwen) without fallback.
  Final attention covered 550/550 fragments and 58/58 pages. The 15-entry audit
  chain verified. Outcome: insufficient observability, not an invented cause.
  Artifact: `tmp/dual-brain-final-broad.json`.
- Updated browser started/cancelled a local case
  during Laya and retained all six baseline observations across preview restart.
  Resume completed in 56.659 seconds with four new probes, two validated Laya calls
  and one validated Qwen call. All ten probes ran once; all ten audit entries verify.
  Independent Windows readback matched the cited endpoint owner, PID and
  creation time. Citation navigation and actual downloaded report were verified;
  the deliberate cancelled call remains explicitly recorded as degraded.
  The private host report remains local and is not part of the repository.
- Final automated gate: 635 passed, one live-GPU test deselected, 85% coverage,
  56.46 seconds with live Windows checks enabled and unhandled-thread warnings
  promoted to errors. Real dual-brain GPU journeys are recorded separately above.
  Final privacy regression suite: five passed after its test-only strengthening.
- Ruff formatting (266 files) and lint passed. Core and full strict Pyright both
  reported zero errors/warnings. Locked dependency and installed-package checks passed.
- Clean owned application-service idle measurement: 43,302,912 bytes peak RSS
  (41.30 MiB), 0.0% mean CPU over 500.12 ms / ten samples. Interpreter PID and creation
  time were verified, not the Windows launcher. This excludes browser/HTTP serving
  and loaded models; it is not an end-to-end host-impact result.
- Wheel/source build and fresh external core-only install passed. Schema v5,
  integrity ok, 13 runtime assets, graph 66/102, passive fixture 2 evidence/4 coverage;
  MCP, AnyIO, tokenizers and Torch absent. Missing-MCP command failed cleanly.
  Package smoke isolates its default config from the user's explicitly enabled profile.
- Verified artifacts are in `dist`: wheel SHA-256
  `2351496180bf9df0e8182ef0f89de653e1e59a88cf25ad00f1d3c0836bf862bb`;
  source archive `bfdbef51086cd11ef994b973edac1666df35700ed9578fec47b9d458c13147a5`.
  Prior 447/577 totals are historical. Fixture benchmark 6/6 checks passed,
  with no diagnostic-performance claim.
- Failed context/VRAM/transport/schema runs are retained, not removed from evaluation.
  All fixture and synthetic results remain distinct from measured diagnostic accuracy.

## Runtime and remaining qualification

The normal preview at `http://127.0.0.1:18765` was restarted with explicit user
approval for its owned processes. Its recorder was off at acceptance; the report
privacy and temporal-qualification fixes were live. No startup task/service was
installed. The local inference endpoint for this host was on loopback port 11435.

Remaining qualification, beyond engineering gates: held-out real Windows incidents,
Windows-specific Laya labels/fine-tuning, measured causal diagnostic performance,
and a separately permission-bound, reviewed intervention catalog with outcome verification.
