# Current state at repository HEAD

This page describes committed implementation only, not working-tree edits or host state. It is not a progress log; acceptance requirements live in [Benchmarks and acceptance](BENCHMARKS_AND_ACCEPTANCE.md).

## Available now

- A Python 3.12+ local-first investigator with a loopback case application and optional MCP adapter. The default install is deterministic; inference is opt-in.
- Seventeen registered read-only Windows collectors, fixed typed inputs, bounded isolated execution for default collectors, passive Event Log and connectivity capture, evidence coverage/provenance/redaction, SQLite persistence, retention, and hash-linked audit. Source observation, capture, case-open, and audit time have separate semantics. Custom trusted in-process handlers are not a hard-kill boundary.
- A bounded dependency/resource task scheduler, durable case state, hypotheses, attempt outcomes, cancellation/recovery, evidence and sourced reference graphs, and registered detail retrieval. Graph edges and keyword ranking do not prove causality.
- An event-driven mixed frontier can rank existing-evidence retrieval, observed graph branches, source-bound read-only measurements, and deep escalation while unrelated probes remain in flight. A selected deep task can run concurrently with later fast turns. Candidate admissions and one-shot worker claims atomically advance their frontier custody; exact parent observation windows distinguish repeat measurements without replaying the same interval. The older synchronous/post-batch route still exists for non-streaming cases and fallback.
- Structured semantic packets expose bounded nested GPU and process values, timestamps, quality, and omissions to the fast provider. Receipt-backed snapshots can freeze all four mixed choice kinds for source revalidation.
- Replaceable fast and reasoning provider contracts, deterministic fallback, managed CUDA Laya, and local Ollama reasoning. An opt-in schema-v4 `warm-independent` profile and CLI path keep the two managed roles independently callable under one host lease budget; schema-v4 sequential swapping remains an explicit low-memory fallback. The warm path has contract tests and fake-provider overlap proof, not a completed real-model coexistence trial at HEAD.
- Exact-scope consent and WinINet repair primitives with fake transport tests. They are not mounted as an application repair route and do not establish a real Windows repair.

## Not yet qualified or delivered

- The default installation is still deterministic and the old schema-v1 profile degrades rather than activating the dual-brain path. No ordinary live case has yet proved that actual Laya and the actual deep model remain warm, overlap, and use the new mixed loop without fallback.
- Incremental invalidation and microbatch code paths exist, but their full-path usefulness, sustained useful judgment throughput, and strict event-to-admission latency target are unproven on this checkout and host.
- There is no measured held-out Windows diagnostic accuracy, independently verified training pilot, trained Laya search policy, cloud inference, general automatic repair, or qualified real-fault repair run.
- A jointly admitted, reliably warm two-model host run has not been qualified. The committed profile is a development pin, not evidence that its model pair is optimal or that a larger model safely coexists.
