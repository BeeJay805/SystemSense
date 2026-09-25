# Current state at repository HEAD

This page describes committed implementation only, not working-tree edits or host state. It is not a progress log; acceptance requirements live in [Benchmarks and acceptance](BENCHMARKS_AND_ACCEPTANCE.md).

## Available now

- A Python 3.12+ local-first investigator with a loopback case application and optional MCP adapter. The default install is deterministic; inference is opt-in.
- Seventeen registered read-only Windows collectors, fixed typed inputs, bounded isolated execution for default collectors, passive Event Log and connectivity capture, evidence coverage/provenance/redaction, SQLite persistence, retention, and hash-linked audit. Source observation, capture, case-open, and audit time have separate semantics. Custom trusted in-process handlers are not a hard-kill boundary.
- A bounded dependency/resource task scheduler, durable case state, hypotheses, attempt outcomes, cancellation/recovery, evidence and sourced reference graphs, and registered detail retrieval. Graph edges and keyword ranking do not prove causality.
- An event-driven mixed frontier can rank existing-evidence retrieval, observed graph branches, source-bound read-only measurements, and deep escalation while unrelated probes remain in flight. A selected deep task can run concurrently with later fast turns. Candidate admissions and one-shot worker claims atomically advance their frontier custody; exact parent observation windows distinguish repeat measurements without replaying the same interval. The older synchronous/post-batch route still exists for non-streaming cases and fallback.
- Structured semantic packets expose bounded nested GPU and process values, timestamps, quality, and omissions to the fast provider. The mixed frontier freezes at most 16 prioritized packets per receipt with explicit omission markers; receipt-backed snapshots can freeze all four mixed choice kinds for source revalidation.
- Replaceable fast and reasoning provider contracts, deterministic fallback, managed CUDA Laya, and local Ollama reasoning. An opt-in schema-v4 `warm-independent` profile and CLI path keep the two managed roles independently callable under one host lease budget; schema-v4 sequential swapping remains an explicit low-memory fallback. A controlled isolated-ledger run on this RTX 4090 produced real Laya rankings while the pinned local Ollama worker was active, and two non-degraded deep results were applied. This is a coexistence smoke test, not diagnostic qualification.
- A fixture-only frontier pilot exporter preserves exact persisted request, response, and source receipts with privacy/oracle gates and split fences. It explicitly refuses training admission because actual worker token IDs and tokenizer/build receipts are not yet durable.
- Exact-scope consent and WinINet repair primitives with fake transport tests. They are not mounted as an application repair route and do not establish a real Windows repair.

## Not yet qualified or delivered

- The default installation is still deterministic. The warm profile is opt-in and development-only; the installed v3 host lease ledger still requires its approved cold-boot v4 migration before normal host use.
- Incremental invalidation and microbatch code paths exist, but sustained useful judgment throughput and the all-attempt under-400-ms p95 target are unproven. The final controlled smoke had one admitted event at 747 ms, not a qualifying p95. Real four-way choice competition and counterevidence redirection remain unproven with both actual models.
- There is no measured held-out Windows diagnostic accuracy, training-admissible pilot corpus, trained Laya search policy, cloud inference, general automatic repair, or qualified real-fault repair run.
- The committed Qwen3.5 4B development pin was verified in this controlled coexistence smoke; it is not an optimal-model claim. Qwen3.8 27B has not been qualified for safe simultaneous residency or context on this host.
