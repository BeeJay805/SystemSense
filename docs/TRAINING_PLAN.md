# Fast-brain training plan

Training is **not** the next implementation step. First make the exact two-brain runtime input and nonblocking loop work, then collect a small independently checked pilot. Laya's job is attention and investigative routing, not final diagnosis or permission granting.

## Frozen example contract

Capture the actual, bounded pre-result candidate menu and exact worker input from the runtime: candidate kind/order, target, registered parameters, observation window, evidence IDs and source/capture times, nested semantic values, quality/coverage/omissions, graph context, cache origin, state generation, budget, and available model actions. Record actual model artifact, tokenizer, wheel/source, builder, worker, prompt/schema, and configuration versions. Store privacy/consent and source receipts. A hash-only trace is insufficient.

For each candidate judgment, independently check what evidence or test it actually yielded for the affected task. Label useful, uninformative, contradictory, failed, or unrun explicitly; unrun is unknown, not negative. A deep model's explanation or teacher preference is not gold. Start with a few controlled Windows fault cases plus healthy and external-fault controls. Require an oracle separate from model outputs and a reproducible replay report.

## Pilot admission before weight updates

1. Prove runtime-to-training parity on real captured examples, including token IDs, attention masks, marker positions, question type/order, state fitting, and every truncation path against the installed builder. Ensure important nested values actually reach the worker.
2. Review independently checked outcomes, privacy receipts, source provenance, and failure/abstention denominators. Split by case, machine, software version, and fault family to prevent near-duplicate leakage.
3. Compare proposed teacher models by measured draft utility, latency, throughput, and cost on the same frozen menus. Neither a preferred 27B name nor a smaller challenger is assumed best. Keep teacher suggestions distinct from oracle labels.
4. Only after the pilot passes, expand data deliberately and train a candidate Laya policy. Evaluate it against the untrained model and deterministic baseline on held-out investigations with identical evidence access, budgets, and probes. Promote only if diagnostic utility and safety hold while latency/resource targets improve.

No large synthetic corpus, blind teacher distillation, or fine-tuning is authorized by this plan. The current desktop/RTX 4090 dual-brain experiment is the immediate runtime target; ordinary-laptop local qualification is a later open-source deployment gate, not a reason to weaken the current architecture. A future cloud-brain deployment must use the same advisory input/output contract and separate privacy consent.
