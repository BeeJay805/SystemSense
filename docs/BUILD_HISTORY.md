# Build history

This is the chronological engineering record. The five canonical product documents
remain authoritative for current behavior, architecture, training, and acceptance.
Entries record evidence at the stated revision; later results do not rewrite failures.
Private case data, logs, screenshots, and clips stay outside Git with hashes recorded
here when used as evidence.

## 2026-09-26 16:20 PDT | Bootstrap | `476611366b632d68a0c62bd3bba2a64ec4792ae4`

- Goal/problem: Establish one current-truth documentation path and a durable record
  before parallel runtime and evaluation work.
- Change and why: Add documentation hygiene to contributor instructions and create
  this history so implementation claims stay separate from retrospective evidence.
- Alternatives/failures: No runtime behavior changed. Existing archived plans remain
  historical; no previous failure has been removed.
- Evidence/metrics: The worktree started clean at the stated base. `dev-context.ps1
  -RefreshMap` ran; its optional map parsed 187/203 modules in this worktree and is
  navigation help only.
- Next question: Which current runtime gaps most affect time to useful evidence and
  false causal claims in the agreed comparison cases?
- Artifacts: Team coordination board under the private local SystemSense directory.
