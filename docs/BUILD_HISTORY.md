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

## 2026-09-26 16:45 PDT | Registry and deep advice | `1b0af4108c1e81cc9d6df921ee0dd1586f31524a`

- Goal/problem: Registered tools without discovery declarations were invisible to
  applicability search; a malformed local deep answer ended the advisory pass.
- Change and why: `0d5060c` declares bounded output, target, window, cost,
  resource, privacy, and purpose hints for the existing built-in registry. `1b0af41`
  retries one malformed deep answer within the original deadline and schema, then
  retains the deterministic degraded result if it fails again.
- Alternatives/failures: A new tool framework or permissive model-output repair
  would add authority or hide invalid advice. The red registry test failed on the
  previously undeclared `core.system`; both malformed-answer tests failed before
  the retry was added. These failures are retained as development evidence.
- Evidence/metrics: 22 focused registry/catalog/Scout tests and 34 reasoning
  tests passed. Scoped Pyright reported 0 errors; Ruff lint/format and diff check
  passed. No actual model output or diagnostic quality was measured here.
- Next question: Does the expanded applicable registry improve meaningful
  shortlist diversity without delaying useful evidence or raising false claims?
- Artifacts: Source and tests in the two stated commits; no private capture.

## 2026-09-26 17:18 PDT | Applicable choices and Scout | `52b6b86b988f6c633069ba8a2b41ef485ce682f9`

- Goal/problem: A fixed first-eight follow-up slice could hide registered tools,
  and speculative Scout work had no durable use or waste accounting.
- Change and why: Rank only applicable registered probes using lexical and
  sourced reference hints, widen a stagnant slice, cancel queued Scout after
  demand admission, and record its exact execution and terminal use category.
  This keeps search bounded and grants no new command or causal authority.
- Alternatives/failures: A new search tree and broad scans were rejected. The
  first Scout ledger counted only terminal attention, later found incomplete.
- Evidence/metrics: 147 focused runtime/investigator tests passed; scoped
  Pyright had 0 errors and Ruff checks passed. No diagnostic improvement was
  established by these tests.
- Next question: Does the actual mixed runtime surface useful alternatives
  sooner while keeping unused prefetch and false causal claims visible?
- Artifacts: Commit above; no private capture at this milestone.

## 2026-09-26 17:36 PDT | Candidate timing custody | `b83400541862f2254f7f836dce2c3da2ca2f6231`

- Goal/problem: A read-only application case failed after a second ranked
  process candidate was admitted. Its worker could start after the short
  model-decision deadline, but execution linking required an earlier start.
- Change and why: Frontier links now require admission within the decision
  deadline, a one-shot claim before execution, and the same frozen invocation.
  Queue time after admission no longer invalidates an otherwise bound run.
- Alternatives/failures: The first actual-model application case at `52b6b86`
  failed with a `ValueError` in candidate execution linking; no assessment was
  completed. The regression failed before the fix and passed after. A fresh
  same-objective case completed custody but stopped insufficient-observability
  with zero hypotheses; it did not diagnose the PDF viewer.
- Evidence/metrics: 21 focused candidate storage/frontier tests passed; the
  fresh actual-model case used 5 persisted probes and completed in 15.580 s
  of case time. No matched speed experiment or cause verification was done.
- Next question: Does this timing rule hold under repeated delayed starts and
  the full integrated gate without introducing a stale admission?
- Artifacts: Private original application log SHA-256
  `D7D343DE5C8AEF11C30625CC1B841097F20A5308CBBDE297018249208ABD70C9`;
  repair log SHA-256
  `6C94185AE575845634D1729AA2D989009BA3C8E73580ACE289EB6259BF67379D`;
  both under the private team directory, with separate case stores.

## 2026-09-26 17:51 PDT | Applied deep use and overlap | `dda0580938484e39dbd6b54b01b2dfea74ad4ba8`

- Goal/problem: The network case marked Scout's `core.resources` prefetch
  wasted although its evidence ID appeared in an applied deep response's
  considered set. A broad gate also exposed a concurrent-follow-up fixture
  without discovery metadata required by the registered-tool path.
- Change and why: Scout terminal accounting now reads durable applied deep
  consideration, and the fixture declares its real probes' output and resource
  metadata. This counts explicit past use even when later attention replaces
  the latest state, while preserving fast/deep overlap checks.
- Alternatives/failures: The original immutable network case still contains
  the narrow `wasted` ledger entry; it is historical failed accounting, not
  rewritten evidence. The first non-MCP run stopped at 542 passed, 3 skipped
  on the fixture failure. A red accounting test returned `wasted` before the
  correction and `used` after it.
- Evidence/metrics: 25 concurrent follow-up tests and the three focused
  correction checks passed; scoped Pyright reported 0 errors and Ruff passed.
  Independent read-only review of the original network case found one Scout
  evidence row explicitly considered by deep, but no diagnosis or assessment.
- Next question: Will the complete suite and integrated reference/evaluation
  changes preserve retrieval quality and truthful accounting?
- Artifacts: Commit above; private network log SHA-256
  `833684E340E2D6E55D2892EE4535903C223003166647257F348FB7D89E924B46`.

## 2026-09-26 18:07 PDT | Founder accepts higher capability direction | `dda0580938484e39dbd6b54b01b2dfea74ad4ba8`

- Goal/problem: The current three actual-model cases produced timely observations
  but no supported diagnosis. A narrow scan or a faster ranker alone would not
  establish the affected task, distinguish competing causes, or justify repair.
- Change and why: The founder accepted an extensible investigator direction:
  typed affected-task/outcome evidence, genuine distinguishing measurements,
  mechanism and rival checks, and complete matched trajectories before deciding
  whether Laya needs training. A remains integration/resource owner; B evaluates
  full trajectories, C reviews source-backed conditional mechanisms.
- Alternatives/failures: No rewrite, broad collector sweep, training, UI, repair
  execution, new lab fault, or cloud deployment was authorized. The existing
  B protocol has not yet run four genuine matched arms, and C's reviewed edges
  have not improved generic packet selection. Broad capability is a goal, not a
  present measured claim.
- Evidence/metrics: Independent review of the three A cases found zero supported
  diagnoses. One app case failed candidate linking; its repaired rerun completed
  with five probes but deep output hit its token limit. The network case exhausted
  its case budget. Founder acceptance and lane assignments were recorded in the
  private team board at 2026-09-27 01:08 UTC.
- Next question: Which stage actually limits diagnostic quality on independent
  network/browser and application/performance trajectories?
- Artifacts: A/B/C/D task IDs and writable contracts are in the private team
  board; private model logs are identified in earlier entries, not copied here.

## 2026-09-26 18:14 PDT | Bounded deep output recovery | `3eaad23ee05e1cc99e9b33675698073c44c407fd`

- Goal/problem: A fresh PDF performance case at `b834005` completed custody but
  Qwen's first structured deep answer ended with `done_reason=length` at the
  configured 1,200 output tokens; no hypotheses were admitted.
- Change and why: A confirmed completed length stop keeps the managed model
  lease, then deep advice retries once with a tighter JSON schema, identical
  admitted evidence and case binding, and the remaining deadline. Validation
  and unknown-cause treatment remain intact. Transport uncertainty still retires
  the owned service.
- Alternatives/failures: Raising all output limits would increase normal latency
  and resource use; accepting truncated JSON would weaken validation. The three
  new regression tests failed before the change. A full non-MCP gate first
  stopped at 1,060 passes on a store-free terminal fixture; the fixture now
  bypasses only persistence accounting. A later run stopped at 1,431 passes on
  a synthetic benchmark without registered discovery metadata; B corrected it.
- Evidence/metrics: 87 focused reasoning/inference/terminal tests passed;
  scoped Pyright 0, Ruff lint/format passed. B's strict latency-trial fixture
  fix was reviewed and cherry-picked as `1befd7db19816d78fc1b1e605e9877e8c838dacb`;
  its 14 tests pass. Actual-model recovery was still unverified at this milestone.
- Next question: Does the same real PDF objective produce a valid deep response
  within the managed deadline, and what causal evidence remains missing?
- Artifacts: Commits above; no private response content in Git.

## 2026-09-26 18:20 PDT | Explicit Scout comparison mode | `309ef096050a0f6d39692747cb3da1eacb541adb`

- Goal/problem: B's complete-trajectory evaluator needs the same policy with
  Scout on and off under matched tools and budgets.
- Change and why: Investigator and CLI expose a default-on Scout switch and
  propagate it into worker clones. This isolates one bounded prefetch variable
  without replacing the runtime or suppressing demand work.
- Alternatives/failures: A separate search tree or benchmark-only policy fork
  would diverge from production behavior. The toggle alone is no evidence of
  Scout benefit; B's runner and actual matched trajectories remain pending.
- Evidence/metrics: 45 focused CLI/baseline tests passed; scoped Pyright 0 and
  Ruff passed. CLI help exposes the no-prefetch switch.
- Next question: How often does prefetched evidence become useful earlier, and
  how much unused work does Scout add on independent cases?
- Artifacts: Commit above; B received the exact constructor/CLI interface.

## 2026-09-26 18:28 PDT | PDF model recovery check | `1befd7db19816d78fc1b1e605e9877e8c838dacb`

- Goal/problem: Verify that the prior PDF objective can complete with real
  local models after the deep-output and candidate-custody fixes.
- Change and why: Ran one fresh read-only case in a separate private database
  with the pinned warm Laya/Qwen profile. No source changed in this check.
- Alternatives/failures: The new run did not trigger the output-length retry,
  so it does not prove that recovery under the actual model. It reached no
  supported cause: four evidence/detail requests remained unsatisfied. The
  earlier failed and insufficient runs remain in history.
- Evidence/metrics: Exit 0; case completed `insufficient_observability` with
  seven persisted probes, two nondegraded Ollama reasoning results, three
  unresolved hypotheses, and no assessment. Case time 24.546 s; process time
  54.153 s includes startup/teardown. This was a functional case, not a
  matched speed experiment. A-owned model jobs and private listener were
  absent after completion; the shared experiment slot was released.
- Next question: Which requested observation and exact affected-task outcome
  are missing, and can registered target/window measurements distinguish the
  remaining rivals without overstating a cause?
- Artifacts: Private log under the team directory, SHA-256
  `6919A9C3FA6AE41B076DB1AA9013BAE5A2D299A90B3C6B177C03994888B9150B`.

## 2026-09-26 18:48 PDT | Ongoing episode-quality loop | `1befd7db19816d78fc1b1e605e9877e8c838dacb`

- Goal/problem: The founder clarified that the full observe, search,
  hypothesize, acquire, discriminate, verify behavior is the outcome, and the
  original eight-hour limit is a working checkpoint rather than a reason to
  abandon unverified capability.
- Change and why: A kept the sole dispatch/resource role, assigned B a frozen
  sequential visible-state matrix and held C's next retrieval change until
  independent labels exist. Integration gates and original resource permissions
  remain mandatory. This avoids adding reference edges with no observable test.
- Alternatives/failures: C's 14-case generic starts yielded 0 changed retrieval
  packets and unchanged 17/38 useful toy branch mapping; the review manifest
  adds source trust but not measured diagnostic benefit. B's first runnable
  14-case CPU pilot completed all cases insufficient-observability; 43/53
  eligible diagnostic tool opportunities were unrun, and model arms are unrun.
- Evidence/metrics: B's runner commit `e4a0f49aac58d4c639a5ba31f0256647e3f648bc`
  is ready for explicit integration review. Its full suite excluding one
  isolated-pass scheduler test passed 3,198/31 skipped; the excluded test passed
  alone, so the aggregate flake cause remains unknown.
- Next question: Can frozen sequential states expose two same-symptom causes
  and counterevidence to the policy, and what specific stage still fails?
- Artifacts: B and C private scorecards/hashes are referenced in the team
  board; no synthetic toy outcome is represented as a Windows result.

## 2026-09-26 19:06 PDT | Reported affected-task scope | `0c30248ff3052e6d0a111fa417da97f9a9b5e505`

- Goal/problem: An objective sentence alone did not durably distinguish the
  action the user says failed from measurements that actually verify it.
- Change and why: Added an optional versioned user report with task kind,
  action, target hint, expected result, and reported result. It is persisted
  explicitly unverified, redacted at intake, and passed to deep reasoning with
  a non-evidence caveat. Browser/network and application task kinds seed a
  bounded relevant registered probe set; an objective-only case retains its
  prior behavior. The hint never selects a process or grants probe authority.
- Alternatives/failures: Auto-parsing an exact target from arbitrary prose
  would risk false identity; a new executor is outside scope. The initial deep
  prompt added a null task field to old cases and made one tight reference fit
  test drop its Windows error reference. Conditional omission restored the old
  packet. A full gate also exposed a sequential-provider test expecting one
  call where the earlier bounded malformed-output retry now correctly makes
  two; its explicit count was updated after isolated red/green review.
- Evidence/metrics: 80 focused task/reasoning/sequential-provider/CLI tests
  passed; scoped Pyright 0, Ruff checks passed. No affected-task outcome was
  independently measured, and no causal capability gain is claimed.
- Next question: How will registered observations bind to this reported action
  and a validated target/window so diagnosis can be checked against the task?
- Artifacts: Commit above; no private user report in Git.

## 2026-09-26 19:12 PDT | Integrated evidence choices and causal guard | `3f04d15e68a2083821445e6353d1a263930dea56`

- Goal/problem: An advisory reasoner could persist a `supported` hypothesis after
  citing a real but noncausal observation. Later categorical observations did not
  automatically contest a prediction, even when a trusted exact fact disagreed.
- Change and why: The synchronous path now keeps model hypotheses unresolved or
  contested, with explicit advisory wording. A later exact, current-case observed
  probe fact can contest a prediction only after its issuance time and durable
  source revalidation. Matching or earlier facts do not contest it. No model
  status becomes an independent causal assessment.
- Alternatives/failures: The red integration tests first reproduced model-support
  promotion and missing counterevidence. One whole-suite run began before C's
  graph commits were integrated and saw a mixed in-memory/disk schema, failing
  after 725 tests; the isolated test passed at stable HEAD, so a final stable
  full gate remains required. The live PDF case still had no affected page-action
  measurement, three unresolved hypotheses, four unmet requests, and no finding.
- Evidence/metrics: At this SHA, 199 focused integration/assessment tests passed;
  four exact regression cases passed after the final assertion; scoped Pyright
  reported zero errors and Ruff lint/format passed. B's integrated frozen toy
  matrix has 14 cases and six evidence stages each; the deterministic public
  Investigator pilot completed 14/14 cases, all insufficient observability,
  with 43/53 eligible tool opportunities unrun and zero supported causal answers.
  Every model comparison arm remains unrun. C's reviewed graph has 25 active
  source-section reviews but no independently measured diagnostic gain.
- Next question: Can a runnable same-start episode acquire discriminating facts,
  update competing hypotheses, and identify the exact affected-task measurement
  that remains unavailable without a false cause claim?
- Artifacts: Private actual-model log SHA-256
  `6919A9C3FA6AE41B076DB1AA9013BAE5A2D299A90B3C6B177C03994888B9150B`;
  frozen sequential contract SHA-256
  `14a0d889ad0faeeb6c032c50161c893751dfaaf06d43fd63b345cbc04ddfd6aa`.

## 2026-09-26 19:13 PDT | Founder execution priority | retrospective

- Goal/problem: Coordination and broad planning were consuming time while the
  observed end-to-end cases still lacked a supported diagnosis.
- Change and why: Founder Desk relayed the founder's explicit priority to build
  the runnable observe, acquire, discriminate, and verify loop using the frozen
  cases. A retained runtime, integration, and resource ownership; B took the
  independent episode harness/score; C took the scoped retrieval-selector test.
  Handoffs are batched to concrete decisions and completed evidence.
- Alternatives/failures: C's first selector gate removed cross-domain references
  but independently scored reviewed-only final packets collapsed to identical
  sets in every distinct-truth within-domain pair (38/38), versus 23/38 before.
  A held that candidate unmerged; hiding scope leakage by relaxing product
  preconditions would invent applicability. Generic toy browser/document inputs
  lack exact product identities, so reviewed-edge coverage is genuinely limited.
- Evidence/metrics: B's independent frozen replay found reviewed-only relation
  changes on 22/31 discriminating stages before the gate and 8/31 after; false
  churn fell 11/39 to 6/39. These are retrieval responsiveness measures, not
  diagnosis accuracy. No new VM, model, GPU, fault, training, or cloud work was
  authorized by the priority change.
- Next question: Which runtime-selected action and exact missing measurement
  prevent a supported answer in the smallest paired episodes?
- Artifacts: Private C pre/post retrieval SHA-256
  `b08e675c1b1625352bfc2ece56daaece13b6bd5a43ccda26c0abd0fb1fed5877` /
  `87e64f8382649f54ec350642ad8fba6e5f7cd1c454d9b2af93abd90d72eb6768`;
  B's scorer and label hashes are recorded on the private team board.
