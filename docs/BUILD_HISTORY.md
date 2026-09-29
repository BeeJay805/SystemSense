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

## 2026-09-26 20:06 PDT | Typed need and case brief integration | `a646320060d2fe11fec9fff92f67841276e936ce`

- Goal/problem: Registered control observations, typed hypothesis test IDs, and
  cited deep context existed in separate paths, but the live investigator still
  closed cases with useful control probes unrun and could trim earlier cited
  evidence from the deep model view without a clear coverage signal.
- Change and why: A added one bounded registered same-category control follow-up
  (`d1de8bc`), reviewed/cherry-picked B's pure typed need resolver (`819fa50`,
  `65a1268`) and C's bounded cited brief assembler (`d00eb3e`), then wired both
  into the existing investigator admission and reasoning path. Typed IDs resolve
  against current registered capabilities; no prose mints a selector. The brief
  prioritizes citations and pending details and labels omitted, unavailable, and
  quality-limited required evidence in the deep request. The existing gate
  retains manifest, permission, budget, and slot authority. The scoped C
  source-selector candidate remains held unmerged after independent regression.
- Alternatives/failures: The first new integration assertion expected the typed
  probe to be the only execution; the loop correctly explored one additional
  registered probe, so the assertion now checks typed follow-up priority.
  An actual-model PDF case before these commits still had three unresolved
  hypotheses, four unmet requests, and no independent page-action measurement;
  no diagnosis is inferred. Model-view omission differs from source-side loss:
  the Wi-Fi collector currently retains at most 16 entries at its source cap.
  The brief cannot recover information never captured; no raw unlimited CLI
  capture, secret retention, or new ingestion authority was added.
- Evidence/metrics: 131 focused unit/integration tests passed at this revision;
  whole Pyright reported 0 errors, Ruff lint/format passed 579 files, and offline
  source/wheel build passed. The stable full non-MCP suite later passed 3,268,
  with 31 opt-in skips and seven expected failure-path warnings in 556.08 s.
  B's clean linked eight-case CPU replay completed 8/8: browser
  direct and external controls ran 4/4 versus 0/4 earlier, using 40 versus 32
  probes and 56 versus 36 deterministic calls. Final toy-world separation and
  causal answers did not improve. Two cases retained two compatible recipe
  variants each with the same labeled cause; battery wear would separate those
  variants but would not discriminate the root cause.
  Its zero typed hypothesis requests do not measure resolver benefit. No model
  or Windows fault was used in this replay.
- Next question: Will a final actual-model case preserve rival/counterevidence
  context and produce a valid requested follow-up under the same budget, and
  what exact affected-task observation still blocks a supported finding?
- Artifacts: B private post-integration replay manifest SHA-256
  `7B0E20919FB6E8F3B36D6BC25A4C72F26CDCF829B5A8A6B12201EEB77D7DD688`;
  private case logs and board remain outside Git.

## 2026-09-26 20:38 PDT | Final-code local model qualification attempt | `a646320060d2fe11fec9fff92f67841276e936ce`

- Goal/problem: Verify that the integrated investigator still runs actual local
  fast and deep providers, retains the changed evidence in Laya's choices, and
  applies deep advice while the fast lane remains available.
- Change and why: No product code changed. A ran one read-only browser task on
  the actual host and one opt-in synthetic counterevidence overlap check at the
  same SHA. After a concrete Qwen local-inference failure, A made one unchanged
  bounded repeat to determine whether concurrency worked under the same test
  contract. The independent foreground game/GPU load was left alone. No fault,
  repair, training, model edit, or cloud deployment occurred.
- Alternatives/failures: The ordinary browser case completed but had a one-item
  Laya rank, so it did not test meaningful competing choices or establish the
  reported browser failure. The first overlap attempt failed its valid
  concurrent-deep assertion: Qwen entered `call_LocalInferenceError` recovery,
  its deep mailbox expired at the case deadline, and no deep answer was applied.
  Laya did rank four relevant later-evidence retrievals, so the failure is not
  evidence that it missed the changed fact. The unchanged repeat passed; one
  pass does not erase the failure or qualify reliability. No test threshold or
  validator was relaxed.
- Evidence/metrics: Browser process 83.053 s including startup; eight probes,
  15 evidence records, two non-degraded Qwen calls, two unresolved hypotheses,
  three unmet requests, no assessment, Scout prefetch used, and explicit
  truncated view/detail scan limit. Its case ended insufficient observability.
  Failed overlap: 23.313 s cold setup, 45 s case deadline, seven Laya menus,
  16 distinct offered IDs, no applied deep. Passing overlap: 20.562 s cold
  setup, 17.313 s case, seven menus, 16 distinct IDs, four complete
  post-counter rankings while Qwen ran, and one applied deep result; it still
  ended with six unmet requests and no supported cause. The passing run's
  3.849 distinct offered IDs/s is below the 20 useful/s aspiration and does
  not count independently judged useful decisions. No matched speed comparison
  or real Windows diagnostic accuracy was measured. All A-owned Python/Ollama
  processes and the managed 11435 listener were absent after each run.
- Next question: Why did the first managed Qwen call fail under the shared host
  load, and can an independently measured affected browser/PDF action plus
  stable simultaneous inference distinguish cause from observation?
- Artifacts: Private browser log/DB SHA-256
  `F0F50303015739141DAEDE08322767F2F7A56840F74A73C6F0EBD03B3A496949` /
  `A2AA62B8A9D5D4AA55B8788989F5D707562354CF7C243C1A8F0B1B1FF55B91C4`;
  failed overlap log/DB
  `F884DC8D380B14BDDE24C273E00360DFCDFC9C86C9B7318D4D63DFBA36EED6E9` /
  `3DB0AEFDFF7EDE544C9EA338DB6D91E50080EA0391AF27F1F6DF94E9D77C8B9D`;
  passing overlap log/DB
  `8F4B8BB152502B20EC5A6EA8131C773CD18CF8DE6ACF675FC7FD534C91FCC4EF` /
  `CCC4E543B90CFA8DDEC48CCACB1107782117E15CEB7D81AF7DA4E3417319F04F`.

## 2026-09-26 20:47 PDT | Toy-world interpretation correction | retrospective

- Goal/problem: A's first interpretation of B's eight-case replay called two
  residual two-world cases distinct-cause ambiguities without checking whether
  the remaining worlds had different root labels.
- Change and why: B read the frozen policy-visible facts and evaluator-only
  labels for both cases. Each pair shares the same labeled root: the network
  pair is DNS configuration and the application pair is software rendering.
  The only distinguishing menu probe is battery wear, which marks the variant,
  not the cause. The benchmark and earlier history wording were corrected.
- Alternatives/failures: The earlier distinct-cause wording was wrong. It is
  preserved here as a documented interpretation failure, not a product or
  evaluator result. The unrun battery probe was registered but the five-probe
  budget was consumed by baseline and diagnostic observations. There is no
  separate admission row, so its admission custody remains unknown.
- Evidence/metrics: B's readback used the unchanged eight-case replay manifest
  SHA-256 `7B0E20919FB6E8F3B36D6BC25A4C72F26CDCF829B5A8A6B12201EEB77D7DD688`;
  no new test, model, or fault ran. The full eight-case suite still has zero
  hypotheses, assessments, or supported causal answers.
- Next question: Which independently observed affected-task outcome and
  competing-cause evidence would justify a causal assessment on real Windows?
- Artifacts: B's private B.md readback and frozen manifest; no evaluator-only
  truth or host case data was added to Git.

## 2026-09-26 21:01 PDT | Protected reasoning citations and task gap | `b83c186bbbae12eda6184329722839c1f85a176c`

- Goal/problem: The actual browser report lacked an explicit terminal statement
  that its user-reported affected action had no independently measured outcome.
  Separately, the new cited case brief could preserve support/counterevidence,
  only for downstream Ollama prompt fitting to evict protected context if every
  visible item was cited and the packet still exceeded model context.
- Change and why: A added a terminal affected-task gap statement (`59406be`).
  C wrote a red test against the full case-brief-to-Ollama-fit path (`4be5755`,
  cherry-picked as `ba7f3f2`). A then made prompt fit defer only unprotected
  observations; if none can be deferred, it raises a bounded local context
  error rather than silently discarding a cited fact and earlier rival. The
  existing provider degrades explicitly on that error, retaining validation.
- Alternatives/failures: The red test showed the old fit returned only the
  counterevidence ID and dropped the previous hypothesis with its missing
  support ID. Trimming the protected citation would make a plausible but
  invalid comparison; unlimited prompt growth exceeds the pinned model budget.
  This fix may abstain more often on oversized all-cited packets, an honest
  capacity limit. The earlier actual-model runs predate the fix and cannot
  establish its live reliability. No model output validator or test was weakened.
- Evidence/metrics: Terminal gap test failed before and passed after the change;
  protected-citation test failed before and passed after. The focused provider
  and investigator set passed 105 tests; scoped Pyright reported zero errors,
  Ruff lint passed, and formatting was applied. Stable whole-suite and live
  model gates for this later revision remain pending. No GPU/VM/fault/training
  resource was used for this fix.
- Next question: On a final integrated model run, do protected citations fit
  without degradation, and where does independently measured affected-task
  evidence remain unavailable?
- Artifacts: C's test commit and A source commits above; failure transcript is
  in the task, with no raw host prompt or private data committed.

## 2026-09-26 21:11 PDT | Source-blind toy rivals and cause-level scoring | `44414d2995069f02eafe7b798ef3e80377fc4ffa`

- Goal/problem: The eight-case toy replay had two recipe variants in two cases,
  and the deterministic provider had produced no hypotheses. Counting recipes
  as competing causes overstated uncertainty; a provider that sees hidden
  labels would overstate causal performance.
- Change and why: A explicitly reviewed and integrated B's independent
  cause-equivalence scorer (`e4aa6dc` to `39fa94b`) and source-blind fixed-rival
  provider/runner (`49e6d2d` to `44414d2`). The provider sees only registered
  policy-visible probe IDs and emits two unresolved family rivals per case;
  the scorer reads withheld labels only after each run.
- Alternatives/failures: The earlier distinct-cause interpretation was
  corrected at the preceding retrospective. All declared distinguishing toy
  probes ran, but the provider never revised or contested a hypothesis and
  never assessed a cause. No extra incidental battery probe would verify an
  affected task or change these same-cause labels. The runner links only 24/40
  executions to decision snapshots and queries two separate admission tables;
  the missing rows do not prove a runtime bypass, so full replay custody is
  still unproved.
- Evidence/metrics: B's private eight-case replay verified its manifest,
  completed 8/8 with 40 read-only toy executions, 8/40 incidental probes unrun,
  16 unresolved final hypotheses, zero revisions/contests, zero assessments,
  and 4/4 designated counterevidence-stage probes observed. The independent
  evaluator found one compatible toy cause per case. B ran 13 focused tests,
  whole Pyright/Ruff, and offline wheel; after integration A ran 74 focused
  benchmark/investigator tests, whole Pyright with zero errors, and Ruff
  lint/format with 585 files formatted. The full non-MCP gate is in progress.
- Next question: What independently bound affected-task result and rival
  evidence can support a real adjudication, and what exact custody linkage is
  needed for the synchronous replay path?
- Artifacts: Private B-010 manifest SHA-256
  `826E79C32CE9B7AFC22351F9513308AC032D2250FD14F233CAFD6E5C97B4C00B`;
  cause score SHA-256
  `7C2C6F37F1307912FFAF8D0EEAD2BCAE4ED6342F19411463AB19CCF831162E74`;
  evaluator-only labels and case databases remain outside Git.

## 2026-09-26 21:29 PDT | Later-code live overlap and combined gate | `44414d2995069f02eafe7b798ef3e80377fc4ffa`

- Goal/problem: The cited prompt-fit correction and fixed-rival integration
  postdated the last actual-model run. A needed a later-code functional check
  and a combined gate without treating an earlier smoke as current proof.
- Change and why: A reserved the single model/GPU slot, checked for owned
  workers/listener, ran one opt-in read-only synthetic counterevidence overlap
  with actual pinned Laya and local Qwen, then verified zero A-owned workers
  and managed listeners before releasing the slot. No host fault or training
  occurred. The trial exercised the cited downstream context path without
  weakening deep-output validation.
- Alternatives/failures: The `a646320` unchanged overlap pair remains one pass
  and one failure, so this later pass does not qualify reliability. The first
  full non-MCP run at `44414d2` failed one durable scheduler reservation test
  after 3,275 passes and 31 opt-in skips; that test passed ten isolated repeats
  and all 66 scheduler-module tests passed. The full failure remains recorded
  while a final integrated gate is pending. No matched speed experiment ran.
- Evidence/metrics: Later-code trial passed once, case 13.625 s after 27.500 s
  cold setup; seven Laya menus offered 16 distinct IDs, one complete ranking
  saw later counterevidence while Qwen was active, one valid deep result was
  applied, and two read-only probes were admitted. It stopped with six unmet
  requests and no cause. Offered-ID rate was 5.993 per active ranking second,
  below the 20 useful/s target and not itself a useful-choice measure. Whole
  Pyright reported zero errors; Ruff lint/format passed at this code revision.
- Next question: Does the final integrated non-MCP gate pass, and can an
  independently bound affected-task result turn rival evidence into a
  supported, counterevidence-aware assessment?
- Artifacts: Private trial log SHA-256
  `DB1C1F4834933C8A6A747053E220C69AF7D1AFB50EDAB7BEFD77DB738F92C2CF`;
  case DB SHA-256
  `6CE10E0594054E1B3E41277D486651808754C5EA974B928456A61B211AC727ED`.
  Raw host/model output remains outside Git.

## 2026-09-26 21:43 PDT | Selection-path custody and clean combined gate | `536ebb496edcc03f05eb6a2c1b6e625848359085`

- Goal/problem: The first toy readback showed only 24 of 40 execution IDs
  linked to decision snapshots and no adaptive admission rows. It could not
  distinguish a baseline or trusted deep batch from an unknown path. The first
  combined gate at `44414d2` also had one scheduler test failure.
- Change and why: A reviewed and integrated B's read-only durable
  selection-path classifier (`28210f1` to `536ebb4`) without changing runtime
  authority or the frozen replay. It checks case-bound execution, step,
  snapshot, and admission links and labels any conflict/absence unknown. A
  reran the full non-MCP gate on the integrated revision, then whole type,
  lint, format, and offline package checks.
- Alternatives/failures: Classifying every unlinked execution as an admission
  bypass was unsupported. The classifier finds eight initial baseline and
  eight trusted deep-requested batch paths where the earlier readback counted
  only fast snapshot links. It establishes selection paths only; no adaptive
  admission authority or causal answer is inferred. The earlier scheduler
  failure remains recorded, even though its ten isolated repeats, 66-test
  module, and this full rerun passed. The opt-in live model test was separate.
- Evidence/metrics: B's fresh eight-case private replay verified and classified
  8 baseline, 8 trusted deep batch, 24 fast snapshot-linked, zero adaptive,
  and zero unknown executions. A's integrated focused set passed 75. The
  non-MCP suite passed 3,280 with 31 opt-in skips and seven warning-path
  notices in 406.46 s. Whole Pyright reported zero errors, Ruff lint/format
  passed for 587 files, and offline sdist/wheel built. No matched speed
  experiment, Windows fault, or affected-task verification ran.
- Next question: Can separately acquired, exactly bound affected-task results
  and preserved rival hypotheses support a real causal adjudication without
  broadening observation authority?
- Artifacts: B's private fresh replay manifest SHA-256
  `B26367EA60E1C0B3885F73614BA20E55006663EFF98B892E14628BB5FBCAAD4D`;
  selection-path readback SHA-256
  `F4E8F3DB6F081E06F6037378C7DC73BE824BB368A67BD6EF7001509DAB01D766`;
  A's private non-MCP test log SHA-256
  `9BC8C2F3B593D3604E4E55932DEAB81BD8CD133E9DF2FE3A4F83C6EAF149182F`.

## 2026-09-26 22:05 PDT | PDF witness chronology, host-only | `07b731c3442aeef474d1f08ba8f2c5727538c579`

- Goal/problem: A founder-priority affected-task result needs exact action,
  target, window, and source binding. The existing PDF PageDown witness had
  pinned viewer/document identity but its journey binder accepted several
  impossible visual time sequences. A fresh generic product verifier would
  have claimed trust not carried by current case exports.
- Change and why: B hardened the existing `bind_pdf_journey` chronology and
  stable-marker checks (`5b63558`), reviewed and integrated by A as `07b731c`.
  It rejects out-of-order wall/monotonic captures, action outside samples,
  invalid frame/fraction quality, inconsistent latency bounds, and replayed
  visual timing between trials. The callable binder contract stayed intact.
- Alternatives/failures: B did not add a report-only product verifier. Case
  export v1 lacks authenticated visual-action time linkage, so this binder
  remains a host consistency witness, not affected-task product proof. No
  active PageDown, VM, fault, or model trial ran.
- Evidence/metrics: B red tests reproduced action-before-baseline and replay
  acceptance before the fix. After A integration, 42 PDF witness tests passed;
  scoped Pyright had zero errors, Ruff lint/format passed. No measured
  diagnostic accuracy or speed result follows.
- Next question: Which trusted persisted producer can bind a real affected
  task action/result to case identity and time without relying on report text?
- Artifacts: B and A commits above; synthetic tests only, no host witness file.

## 2026-09-26 22:05 PDT | Custodied rival continuity | `4b7b5e1c745eff8d1dc6c2c78b1ab6b1a5371abe`

- Goal/problem: A valid second deep response could replace all prior
  hypotheses, silently dropping a cited competing explanation. A first red
  integration case reproduced this: only the newer rival survived. Concurrent
  deep merging also risked overwriting prior contradictory citations and
  coordinator-stamped categorical prediction times.
- Change and why: C built a pure bounded transition (`8298ed2`), then fixed
  prediction continuity after A review (`d72dfb0`). A reviewed/cherry-picked
  both as `3c4c702` and `7577a52`, then wired both synchronous and concurrent
  deep paths at `4b7b5e1`. The coordinator checks cited IDs against stored
  current-case evidence or previously validated historical excerpts. It
  retains omitted rivals, exact contradictions, and original prediction
  boundaries; unavailable citations, unseen request IDs, rejected semantic
  rewrites, and 16-item cap losses stay explicit. Every retained hypothesis
  remains advisory/unresolved or contested.
- Alternatives/failures: C's first helper draft reset a repeated prediction's
  observation boundary; A caught it during commit review and C added a
  regression/fix before integration. An existing historical-citation test
  required explicit same-ID revisions that carry all older citations, so
  blanket rejection would have lost valid counterevidence. The final helper
  accepts that narrow revision without transferring citation roles silently.
- Evidence/metrics: A's integration test failed before wiring and passed
  afterward. The existing historical contradiction and timed-prediction tests
  passed; 102 focused deep/investigator/reasoning tests passed with one opt-in
  actual-model skip. Scoped Pyright reported zero errors and Ruff lint/format
  passed. The prior clean whole-suite and live-model results predate this code;
  final combined verification remains pending.
- Next question: Does the integrated whole suite remain clean, and can a
  trusted independent affected-task result support adjudication of these
  preserved rivals in a real consented episode?
- Artifacts: Commits above and focused test transcripts in the task; no
  private host evidence or model prompt was committed.

## 2026-09-26 22:10 PDT | Historical citation custody correction | retrospective | `3f5982f6a11ce5802c4e792410f09f0b58237ec5`

- Goal/problem: The initial A wiring at `4b7b5e1` treated an historical
  citation as custodied only while an excerpt remained in the current or last
  assessed bounded context. Synchronous reasoning can replace that context,
  so a linked, persisted historical observation could be falsely marked
  unavailable and its earlier rival silently removed.
- Change and why: B independently reviewed the integrated diff and supplied
  a red regression (`65bd3b9`, cherry-picked as `bd9c5cc`). A changed the
  custody check to read the typed stored record/source and require ownership
  by the current case or one of the case's durable historical links. The
  compact request no longer determines whether a persisted linked citation
  exists; it still determines whether that citation was shown this turn.
- Alternatives/failures: The first A implementation was incomplete; its
  focused 102-test pass did not cover a second turn after historical excerpt
  eviction. Accepting any cross-case evidence row would be too broad. The
  repaired check uses the case's preselected historical owner IDs and verifies
  stored evidence, case, and source identities; arbitrary unlinked rows stay
  unavailable. It does not promote historical reference text to causal proof.
- Evidence/metrics: B's test failed on the initial A integration with the
  second transition returning zero hypotheses; it passed after the fix with
  the rival retained and marked unshown. The focused deep/investigator suite
  passed 103 with one opt-in live skip; scoped Pyright reported zero errors and
  Ruff lint/format passed. The whole combined gate is still pending for this
  revision. No model/GPU/VM/fault/training resource was used.
- Next question: Will the final combined gate and an independent affected-task
  result support a real cause comparison with this custody rule?
- Artifacts: B red-test commit, A fix commit above, and task test transcripts;
  synthetic SQLite fixtures only.

## 2026-09-26 22:24 PDT | Assessed fact-page retention | retrospective | `1f858cc`

- Goal/problem: The combined non-MCP gate at `2c053bc` found one regression
  after 3,310 passes. A model citation to an unpersisted synthetic record was
  correctly rejected, but the same turn also discarded a fact page already
  presented under that evidence ID when attention moved to another page.
- Change and why: `_retain_assessed` now carries previously presented facts
  for a matching immutable evidence ID even if no advisory hypothesis survived
  citation custody. It does not admit the rejected hypothesis or treat a page
  merge as cause proof.
- Alternatives/failures: The earlier rule anchored pages only through retained
  hypothesis citations, coupling two separate concerns. Re-running the case
  alone reproduced the failure. Broadly accepting the unpersisted citation
  would have weakened the custody rule and was rejected.
- Evidence/metrics: The formerly failing case and the focused deep/loop/
  progression group passed 70 tests at `9cd8393`. The full non-MCP gate at
  that revision passed 3,311 with 31 opt-in skips and seven warning-path
  notices in 411.71 seconds. The final `1f858cc` amendment changed formatting
  only; whole Pyright reported zero errors/warnings, Ruff lint and 590-file
  format check passed, and offline sdist/wheel build passed.
- Next question: Can an independently custodied Windows task result test the
  rival loop beyond this clean software gate?
- Artifacts: Private failed suite log SHA-256
  `7171BD012A2FE61EAECCB398B9B2B14B24CDA638930FDB898160D6C785CB88B3`;
  passing suite log SHA-256
  `65B9E6D2424B42F1BA0976A9D230137CACAF7CF9BEB857B61E8D8153CCB0FDCD`;
  code commit `1f858cc`; no private capture in Git.

## 2026-09-26 22:45 PDT | Final-code local-provider and VM access checks | `1f858cc`

- Goal/problem: Exercise integrated local providers at the final code revision
  and test whether the named disposable guest can enter a valid pilot without
  inventing an endpoint or weaker outcome label.
- Change and why: No product code changed. A ran a fresh read-only browser/
  network CLI case with the warm local profile, then the existing opt-in
  counterevidence overlap test. A started only the named VM, inspected its
  normal sign-in screen and read-only qualification report, then saved it with
  its network cable off. The guest needs a known credential or normal recovery
  answer before an affected-route baseline can be captured.
- Alternatives/failures: The ordinary case used actual Qwen but only
  keyword-baseline fast turns; it is not evidence of Laya choices. Its advisory
  summary called this Windows 11 Home host "Windows 10" despite the host
  caption, a false factual claim that remains a miss. A blank guest-password
  attempt failed; no credential guessing or offline account bypass followed.
  The existing affected-task binder also requires CONNECT/502 custody that
  the previously approved closed guest port `127.0.0.1:9` cannot supply.
- Evidence/metrics: The ordinary case captured seven read-only probes, one
  used Scout prefetch, two unresolved hypotheses, two unmet requests, and no
  assessment/cause. One Qwen response was accepted and another degraded. The
  synthetic overlap check passed 2 tests: case 11.750 seconds after 15.609
  seconds of cold setup, seven Laya menus/16 distinct offered IDs, complete
  post-counter rankings while Qwen was active, one applied deep result, two
  admitted probes, six unmet requests, no cause. This is a functional check,
  not a matched speed experiment or useful-choice score. VM read-only
  preflight returned `can_begin_episode=false` with guest login, clean reset,
  and independent oracle unverified; GuestInfo remained zero users. No fault,
  repair, training, or network adapter change occurred. A-owned model jobs,
  listener, and running VM were zero after the checks.
- Next question: Can the named guest be entered by its normal account path,
  and can a controlled origin plus a fault/outcome protocol with matching
  receipts be qualified before a real Windows cause comparison?
- Artifacts: Private ordinary log SHA-256
  `1669BAE50A9A67E89806242309B52AA91BDA0B8DE7F56FBE84C7985347D4BDDC`
  and DB SHA-256 `B6E1BD209AA9E248075F6678AF8A4321090F799D64DAFB78621807283BD53504`;
  overlap log SHA-256
  `10869C63DDA25C553EB336E509E96D36D6301B0CF7E308932C1DED37D2953E39`
  and DB SHA-256 `BF7D81439CF64A38BEDA90D43D1DF0FA5509AFBDA05DDED65F9E7D6D0B63C6E1`;
  private VM sign-in screenshot SHA-256
  `4FF824D276240C514CEEC1C51046BC5CCFF27E257FA9F6A4B9D9B7F621B38C56`.

## 2026-09-26 23:08 PDT | Distinct OS release evidence | `4a26448`

- Goal/problem: The final-code local model's "Windows 10" summary came from
  ambiguous `core.system` evidence: the worker said `Windows 10.0.26200`
  while that value was the kernel/build version and the host product release
  was Windows 11.
- Change and why: `SystemIdentity` now stores the Python-reported OS release
  separately from kernel version, the existing registry advertises the new
  fact path, and the worker summary labels both roles explicitly. An absent
  release stays absent rather than being inferred from the kernel string.
- Alternatives/failures: Prompting the model alone would not correct the
  ambiguous source. Hardcoding Windows 11 from a numeric build would confuse
  product identity with version mapping. The first red test failed because
  `os_release` did not exist; the source and worker regression turned green.
  This source fix cannot guarantee that a future model never misstates a fact.
- Evidence/metrics: 33 focused tests passed with one opt-in live skip; the
  opt-in live Windows core test passed separately. This host read back
  `os_release=11`, `os_version=10.0.26200`. The whole non-MCP gate passed
  3,311/31 opt-in skipped/seven warning-path notices in 450.16 seconds;
  whole Pyright reported zero errors/warnings, Ruff lint/590-file format and
  offline sdist/wheel passed. One same-objective read-only local-model run
  showed the clarified `Windows 11 (kernel 10.0.26200)` source and did not
  repeat the OS mislabel, but ended with no assessment and three unmet
  requests. One Qwen deep result applied; ten later tasks failed closed at
  prompt fit because protected cited evidence exceeded the 16k context.
  These are reliability misses, not ten invalid generated answers. No matched
  speed or diagnostic-quality improvement is inferred from two different
  runs.
- Next question: Can protected cited context be presented within the owned
  model budget, and can duplicate unfit deep tasks be suppressed until the
  evidence basis changes without dropping rival support?
- Artifacts: Code/test commit `4a26448`; passing suite log SHA-256
  `D29883670BDBA793E1F56DF62421BCA05710C9103683B81AA3CAFCD1C9808007`;
  private changed-code model log SHA-256
  `EF773E36C908CE387E436E4342E11B35CF39FBA71A8642B17F692AC6881C2FA4`
  and DB SHA-256 `837E31007C45FA0C71813B15F31B699E8E71D3FF62FE186CFEDF8610D428F0E4`.
  No private host capture entered Git.

## 2026-09-26 23:53 PDT | Integrated toy reviewer and desktop candidate | `922d65b`

- Goal/problem: Preserve trustworthy comparison bookkeeping while giving the
  existing read-only investigator a local Windows user interface.
- Change and why: Explicitly reviewed and integrated B's frozen 14-case
  trajectory runner and same-state reviewer ordering, then the isolated
  Electron desktop client. Concurrent probe completion order remains raw
  evidence; reviewer credit now follows the frozen offered menu for same-state
  choices. The desktop main process owns the local cookie and CSRF tokens,
  while a sandboxed renderer exposes only fixed case actions.
- Alternatives/failures: B retracted an earlier same-code replay claim after
  finding different runner hashes. Two corrected exact-revision replays still
  differ in raw execution order and elapsed time. The first A desktop format
  check failed on 24 contributed files; applying the existing formatter made
  it pass without a semantic code change. The installer is unsigned and has
  not been installed on a clean machine. Optional model dependencies are not
  bundled, so desktop diagnosis quality is unqualified.
- Evidence/metrics: Two B exact-source CPU replays each completed 14/14 toy
  deterministic cases, 26 useful/26 wasted/four unknown effects, with 14/14
  agreement on selected probes, useful counts, final compatible-cause labels,
  and cause-reducing credit; raw execution order differed in 11/14 and actual
  first-useful time in 8/14. Forty-two model cells were unavailable and no
  four-arm pair completed. A integrated ten focused benchmark tests passed.
  On A integrated Python code, npm unit seven, desktop/backend end-to-end ten,
  separate packaged-executable launch one, TypeScript typecheck, ESLint,
  Prettier check, PyInstaller backend build, and NSIS installer build passed.
  No real fault, model-mediated cause, or measured speed gain follows.
- Next question: Can exact cited evidence fit the configured local model
  budget, then produce a supported and independently bound affected-task
  result on the predeclared eight-case gate? VM qualification also awaits
  normal guest login and a nonce-bound 204 origin.
- Artifacts: B source commits `3f6f8cf`, `8357a79`, `2f67cb4`, `f02e89e`,
  `5b2ad00` integrated as A `93d8c87` through `282771f`; UI source commits
  `b2d82a7`, `0304bfc` integrated as A `fbdd66e`, `922d65b`. B private
  exact-revision replay manifests SHA-256
  `7AE4345ED4CEA34C00001646FCA9458F76AF4C29E4B02D6DCB53DE3DD64D561B`
  and `C48B4455EE882AF582DEC79D6A6B4ABC946649D2D9A4D9720C491F6DE1C8AB22`.
  Ignored unsigned installer SHA-256
  `04A2DF59EB83992D02B76554638AFB3E589D567D3B3CA4752CB73C2B5C716C53`;
  runnable bundled executable SHA-256
  `630D1A4DA889B3984655C11363547BBCACA1B364A8FD771A6B598BD8DED4D40A`.
  Private case data and UI screenshots stay outside Git.

## 2026-09-27 00:15 PDT | Bounded protected-context recovery | `d449429` plus profile change

- Goal/problem: One actual Qwen result applied, then ten distinct later deep
  requests failed before inference because cited observation excerpts and the
  response schema exceeded the opt-in local profile's context admission.
- Change and why: B independently replayed the frozen requests without a
  model call. The opt-in warm development profile now requests 32,768 context
  tokens while retaining its 1,200 output reserve, exact local model pin,
  conservative byte-count check and host GPU admission. Protected citations
  and validation are unchanged. C's independently reviewed game-only
  reference gate also integrated at `d449429` to remove unrelated frame-time
  guidance from generic browser/document focus.
- Alternatives/failures: At the original 16,384 context, 10/10 frozen later
  requests rejected even after optional catalogs and references were removed;
  all request/basis hashes differed, so identical retry suppression would not
  solve this run. Recursive schema title/description removal saved only 630
  counted units per request and could remove model guidance. A Qwen3.5
  matching tokenizer is not locally pinned; available Qwen3/Qwen3.8 tokenizer
  artifacts are not assumed equivalent. Fact-level exact source excerpts with
  durable originals remain a design question. A larger context can increase
  memory use and does not make the cause evident.
- Evidence/metrics: Original input capacity was 15,184 counted units after
  output reserve; the ten final protected prompts needed 18,253-23,360.
  B's offline exact-request sensitivity admitted 10/10 at 32,768 context,
  with minimum headroom only 64 units. One fresh isolated 32k actual-model
  read-only browser run at code `d449429` exited zero and used nine registered
  probes; four Qwen results applied, one mailbox task cancelled, no prompt-fit
  rejection, three unresolved hypotheses, no assessment, budget exhausted.
  Six Laya catalog-attention events and 16 keyword-baseline fast calls were
  recorded; this was not a matched policy or speed comparison. The shared
  model slot was released after no A-owned Python/Ollama job or listener 11435
  remained. C's reviewed-only game-scope candidate removed 14 unrelated toy
  packet changes, with final distinct-root collisions unchanged at 23/38;
  20 integrated focused knowledge tests passed. No real fault was diagnosed.
- Next question: Can an exact deployed tokenizer and bounded sourced fact
  presentation create reliable headroom without dropping counterevidence,
  and can the investigator link an affected-task result to cited rival
  adjudication before supporting a cause?
- Artifacts: B private aggregate SHA-256
  `D1E59B156C59D8438D8C2F96E2C7CE569FF119AC852CAAACDB698D407D4FE74D`,
  budget sensitivity SHA-256
  `75A82609927A08A679ED33D30D429682FBF47CD44FE756586FB5AAB3D0938EBB`;
  A private 32k profile SHA-256
  `0A9DD82BF16B7BB9B7DE4C9EB1345A6053980F192436B70CDABD2B53A0A16DE0`,
  private CLI log SHA-256
  `08C7A6E9C3507AF6A4703E38EC6B11C7B34E1181EE946982B78E1DEDCB02EF15`,
  case DB SHA-256
  `6E045D197B9A721469E58E3AE9103DAD631F795EB99A0D492109A70A0F744030`.
  Only counts and hashes enter Git.

## 2026-09-27 00:44 PDT | Readback gate, exact details, and focused UI | `e32e540`/`fba0a25`

- Goal/problem: Distinguish delivered model advice from an independently
  supported browser cause, preserve a newly accepted exact detail request,
  and integrate the founder's sparse desktop visual direction.
- Change and why: B's saved-case gate readback reports source-visible
  citations and unknown independent correctness without assigning toy truth
  to a host case. C independently confirmed the user report lacks exact page
  target and expected outcome. A reproduced one fifth detail request dropping
  behind four pending requests, then expanded the existing durable queue to
  16, kept newer requests at overflow, and reported the older omission count.
  The UI task's charcoal/mint layout and fixture-viewport follow-up were
  reviewed and integrated without changing the native backend authority.
- Alternatives/failures: A combined suite initially failed one valid test
  after 2,935 passes because it still asserted the old 16k development
  profile; the assertion was updated to the measured bounded 32k profile and
  a second full gate passed. The first D-017 desktop end-to-end run used the
  previous renderer bundle: five UI tests failed on stale controls. Rebuilding
  Vite from the integrated commit made all 13 active tests pass. C found no
  duplicate summaries or equal observed/capture times among 68 frozen source
  excerpts; a case-brief-only lossless compactor would save zero bytes, so no
  speculative truncation was added. The 16-item detail queue can still
  overflow and then reports a limitation instead of silently losing it.
- Evidence/metrics: At `29a25d9`, the stable non-MCP suite passed 3,327 with
  31 opt-in skips and seven expected warning-path notices in 447.49 seconds.
  After `e32e540`, 50 focused two-brain/readback tests passed; the final
  combined non-MCP gate passed 3,332/31 opt-in skipped/seven expected warning
  notices in 420.77 seconds. Whole Pyright reported zero errors/warnings,
  Ruff lint/format and offline sdist/wheel build passed. B's private 32k readback found
  four applied Qwen responses, 13/13 source-visible support/contradiction
  citation occurrences, three unresolved hypotheses and no assessment.
  Eight detail keys were three completed, four pending, one formerly lost.
  The final UI source passed seven unit, 13 active end-to-end, one separate
  packaged executable, TypeScript/Vite build, ESLint and Prettier. Native
  normal/150% fixture views were inspected. No real cause was verified.
- Next question: Can an exact specified affected task and independent result
  test the retained rivals in the consented VM, and does the repaired detail
  queue help without exceeding protected context? Guest login, a nonce-bound
  204 origin and a coherent CONNECT/502 fault receipt remain pilot gates.
- Artifacts: B readback commits `4866407`, `26527f8` integrated as A
  `94b70ae`, `fba0a25`; private corrected 32k aggregate SHA-256
  `A72322291BCA75330A066594594F43827199E4FF7CE3F6D0EB1C1D8236C4FC46`.
  UI commits `b5814c9`, `e939c52` integrated as A `1e9daab`, `f62085b`;
  ignored final unsigned installer SHA-256
  `AFD62129737B599C913AE9EFE4F31DA5CA925BDE660B6E185F4D4EA7C5507AB7`
  preceded the runtime detail fix. The final rebuilt unsigned installer
  SHA-256 is `4F6CD60EF4096C4C208D5CB2EC66217C635763C2E5897CE567C1BFA26012F4CC`
  (132,368,432 bytes); bundled executable SHA-256
  `E45AAA30BBECD550A4C6A0CFC44B0D6A4CDE43DD904F4DA2FCA411847E7C23A9`.
  Passing final suite log SHA-256
  `FEE7360BF485F95BB471C6F85BA2642C549413F97421D8113AC67314E499BF01`;
  private backend build log SHA-256
  `E71CBD9DE9FEE88C765930022AF98513A1ACE54760B01B8F149CBBDDEFDC7A94`.
  Private screenshots, logs, and case data remain outside Git.

## 2026-09-27 01:43 PDT | Alternate local search policy seam | `38a3909`

- Goal/problem: Compare the existing Laya-led frontier against a real local-deep search policy on the same offered state. The prior deep-only benchmark arm had no actual provider and could have accepted a declared mode without a deep ranker.
- Change and why: A added an explicit comparison-only v4 factory. One owned, digest-pinned local Qwen client now serves the existing probe-decision, mixed-frontier ranking, and reasoning interfaces. The frontier ranker receives the same source-bound frozen request, allows only a complete offered-ID permutation and considered-ID set, and visibly abstains on invalid, unfit, or late advice. Its turn cap is 20 seconds within the original case/session deadline; default routing and Laya's short turns are unchanged. B received the exact interface for independent paired-runner admission.
- Alternatives/failures: A first drafted a keyword-baseline decision plus deep frontier, then rejected it because keyword advice could make early probe choices and falsely label the search policy deep-only. A changed the factory to put probe advice on the same owned Qwen client. The first local test command accidentally used the global Python 3.11 without pytest/Pyright/Ruff; the worktree's Python 3.12 virtual environment ran the actual gates. No local-model comparison or VM fault was executed at this milestone. B's fresh-case inspection found remaining decision budget can drift even under equal frozen initial limits; an artificial clock seam was deferred so runtime behavior remains observable.
- Evidence/metrics: At `38a3909`, 132 focused decision/frontier/profile/PDF-target tests and 34 adjacent storage/investigator tests passed. Scoped Pyright reported zero errors/warnings, Ruff lint and format and Git diff checks passed. These are implementation gates, not root-cause accuracy or speed evidence.
- Next question: Can B's independent runner enforce actual provider, full menu, budget, and affected-task parity across four arms, and does the deep-only policy reach useful evidence and resolve rivals without false cause claims?
- Artifacts: Code commit `38a3909`. B's CPU-only eight-case freeze at `2e4c251` has private manifest SHA-256 `27368D7C519B3AE564B1CD718E5741F5BAE077DBCD19806C59CF282CBEB78102` and frozen protocol digest `49eb95a6253a7f567c9843865211040773319fa5a5ce582040886fa4e14cf055`; eight deterministic cells completed, 24 model cells unavailable, zero pairs. C verified its custody without treating private toy labels as policy-visible. Private case data remains outside Git.

## 2026-09-27 01:53 PDT | First alternate-policy execution miss | `840596f`

- Goal/problem: Exercise the integrated four-arm local search comparison on an existing frozen network/browser toy case and check whether model alternatives actually choose on the mixed frontier.
- Change and why: A integrated B's `2e4c251`/`949e880`/`4346f34` as `03ebf79`/`856f3c1`/`840596f`, preserving raw provider events, state calls, first-request content and budget distinctions, and an explicit unbound affected-task result. A used one shared model slot, the pinned warm v4 profile and real host lease, and separate private case databases for one four-arm `toy-network-002` run. B independently read the immutable result; C received only the predeclared blinded review packet.
- Alternatives/failures: The private first driver invocation failed before a case because its outside-Git path lacked the repository import path; A preserved that log, fixed the driver path, and ran once. All four cells then completed, but **none exercised the intended frontier search policy**. Deep-only's Ollama probe advice degraded to keyword fallback; mixed arms made keyword fast choices with no actual Laya decision/frontier call. A held the second planned model comparison pending a CPU-only realized-policy gate. The toy affected page/expected outcome is unbound, first-request content and remaining budget differ, and zero supported cause assessments exist. Do not treat completed cells or elapsed times as paired policy performance.
- Evidence/metrics: Combined focused gate 156 passed, scoped Pyright zero, Ruff lint and diff check. Artifact verifier on A's exact checkout: integrity true, four planned/four complete/zero failed; frozen toy effect accounting per arm one useful, three wasted, one missed opportunity. Wall times 0.250/27.297/9.906/10.047 seconds for deterministic/deep-only/mixed Scout-off/mixed Scout-on. Zero local-deep frontier, zero Laya fast/frontier ranks. Resource release confirmed no A-owned Python/Ollama job and no managed listener `11435`; unrelated GPU work untouched. Verification from B's separate checkout false-rejected the raw runner hash due Windows line-ending differences, so A's exact checkout is the artifact verifier and that portability limitation remains recorded.
- Next question: Can the frozen fixtures reach the **existing** event/mixed frontier with meaningful alternatives while keeping their input contract, and can the evaluator reject a model arm that completed through fallback without its named search policy? An independently bound affected-task outcome still requires a new consented pilot case.
- Artifacts: Private four-arm manifest SHA-256 `5966051A9FCA779C3C881B38279AC60528608CCF82C02327789C8AF705BFF19B`; run log SHA-256 `11489878857ED42B58FA23B73C5E8460DE5877D930011269AB544116D300A1B5`; corrected outside-Git driver SHA-256 `F7570DF260A67165199A863A08E0A43284319D9A7E12E709DEBA745EE8F5746D`. The first import-failure log is retained privately. No private case content enters Git.

## 2026-09-27 02:01 PDT | Same-visible frontier component check | `840596f`

- Goal/problem: Determine whether the newly built local-deep ranker and existing Laya ranker can both execute a complete choice on one frozen source-bound four-item menu, after the toy trajectory failed to offer rankable items.
- Change and why: A called the existing ranker interfaces serially under the shared host lease, changing only provider/model pins and deadlines while hashing the common symptom, hypothesis briefs, semantic items, and evidence packet. Runtime closure and the absence of owned workers were checked before role transfer and final slot release. This was a component check, not a replacement for the full affected-task trajectory.
- Alternatives/failures: A first cold Laya call returned the explicit `deadline_expired` fallback after 1.407 seconds; the concurrent local-deep call completed in 9.281 seconds. A then tried Laya alone with prewarm (successful) and finally re-ran both on one exact identical synthetic visible request. Prewarming only Laya makes elapsed times incomparable, and neither selected action was executed. No cause or utility winner was assigned. C's blinded review of the separate four-arm toy trace found a broad predicted proxy-disabled fact that the generic toy `observation` fact did not contest when the enabled-proxy control arrived; the model hypotheses remained unresolved and no assessment was made.
- Evidence/metrics: The final shared visible digest was `13e22d6230b70282fd15a87600f46e590112e133638c7d9aba34ec65bad41883`. Real Laya returned nondegraded order `[4,3,1,2]` with complete four-ID coverage in 140 ms after separate prewarm; real local Qwen returned nondegraded `[2,1,3,4]` with complete coverage in 9,203 ms from a cold dedicated service. The artifact is a functional provider-seam proof only. After the run, no managed listener `11435` or A-owned Python/Ollama job remained.
- Next question: Can a source-backed frozen fixture supply *competing executable frontier alternatives* and an exact affected-task result, so a chosen rank can be judged independently? B is adding a fail-closed policy-realization gate before another trajectory attempt.
- Artifacts: Private result SHA-256 `62C27D9DE1F817A27A78E1E33D1448E55F6FD597FFF1ECB791F127BE945F5E98`, log SHA-256 `4727C5ED23EDD1F867D7E5CE9561BED4D948037C52A7A0D5AFB84D46B491B894`, outside-Git driver SHA-256 `146D0503F0504D62109768ADBCE86BE17A40D593388391A19ED655BE5ED5D7E3`. Earlier cold Laya failure and Laya-only warm artifacts remain outside Git; no private data was committed.

## 2026-09-27 02:20 PDT | Durable search-policy admission and combined gate | `ee16b1f`

- Goal/problem: A completed four-arm case could be mistaken for a comparison even when its named rankers never ran and its affected task was unbound.
- Change and why: A reviewed B's two benchmark-only commits and integrated them as `3653a1a` and `ee16b1f`. The comparison now requires nondegraded durable calls for the named decision, frontier and reasoner, with the frontier call tied to a source-backed menu at the same state version. A rebuilt the unsigned desktop development installer from runtime code `840596f` and checked its bundled executable. A restricted the Python source distribution to package source and required project metadata after its first build swept in ignored desktop outputs. Default routing and read-only policy were unchanged.
- Alternatives/failures: B's first gate expected frontier calls under `fast_decision`, but runtime records them as `catalog_attention`; A held it until B corrected the mapping in `e9542fb`. The frozen toy case has no source-backed event menu or candidate snapshot; its actual model arms fell back or never reached the named frontier rankers. A held the second model speed episode. The combined gate initially found three Ruff test assertions using constant `getattr` and two opt-in test annotations restricted to the concrete Laya ranker; A repaired those test-only issues without weakening assertions. The first offline sdist was 348,831,095 bytes and included ignored desktop binaries and dependencies; the corrected one is 699,272 bytes, and the wheel hash is unchanged. The VM pilot remains blocked by normal guest login and a compatible nonce-bound 204/CONNECT-502 lab origin; no fault was injected.
- Evidence/metrics: B's exact-code private eight-case CPU replay verified integrity, with eight deterministic cells complete, 24 model cells unavailable, zero realized pairs and zero admissible pairs. A's combined non-MCP Python suite passed 3,348, skipped 31 opt-in tests, deselected one MCP test, and emitted seven warning-path notices in 427.02 seconds. Whole Pyright reported zero errors/warnings; Ruff lint passed, focused profile/comparison tests passed 57, and Ruff format checked 596 files. The corrected offline sdist has 261 members, no desktop tree or DB/log/EXE file, and builds the identical 849,045-byte wheel. The installer was built and desktop gates passed on runtime `840596f`: seven unit, 13 end-to-end with one packaged opt-in skip, separate packaged executable Playwright one pass, TypeScript/Vite, ESLint and Prettier. The package is unsigned, without opt-in inference dependencies; clean-machine install and packaged-model behavior remain untested.
- Next question: Can a frozen network/browser and application/performance case offer real source-backed competing actions with equal visible requests and an independently bound affected-task result, before any model speed or diagnostic quality claim? Normal guest recovery and a coherent lab endpoint are still required for the VM pilot.
- Artifacts: B private eight-case manifest SHA-256 `879C1E115659CEB0034E7DFADBED47598DB15C938F5EC136877B3E28303C5C1B`; A private combined test log SHA-256 `3A602B9467EF340F918B176F3A0FCA3AA65BAFF076A3418A20EB41747A19F77F`. Corrected sdist SHA-256 `191DA8CF52EF0FBB4241D5B0F826C15F3E7EC11ABD1B1DDFFDB5F072FC810C97`, wheel SHA-256 `3CFCCB3628044D058317584EA245ECCB89292359598BC964E3A2F78DB8EFADF2`; oversized first sdist SHA-256 `91A10EF08F0A61ADC5F403B173EF248F4F5CDE2E05A30308ABFB66E8B99CD671` records the failure, and that private archive was removed after verifying the hash because it swept ignored desktop outputs. Rebuilt unsigned installer SHA-256 `84E8D579E302C25A798EB9C2FEB81B09767289D4AC54B44CF20CB25602C120FE` (132,374,398 bytes), bundled executable SHA-256 `E45AAA30BBECD550A4C6A0CFC44B0D6A4CDE43DD904F4DA2FCA411847E7C23A9`; backend build log SHA-256 `81DD0D33F0C5946A9F119FAE20F2991C99E443FA3E9F4D9374EA78003C158FDA`. Private logs, case databases and screenshots remain outside Git.

## 2026-09-27 02:55 PDT | Source-backed frontier reachability | `5a294c2`

- Goal/problem: The first four-arm toy case never offered a source-backed menu, so it could not evaluate either named neural search policy. Test the existing event frontier's choice custody before another model run.
- Change and why: A reviewed B's two benchmark-only commits `cd15de4`/`fab9037` and integrated them as `eb1e168`/`5a294c2`. A new versioned CPU pilot seeds typed synthetic source observations and calls the existing durable event frontier with scripted ordinal advice. It keeps the old eight-case protocol untouched and imports the withheld toy oracle only after provider calls. C checked source-visible packets and exact selected facts independently.
- Alternatives/failures: The 48 background rows and six no-new-fact pages are artificial catalog paging stress, not ordinary time-to-useful evidence. A first `app.run` prototype silently reached no ranker because B's seed also counted 52 probe executions and exhausted `max_probes`; source-only seeding corrected that fixture mistake. The corrected whole-run prototype then reached 45 scripted rank calls but a different menu and selected IDs, so the frozen direct event-turn pilot remains **not** a matched whole-trajectory comparison. C found source titles/order can cue relevance and neither an exact real affected-task target/window nor independent outcome is bound. The first pilot used a coarse Windows `monotonic` clock and emitted millisecond decimals beyond its resolution; B preserved that artifact and replaced it with a recorded `perf_counter` clock in `fab9037`. No model, VM fault or training followed.
- Evidence/metrics: On A's integrated checkout, the corrected private artifact verified 4/4 CPU cells and `comparison_admissible=false`. Each cell offered four distinct durable retrieval IDs in one menu, one nondegraded scripted frontier call at the same state version, and exact selected-fact readback. C's predeclared review found no hidden exact fact/cause label in rank requests; selected `ev49` narrows two declared toy recipes and misleading `ev50` narrows neither, with no supported diagnosis. Corrected CPU paging stress took 170.943–174.302 ms for six setup pages, 322.607–326.441 ms to first menu and 494.183–505.544 ms per direct cell; these are not model-policy speed estimates. Twenty-two integrated focused benchmark tests passed, scoped Pyright zero and Ruff lint/format passed. The earlier combined 3,348-test gate at `ee16b1f` predates these benchmark-only commits; final whole-gate validation remains pending.
- Next question: Can a checkpointed postbaseline ordinary `app.run` preserve one exact multi-choice source menu across two cause variants per family, bind synthetic task target/window/outcome, and pass independent review before any remaining model comparison?
- Artifacts: Corrected private manifest SHA-256 `AE5E91ED3ECA8633ADCBA4D7089913E9DD3AB3A13C001CB6F21CAF98EA58C65B`, protocol digest prefix `69278223`; original coarse-clock manifest SHA-256 `019FA13454573DD4D1BDF96FB764EBA02E235E77CAFF4B3D58581F4F90A86FB0` is retained only as historical custody. Private case databases and logs remain outside Git.

## 2026-09-27 03:34 PDT | Full-run synthetic source custody | `97a241b`

- Goal/problem: The direct event-turn pilot did not prove that ordinary `Investigator.run` could reach a stable choice menu or bind even a synthetic affected-task result. Test the existing loop without claiming a real Windows outcome or a model-policy winner.
- Change and why: A reviewed B commits `0afc087`/`df37d39`/`d0b1b73` and integrated them as `32c5769`/`b7bb226`/`97a241b`. The CPU-only fixture copies a closed postbaseline checkpoint per domain, appends preexisting synthetic source records, and makes two scripted choices across two hidden recipe variants for each of network/browser and application/performance. A registered `fixture.task_baseline` probe independently stores one synthetic target, expected/observed result and 500 ms UTC window. The 52 preexisting source rows per cell now say they are synthetic and have no on-case probe execution; separate readback confirms zero source-to-probe links and one baseline probe attempt. C reviewed anonymous prechoice requests, then stored custody, then evaluator effects.
- Alternatives/failures: The first `app.run` prototype counted 52 source rows as probe executions and exhausted its probe budget; B discarded it. Commit `0afc087` misleadingly registered the synthetic task as built-in `core.system`; A held it until `b7bb226` gave it fixture-specific identity and explicit no-Windows limitation. C then found the 52 source records lacked a preexisting-synthetic limitation despite synthetic execution IDs without corresponding probe executions; `97a241b` corrected that without fabricating attempts or relaxing validation. The validated first-choice request still differs across hidden worlds in `ev49`'s source-content hash. Static projections of the fields current Laya/Qwen adapters would send match, but no model transport ran. The first model evidence packet exposes the task action only; target handle/result/window are durable but omitted by compact packet budgeting. C had seen provisional oracle source earlier, so this was source-first review, not strict unseen-label blindness. Forty-eight background records and six no-new-fact pages are artificial paging stress; their timings are not policy speed.
- Evidence/metrics: A's exact-code verifier passed 8/8 cells with `comparison_admissible=false`; three focused benchmark tests, scoped Pyright zero, Ruff lint/format and diff check passed. Each target menu has four source IDs at state version 30 and a nondegraded scripted `catalog_attention` call. Four `ev49` choices each reduce two synthetic recipe labels to one; four abnormal `ev50` controls reduce none. All eight ordinary runs end `no_progress`, with no supported causal answer. Prior four-arm toy and eight-case policy protocol remain zero admissible model-policy pairs. A's final non-MCP Python suite at this code revision passed 3,351, skipped 31 opt-in tests, deselected one MCP test, and emitted seven warning-path notices in 441.27 seconds. Whole Pyright reported zero errors/warnings; Ruff lint and format check passed across 602 files. Offline sdist/wheel build passed; the 261-member sdist had no desktop tree, logs, databases or executable files. No A-owned Python/Ollama job, listener `11435` or running VM remained after the heavy slot was released.
- Next question: Can the exact affected-task identity and outcome reach a bounded model-visible request while preserving source custody, and can an independently observed real task qualify a matched model comparison? The named VM still lacks normal guest access and a nonce-bound HTTP 204 plus coherent CONNECT/502 lab origin; no fault or repair ran.
- Artifacts: Private exact-code full-run manifest SHA-256 `F9A5D630BA679EEAAC6E0A849D59090E67AD479E6C3C5392127CD173800ECE97`; anonymous request packet SHA-256 `3D8762A14E3E1CCF96ADADE823CA4F386206D3DDF00CB9138DBAFB33E9FED86D`; protocol digest `2CA7E63D9928A5DD924F919B164950221ABD742756D441B66D0725D5850EAF79`. Final combined test log SHA-256 `AFC99A04E1B526AB56DDCB13712EF1BFF1A9D14F91724247498E5771040E716F`; corrected offline sdist SHA-256 `191DA8CF52EF0FBB4241D5B0F826C15F3E7EC11ABD1B1DDFFDB5F072FC810C97` and wheel SHA-256 `3CFCCB3628044D058317584EA245ECCB89292359598BC964E3A2F78DB8EFADF2`. Prior `0afc087` manifest `33AB996EEE4133FAB9964870DA86053693009EB9BFBDA166EA0E79FAB40E59F0` and `df37d39` manifest `AB148590D3B5120CA2756E7DB91462650FD798DE989AFE9DE559FFC317EED4DB` remain failed/reviewed candidates outside Git. C's review is in the outside-Git team board; no private case data was committed.

## 2026-09-27 03:48 PDT | Final-code model overlap and desktop gates | `97a241b`

- Goal/problem: Recheck actual local-model coexistence after benchmark integration, while keeping the synthetic source-choice comparison separate from model-policy qualification.
- Change and why: A ran the existing capture-off synthetic counterevidence test using the opt-in warm Laya/Qwen profile in an isolated outside-Git case database. A also reran desktop unit, end-to-end, type, lint, format and renderer build gates against the integrated checkout. No runtime code, host settings, VM, model weights or product repair changed.
- Alternatives/failures: This demonstration reused a scripted read-only pressure contradiction; it has no independent affected-task result or diagnosis oracle. Setup included cold model admission, so its elapsed time is not a matched policy-speed experiment. Two post-counter menus reported incomplete worker evidence, and five evidence/detail requests remained unsatisfied. The 20-distinct-judgments/s target was missed; all-eligible-event p95 under 400 ms was not measured. The desktop package test remained an opt-in skip during the 13-test end-to-end run; its earlier separate packaged executable pass was at the prior runtime build and does not prove a clean-machine install.
- Evidence/metrics: The actual-model test passed one with one deselected in 27.57 seconds; case runtime was 12.14 seconds after 14.25 seconds of setup. Seven Laya menus offered 16 distinct IDs; four post-counterevidence selections completed while Qwen was active, and one Qwen result applied. Two synthetic read-only probes were admitted; the case ended without a causal answer. Active ranking offered 5.885 distinct IDs/s. Desktop checks passed seven unit and 13 end-to-end tests with one package skip; TypeScript, ESLint, Prettier and Vite build passed. After owned worker closure, no A-owned Python/Ollama/VM process or port `11435` listener remained; only TCP `TimeWait` entries were present.
- Next question: Can the model-visible choice carry exact task target/result/window and a verifiable real affected-task outcome, then produce a matched comparison with lower false-claim and time-to-useful-evidence cost? The named VM remains gated by normal guest access and a coherent nonce-204/CONNECT-502 origin.
- Artifacts: Private demo log SHA-256 `4ED55845784CE44C0DE3DF65902FF97C62E79CF27227FAEC1717467A45659A89` and isolated case database SHA-256 `9D0CC5BC8DA440657945D5B7998C9B92C1CEC5FB0274BCBD28B764B556FDEB47`. Test output and case data remain outside Git.

## 2026-09-27 05:31 PDT | Source-bound synthetic task transport | `2b258a5`

- Goal/problem: B's eight-cell full-run fixture stored an exact synthetic target, result and 500 ms window, but the first model choice saw only its action. Preserve that identity through the existing frontier without treating fact names or abnormality as causal proof.
- Change and why: A added a fixture-only versioned task reference, exact case/source/collector/execution/record-hash readback, bounded complete task context for both ranking adapters, atomic required Laya fit, and visible quarantine when custody fails. A also revalidated the reference when a ranked measurement snapshot is frozen, selected or linked. B bound the actual executed `fixture.task_baseline` record before copying the closed checkpoint; A integrated B's benchmark/test commit as `dc4c8c4`. C independently reviewed source custody and adapter captures, accepting only synthetic structural transport. Cloud export of this new context fails closed pending an approved export contract.
- Alternatives/failures: B's RED adapter test initially found all 16 first-choice captures missing task result/target/window. C rejected generic seven-key fact matching and warned that Laya's top-three fragment selection and optional state fit could drop separate fields. A's first broad gate at `dc4c8c4` failed five tests after 3,352 passes: two expected schema 5 rather than 6 despite intact PDF target behavior, one pinned the old worker source hash, and two historical v1 snapshot reads compared the newly optional null task field against old bytes. `adc2b57` corrected the expectations/pin and preserved exact historical v1 readback, digest and no-new-selection checks. A stopped the next broad run after finding measurement snapshot reassembly omitted the task reference, then fixed it at `2b258a5`. An initial private model script lacked its repository test import path; a v3 admission helper then correctly denied startup against the migrated v4 host lease database. Both failed attempts remain recorded; the supported v4 profile succeeded. No test or model validator was weakened.
- Evidence/metrics: Integrated focused tests passed 94 before the snapshot fix; 35 snapshot/source and historical tests passed after it. The final non-MCP Python suite passed **3,358**, skipped 31 opt-in tests and emitted seven expected warning-path notices in 483.73 seconds. Whole Pyright returned 0 errors/warnings; Ruff lint and format checked 605 files; offline sdist/wheel build passed, each with 262 members including `task_observation.py` and no desktop/log/database/executable in the sdist. A's exact-code CPU replay verified 8/8 cells but still reported raw hidden-world request mismatch and `comparison_admissible=false`. One actual pinned Laya v4 call on a frozen schema-2 four-source request returned a complete nondegraded ranking; four evidence and one probe exact worker capture retained the whole task context and model input. It measured structural fit, not cause quality or speed. Rebuilt unsigned desktop gates passed seven unit, 13 end-to-end with one package skip, separate packaged executable one, type/lint/format and renderer/backend/installer builds. After model close, owned workers, listener `11435`, v4 active/pending leases and running VMs were zero.
- Next question: Can a real independently observed affected task and controlled healthy/fault/recovery outcome make a matched comparison admissible? The named VM still lacks normal guest access and a nonce-bound 204 origin with a coherent CONNECT/502 receipt. The synthetic source titles/order, fake-worker compare stage and absent Qwen rank on this task remain limits; no training, fault, repair or cloud deployment ran.
- Artifacts: Private final suite log SHA-256 `28BD58750D626AADD0D48BBFB523AE50C719482F8E4156F347BC51DE5112CFDE`; earlier five-failure log `F216526E2BFA8A63920558F473B91BAF4531EC89CD86E018A12CE9842660F547`. Exact-code eight-cell manifest `71AD2C3D055F58B8DA629777B55242A95B90945E578FFD47388FEE7A3ED58F93`, anonymous requests `C9AFFF8D8ACE594FF489F5DD70D2E771C002D749561146BE1D02B68B13443407`, protocol digest `10e2cebe6b1fe08ead2a955af3c78131e4fdd59ac9ec400513436942bd11c5f7`. Actual Laya log `10461582E42DEB38E8C30C57513CF19D9D9EA4CEA8D8EB8B947E91E9B8BE5252`; v3 admission failure log `E16F55406059A41D26C52FC1F51AF821328E5F35F95415DF07B8C0E7C12368F7`. Offline sdist SHA-256 `EA8FDDBE8F4E0BAA4BB471FAE8FFFF4B2A75C75F9B302C75AD3B4EAFD489FCB1`, wheel `370C1D0FFB8D358E64E93C9C6083A6C896B6F90DE460F4E70159D8A73CAC47BF`; rebuilt installer `FBB462847DA4B4416AF708A81ED1122E0513EE6EC568483F0E3F8B4C2A070F07` (132,386,660 bytes), backend executable `260AB8A316DFD9B6B0915562BADBFD57C281248073DE31141E1EA77BE7C45DC8`. Private logs, databases and package binaries remain outside Git.

## 2026-09-27 06:30 PDT | Paired model-input and cue audit | 70f1eb5

- Goal/problem: The eight-cell source replay had matched static adapter projections but different raw source commitments, and its useful source could be selected by title or position alone. Establish what the current adapters actually present before spending a model comparison.
- Change and why: A reviewed and integrated B's benchmark-only cf81d99 as 70f1eb5. The linked audit captures actual MixedFrontierRanker input, fake Laya fitted worker state and LocalDeepFrontierRanker prompt for all eight cells. It retains the original v3 case artifact and raw request hashes. C froze blind criteria before B's change, inspected policy-visible captures before evaluator labels, reran the focused test and accepted only an input-fidelity/confound claim.
- Alternatives/failures: All four same-choice hidden-world pairs matched at the model-facing adapter boundary, while the validated requests still differed in item_semantics[0].source_record_sha256; those are different parity questions. The useful ev49 source is always first and uniquely task-titled, while ev50 is a generic CPU/storage abnormality. First-item and lexical title rules therefore choose ev49 in every pair. Reversed order was only an adapter counterfactual and leaves the title cue; no reversed Investigator.run trajectory or model judgment ran. ev50 was uninformative under the toy oracle, not shown to induce a false cause. No diagnostic discrimination, model winner, causal answer or speed claim follows.
- Evidence/metrics: Eight captures completed with zero capture failures; four model-facing pairs matched and four raw request pairs mismatched. Four scripted ev49 choices reduce the toy compatible-label set and four ev50 controls do not; all eight original runs remain no_progress without a supported causal answer. C's independent focused test passed once in 29.52 seconds. After integration, A's two focused benchmark tests passed in 54.41 seconds; whole Pyright returned zero errors/warnings, Ruff lint and format passed across 607 files, and diff check passed. The prior whole Python/build/desktop gates at f82fbfb predate this benchmark-only commit; no model/GPU/VM/heavy run occurred for this audit.
- Next question: Can existing source metadata honestly express two similarly plausible task-related retrievals with counterbalanced order/IDs and a prechoice applicability signal, so first/lexical baselines cannot decide the result? B owns one bounded CPU feasibility attempt; A retains contracts, model resources and integration. The real VM affected-task pilot still lacks normal guest access and a compatible nonce-bound origin.
- Artifacts: Private linked manifest SHA-256 D32DDB1798DCE76A9EF4375A719F3473EDE87C303B58F6D0EEF622D6C0095609; blind adapter inputs SHA-256 9EF49306BD756393BF37A52CDB73F2C53778F27BF7BDFF4EED00C115DB44CE10; evaluator pairs SHA-256 9079893B9F511CA2E0280F02E35BA421505137F959D6329DFBCCDD95AFB77E42. Private case databases remain outside Git; C's frozen rubric and review are on the outside-Git team board.

## 2026-09-27 07:08 PDT | Exact synthetic source applicability | 25b33e2

- Goal/problem: The paired audit showed that the existing source projector gave every retrieval unknown task scope. Equalizing titles made the two model-facing descriptions indistinguishable, so a useful-over-uninformative choice could not be tested honestly without source coverage metadata.
- Change and why: A added an optional version-2 source-task relation to the existing frontier semantic, derived only from exact case/source row, strict synthetic fixture producer/locator, source identity, UTC coverage, exact row time quality and the version-2 bound task observation. Valid full target/window coverage, valid different-target/insufficient-window, and ordinary unknown stay distinct. A reassembles the relation at prepare/finalize/snapshot capture and rechecks source hash, fixture time and task binding before later snapshot selection. B's RED64f2837 benchmark became green after adopting A cd9218e; A explicitly integrated B's benchmark-only RED/fix commits as 5bf82d7/9224197. C independently reviewed both runtime and B fixture, accepting only synthetic owner-assembly and retrieval claims.
- Alternatives/failures: A initially considered using free-text summaries or hidden source facts to signal relevance; those would create a lexical cue or prechoice leak. B's prior read-only report found 32/32 old source choices had unknown task scope. The first whole Pyright after integration found one private import exception comment on the wrong line. A corrected only that location at 25b33e2 and whole Pyright then passed; no type rule was disabled. B's first RED failed because the new relation was absent. Its green fixture still has equal trusted-source facts, scripts the selection, and ends no_progress in every cell. The source/collector/parser markers plus recomputed locator hash attest internal consistency of a fixture record, not an independent real producer or cause. No model, VM fault, repair, training or cloud run occurred.
- Evidence/metrics: A's new relation tests were RED on import, then 65 focused source/frontier/snapshot/historical tests passed. Six historical readbacks include an exact canonical v1 comparison and no-new-selection/tamper checks. The integrated B balanced-menu plus adjacent tests passed 5/5 in 102.17 seconds. Eight actual Investigator.run cells cross two domains, matched source at ordinal zero/one and scripted selection of each; selected and alternative rows were read back, and a private unopened sentinel was absent from the prechoice request. C separately reran B's focused test 1/1 in 26.53 seconds and verified all eight ended no_progress. Whole Ruff lint/format passed 610 files; the first whole Pyright failed one private-usage annotation placement, then passed zero errors/warnings at 25b33e2. Offline sdist/wheel built on code 9224197; package code did not change in 25b33e2.
- Next question: Can two hidden factual cause variants per domain, crossed with covered-source position and selected action, produce a blind independent effect score from exact retrieved facts while preserving equal policy-visible inputs? B is constructing 16 CPU cells; C will review before any A-owned model run. The real VM pilot still lacks normal guest access and the nonce-bound 204/CONNECT-502 origin.
- Artifacts: B RED log SHA-256 4DCC4104D994604C95A5EF7937F3F0217BAA5C81F9BA354D929CB33692BC4184. Private A offline sdist SHA-256 D0E8FFE7B1BC6799828CF02055D0C4A45343BA5E900261A8A15623CB53C2B37B; wheel SHA-256 F2DB2E68935744E5E049C3832B416B3D2560341A01CE2FC9867CA816538CD31F. B offline wheel SHA-256 DBF7C7EE517A2B5889FECDDB42A794D7E1CF60A8D10B2BC42B14EBCFE49B1940. Logs and case databases remain outside Git; C's review is on the outside-Git board.

## 2026-09-27 07:31 PDT | Balanced synthetic source effect audit, verified 08:39 PDT | `f6417e5`

- Goal/problem: The equal-fact eight-cell fixture exercised source applicability but could not show whether the chosen exact source supplied useful evidence. The prior toy source was also favored by its title and first position.
- Change and why: A reviewed and integrated B's `038da65`/`0662973` as `886d9df`/`83f5bb2`. The CPU fixture crosses two hidden toy fact variants in each of two domains with covered-source position and scripted choice. Two equally titled sources offer exact task-coverage status before selection; a separate evaluator reads persisted selected source and task rows after retrieval and scores whether exact facts reduce two frozen fixture rivals. C froze a blind prechoice assessment, then unsealed and independently rescored every selected row. A integrated B's narrow future false-claim accounting correction `885ff98` as `30f6314` after C identified the defect.
- Alternatives/failures: The explicit fixture relation itself identifies the covered source. Thus a deterministic coverage rule chooses it 8/8 on eight unique menus; this does not test an installed model's judgment or independence from fixture-declared metadata. The 16 choices were scripted, baselines were reindexed from executed alternatives rather than run separately, and all cases ended `no_progress`. Eight hidden-world raw rank requests differ by a source-content hash although fake adapter-visible payloads match. C found that a future unjudged claim would be counted as zero false claims; the correction now preserves unknown. The original frozen artifact belongs to `83f5bb2`; new-code source-pin verification does not retroactively reverify that artifact. The first broad Python run was interrupted after a failure at the deferred counterevidence menu assertion; a `-x` repeat reproduced it after 733 passes/3 skips. C traced this to the test's imported `_gpu_source` helper using a module-import-time clock: after the long suite, the source exceeded the product's valid five-minute window and was correctly omitted. A refreshed only that helper clock in the importing test at `f6417e5`; the GPU freshness rule and mixed-menu assertion remain intact. An integration-only run separately stopped on selected-invocation timing/binding after 236 passes; B could not reproduce it in ten isolated attempts or the exact 237-test prefix, and the composite guard's failed predicate remains unknown. The post-fix full gate passed, but that success does not erase either prior failure or establish the second cause. A private model script first missed the repo import path, then used a v3 admission helper against the current v4 ledger, then read the disabled implicit profile; the explicit supported v4 profile succeeded. No VM fault, training, repair or cloud deployment ran.
- Evidence/metrics: B's original exact-code 16-cell replay verified 16/16 with eight toy-useful full-window retrievals, eight wasted controls, zero unknown effects, zero causal claims, and eight matched fake model-facing pairs; C independently verified each source row/hash/fact and toy effect with no mismatch. First-item and title-tie-first baselines were 4/8 useful, lexical-title-only abstained eight, coverage-rule 8/8. C's focused review passed 1/1 in 48.67 seconds; B's accounting regression passed and its revised two-test pilot passed 2/2 in 49.06 seconds. A's integrated changed-path gate passed 5/5 in 80.06 seconds. At `f6417e5`, the post-fix combined non-MCP Python gate passed **3,364**, skipped 31 opt-in/runtime-specific cases and emitted seven expected warning-path notices in 590.57 seconds. Whole Pyright returned zero errors/warnings, Ruff lint/format passed 613 files, `git diff --check` passed and offline sdist/wheel built with 262 sdist members and no private database/log content. Rebuilt desktop backend, seven unit tests, 13 end-to-end tests with one expected package skip, separate packaged executable test, TypeScript/Vite, ESLint, Prettier and unsigned NSIS installer all passed. Two direct pinned Laya v4 calls on the frozen menu returned complete nondegraded four-item ranks with the full-window source first when placed at ordinal zero and one; this is installed-model request compatibility, not an executed choice or advantage over the exact coverage rule. No time-to-useful-evidence, diagnostic advantage, matched model-policy comparison or real-cause result follows.
- Next question: Can a real independently observed task and controlled healthy/fault/recovery outcome qualify a source choice and causal comparison? The named VM still lacks normal guest login and a lab-owned nonce-bound HTTPS 204 origin with a coherent CONNECT/502 receipt. The user authorized normal access and compatible setup but has not supplied credentials or origin control. No fault was injected.
- Artifacts: Original private manifest SHA-256 `94E6FBB6768B08D4418D5CEB08A131EB0CD299D4D1305D63747CD74F6EDAF808`; blind inputs `9B4F906CDC16EDA203724316F4907A6F5286BFF7615E4BEAFD6F78AEDE6765E4`; evaluator reviews `3F8AB659FF3102851D92492545BB01E2B6394BCFD06AD28173D1378B0FC2713D`. No-execution linked accounting correction SHA-256 `44A6CE802F1255F74F60274A91C9CC025D92EC81471FE16DB4CBEFF0D7528D05` is outside Git. A broad `-x` failure log SHA-256 `5865FF70239D0597369C039432EFBE176B9DCD3C79E92DF4A59DB6FAC793F5FE`; integration-only failure log `8B91BF4390456D7BAC93F91A7C6C54C8A5CE3D05EA537B51C26BE961E58AB5E9`; final full gate log `E94710FD9825EFEC8F7F47F1E1C78296E804C7917DD2C0E3FE0D670F47A1F460`; focused gate log `251BD50F9AA0F1FE69F1127AFD1DF21FCCD85C12D6A073685392E62CCE8E9148`; actual Laya success logs `9BAA1A8BD6F6B3AB0533CFCC684ACC1C8AC0315E56F755CF4A7EB573082B7122` and `12D128276C413352AE177118580305907F96C99CD8FF77052110FAC67529B6FE`. Offline sdist SHA-256 `21443EFE6DAD5D1C01C0B62C8BE805A93BAA8E0F000FD001DC814E8608847A6B` and wheel `EC1EAACC233DED0E7D1C9D4E61798AC34870BC36EA74FBDDD900859154FFBA40`. Rebuilt desktop backend log SHA-256 `54E948CD4627904F71F82C5A9CD3F10E1CE83DB6CEA128E97EB82E3B1D40C6AE`; unsigned installer log `651C1BE8C158C997A33661044B9CB6B9D7F66FC410BC921D2F6C6D0E1BE62D72`, installer SHA-256 `F580EA75C3B0E073A5ACEF24C07B278F0B2A085C495B782B925EDA91956A3E3C` (132,392,147 bytes), bundled backend executable `F42027714529FB3AD440B309402E0EFB5F237DFA5A482B5EB6FD79A0C3E3D03B`. C's frozen rubric and review are on the outside-Git team board.

## 2026-09-27 11:35 PDT | Receipt-bound postretrieval advisory | `8cbe0ee`

- Goal/problem: The balanced source pilot showed that a useful stored source could be selected, but its exact task binding and chosen-source identity did not reach the first deep request. A later retrieval of the competing source made the terminal state unsuitable for first-choice attribution.
- Change and why: A added a version-5 reasoning request carrying the exact validated synthetic task observation and receipt-backed selected frontier source with its bounded fixture target/window relation. Task and selected IDs are reserved in the deep brief. A made event, synchronous and mixed PDF frontier focus receipts atomic with their case checkpoints. B added a 16-cell scripted first-postselection advisory replay; A reviewed and integrated B `0824cd0`/`597b4f9` as `40df3dc`/`c309bf9`. C froze a blind score, then independently checked the source rows, receipts, first applied revisions and terminal records. The task/coverage fields guide advice only; the assessment gate remains unchanged.
- Alternatives/failures: A rejected treating `priority_evidence_ids` as proof of a selected source because it also includes requested and background evidence. The first contract attempt caused a circular import and exposed typed-ID/format issues; A moved the shared relation type to the domain and kept old request versions available. C found that exact fixture row time quality and required brief IDs needed rechecks; both were added. B's RED found no focus receipt in the event path; A's direct RED found the same gap in the older synchronous path, and C found it in the PDF route. All three paths now commit receipts with case state; source-loss and stale-generation rollback controls remain. B's first private 16-cell run failed its verifier on tuple/list JSON equality after execution; a corrected fresh artifact was frozen, leaving the failed attempt in private history. C's preregistered prediction/next-test requirement failed in every cell: the scripted provider emitted no expected fact, distinguishing probe or explicit next request. The toy source relation itself identifies applicability, and later matched-source retrieval in controls erases first-choice terminal attribution. No real task, fault, repair, training, cloud run or matched policy-speed experiment occurred.
- Evidence/metrics: C independently found zero mismatches across 16/16 exact synthetic task/source rows, hashes, receipts and first applied response revisions. Eight full-window first choices changed source-cited support/contradiction; eight controls did not. All 16 ended `no_progress` with no assessment or causal claim. A's integrated focused gate passed 11 tests; combined non-MCP Python passed **3,367**, skipped 31 opt-in/runtime cases, deselected one MCP case and emitted seven expected warning-path notices in 638.42 seconds. Whole Pyright returned zero errors/warnings; Ruff lint/format passed 562 files. Offline source/wheel built with 262 members each and no private DB/log/media paths. Rebuilt desktop backend, seven unit tests, 13 end-to-end tests with one expected package skip, separate packaged executable test, TypeScript/Vite, ESLint, Prettier and unsigned NSIS installer passed. One integrated actual Laya/Qwen synthetic overlap passed in 43.19 seconds, with seven menus, 16 distinct IDs, 34 microbatches, two admitted read-only probes and one successful deep call; observed active ranking was 5.887 distinct offered IDs/s, below 20/s. It supplied no cause and no all-event 400-ms p95 or time-to-useful-evidence result.
- Next question: Can a real independently observed affected task support a timed prediction, later counterevidence and reviewed causal assessment without false claims? The named VM remains saved, cable off and without normal guest login; `https://example.com/` returns 200 instead of the nonce-bound 204, and the closed proxy port cannot supply CONNECT/502. The founder authorized normal guest access and compatible setup but no credentials or controlled origin are available. Preserve unresolved output until those prerequisites and a scoped pilot protocol are real.
- Artifacts: B corrected private manifest SHA-256 `177B8EDDEB61915B6AFED146A73E583267032BA41D458E28C5303B23849CDB8A`, blind first-choice packet `5EC6FD5975C36ED60DB086702B7F10B823142C66D8965D5BCB5E2399B89E9D0D`, evaluator review `12A4EBC5E7AA250372C3C551FE3FEBBB26879FFEA3AA6222A2AF882B132F2061`; C's blind-first review is in the outside-Git team board. A private combined Python log SHA-256 `9EF972F8DE20124668C7EB12C52F1A545AD7A1CA9548ACBAA13376D3F89FA157`, backend build log `4B695282EE27248C5B1830B296B3B45E29149B2A17F28DEC741CB6B73570E687`, installer log `4A09860B0CE52D04B5BFF115019AAC9B036FF361C4471777D82022EBF4103BE0`, local model log `5A1F8AE21ED025F88D288F4D8518CAE834617B83170614918E9099D524469A05`. Offline sdist SHA-256 `56994108B0E691054F0C27673DBE615387F9147C9A55782A30C84338FD5291D9`, wheel `B60AABBE2CE8F0EC30C190DBFB6256846C94786153C428BF1653AA5BB9710D07`; unsigned installer `8DCEE4C4B412E1F83452CBC13788F2EFF9A4BA63B8929CECC0F4F7F20F55DCE7`, backend executable `A911113EB19D4277B0310D605B8A3EC4609FCC5EB0DECC53E561AF3DC589BD11`. Logs, screenshots, case DBs and binaries are outside Git or ignored build output; no private data is included here.
## 2026-09-27 12:50 PDT | Prospective rival continuity and bounded local check | `5d9cd53`

- Goal/problem: The earlier 16-cell first-source replay changed citations but failed its registered prediction/next-test gate 0/16. A complete later counterevidence turn was unproven. B's new 52-source RED replay showed the first deep response and subsequent read-only probe/prediction contest worked, yet the next deep request lost both prior rivals.
- Change and why: A reviewed and integrated B's benchmark commits `1a9da85`/`bb7534d` as `1f5caae`/`7eed45f`. At `5d9cd53`, retrieval reserves the bound task and rotates live rival citations ahead of aged selected sources in both the 48-record packet and 12-context brief, without raising caps or causal authority. A prior citation and exact later counterevidence can now coexist in the next reasoning request. B adopted the fix as `732ad14` in its own branch and froze a fresh one-cell artifact. C preregistered a blind rubric, scored the new visible trajectory before opening private data, then independently checked exact SQLite rows, receipts, mailbox requests/responses and terminal state.
- Alternatives/failures: The original failed attempt05 remains FAIL: one first accepted prediction, one later registered probe and one `prediction_contested`, but `previous_hypotheses=()` in the next request and no second scripted response. A's first patch reordered only the 12-context brief; the test remained red because the 48-record retrieval packet had already evicted the citation. The second layer fixed that. An adjacent integration test then failed because its single formerly omitted citation was now correctly retained; A changed the test to exceed the unchanged eight-priority bound with nine citations, preserving its explicit omission assertion. Of 125 adjacent tests, 124 passed before that correction; the corrected focused gate passed 12. Two standalone pinned-Qwen attempts degraded with `startup_endpoint_occupied` and no A-owned listener afterward. One instrumented attempt returned a completed output-token limit, then passed the existing tighter-schema retry: unresolved advice with three rivals including unknown, two categorical predictions and one registered probe. Its predicted fact `browser_direct_origin_reachable` with `running`/`disabled` does not match the fixture probe's `direct_origin_status` with `online`/`offline`; count it as no useful tested prediction, not a diagnosis. No model chose a source, no matched speed experiment, fault, repair, training or cloud deployment ran.
- Evidence/metrics: At `5d9cd53`, the B 52-source test plus case-brief controls passed 11, then 12 including the overflow regression. Scoped Pyright 0 errors/warnings, Ruff lint/format and `git diff --check` passed. B's adopted focused replay passed 1/1 in 7.18 s; related source tests passed 3/3 in 34.12 s, scoped Pyright/Ruff passed, offline wheel built. C verified the first source citation and opposite prospective predictions, coordinator stamp, exactly one registered read-only `offline` observation 48.715 ms later, `prediction_contested`, second applied deep turn whose resulting state retained both rivals/citations/stamp, and terminal `no_progress` with no assessment. The new scripted one-cell mechanism passes its restricted gate; independent real diagnostic utility and false-cause rate remain unknown. A's real-model standalone call was not an `Investigator.run` trajectory. The named VM was booted with its cable off, showed the normal `SystemSense Benchmark` password screen, rejected one blank-password attempt, reported LoggedInUsers=0, and was saved again with cable off and no running VM; the clean snapshot remains available, but the saved guest session now includes the failed sign-in and a clean reset is unverified. No compatible nonce-bound HTTPS 204 origin or CONNECT/502 receipt was configured or verified for this pilot.
- Next question: Can a real local model produce a prediction whose exact fact name and value domain match a registered probe output, then revise rivals after an independent observation? A controlled Windows pilot additionally needs normal guest credentials and an independently owned nonce-bound HTTPS 204 origin with route receipts. `https://example.com/` returns 200 and cannot qualify. The user authorized normal access/setup but does not know the password or endpoint; no VM fault was attempted.
- Artifacts: Failed attempt05 private manifest SHA-256 `12234B9859BA42335C14241EB1B19285D6CD13559FCA39ADC2707A68CE493D15`. New linked manifest `24654E288684E2CB19E0764538CD77A48ACDFD570299B35A48CF1CDB4C39840F`, blind packet `5EA8534ED8ECF118942CA7CAD6C04D0A321361F582490B26B5CDF0068C6BF5CC`, evaluator readback `92EA84A951887AD6F4151EDD460AF8B8A9034F52B63AF0E5B516D221516FF492`, case DB `6A56E4985BEA7DD861186CDAFEF89B0AEA4197A69822D162011EFA949AAE5ACC`. Actual-model attempt outputs `96FA3782AF85D32742BBF29617B0A975B699BAA7B0F540FB272097B8CFD7F95C`, `006DF5A10A1F3E6329CE0FF34B9E110FCC4B2A0CC58DCC152989EB2FBFAB7255`, `B0F5E4456481664F39B9193874E4889B9E3646D0232428E9A7B09A589F66AD8F`; final private driver `2C11483458932AF3111B10B542C502CB6E1F7FCBA83CC7913AB1E75F4C9FE821`. VM sign-in and failed blank-attempt screenshot hashes `E405560950967E7F59A886AC822F04CF17AA8BF3BE6A328161204078B4B60AD7`, `5C8AC021DC49A3C43817210D18E531DA3348FBCF500DE50EF9A93936BBD08D99`. All artifacts remain outside Git; no credential or private capture is included here.

## 2026-09-27 13:30 PDT | Combined priority repair and release gates | `d010b46`

- Goal/problem: The full non-MCP suite exposed a PDF retrieval regression after 3,368 passes: when eight explicit requests filled the packet's eight priority slots, a newly selected frontier source became obsolete before delivery. Preserve demand and rival continuity without losing the selected source or raising the bound.
- Change and why: A restored one selected-source slot, followed by explicit detail/evidence requests, rotating live rival citations, then older selections in the packet. The 12-context brief puts explicit requests before rival citations and older selections. The selected retrieval, pending demand, and prospective rival evidence now compete under a documented priority order. No new authority, scan or search tree was added.
- Alternatives/failures: The first full run at `5d9cd53` failed 1 PDF test after 3,368 passes and 31 skips; moving only explicit requests ahead of citations still left the selected retrieval obsolete. Focused PDF, B two-turn and overflow tests passed 3/3 after reserving its slot. A local `python -m build --no-isolation` attempt failed because that virtual environment lacks `hatchling`; the configured offline `uv build` succeeded. Ruff's first format check found only the modified tuple layout; formatting it left no Git content delta. No failing result was erased or test weakened.
- Evidence/metrics: At `d010b46`, the full non-MCP Python suite passed **3,369**, skipped 31 opt-in tests and emitted seven warning-path notices in 651.73 s. Whole Pyright returned zero errors/warnings; Ruff lint and format passed 564 Python files. Offline source and wheel packages built. Desktop backend build, seven unit tests, 13 end-to-end tests with one package opt-in skip, the separate packaged-executable test, TypeScript, ESLint, Prettier, Vite and unsigned NSIS installer all passed. This verifies integration and packaging, not a real diagnostic or release qualification. The actual Qwen call and B/C one-cell artifact exercised predecessor `5d9cd53`; the final ordering delta has deterministic regression and combined-gate coverage but no repeat model trajectory. No owned model listener or Python worker remained after checks; the unrelated Ollama process was untouched.
- Next question: Can a real model emit probe predictions constrained to registered output fact names and value domains, then revise after a matching independent observation? The Windows affected-task pilot still needs normal guest access, a verified clean reset and a controlled nonce-bound HTTPS 204 origin with independent CONNECT/502 receipts. No fault, repair, training, cloud deployment or matched speed experiment was run for this milestone.
- Artifacts: Failed first full suite log SHA-256 `015E2BDA3670A27C9F19CEA5D1D405866C6F4E1FBC122D2B435E20F44C02200B`; passing final suite log `16FFD93D3735829F9D6092DD71C0031E9E5C1D000888217FEF04F61163FFC14F`. Offline sdist `F104EBFA9B5C409B56DBD570B92EB550B15B8942F3C0BD13588152BECD1584FD`, wheel `BE646C960C9646BF470F94F50F527607E9C284074B56418938B463C58111BE44`. Desktop backend log `F124887A3CF1CC8DC13363EEBC2668070E2C1BD2CC1390F80A73C195ED14940E`, gate log `77B0CFEC70D53841DB56C32CB9DC61D9D6CF18166D83837A75EA7F12A14CE1D1`, packaged-test log `BCF236E5978247BDCA6B9A02B1BDAFF1D76F2D0B6AC374445233B8DAC8D47BF8`, installer `DBD10A98479888B2F71084E6BDBBE6F3A41E217FA52ACC6C9E9FB1DE7B61A76D` (132,397,985 bytes), backend executable `69FD10D201DC138594C12B3B949D07F396970D8EABFCA349D64B8F7A6881E5E7`. Logs, package binaries and private case data remain outside Git or ignored build output.

## 2026-09-27 16:44 PDT | Registered prospective facts, live retry and desktop integration | `fe9e16d`

- Goal/problem: The earlier actual local-model answer proposed fact names and values that the selected probes could not emit, so no prospective test existed. The two-turn synthetic replay also exposed a lost cited rival, while a real affected-task Windows pilot remained inaccessible.
- Change and why: A integrated B's registered-output fixtures and RED tests, added version-6 finite top-level output contracts to existing probes, bound predictions to exact registered versions, and required later collector-version identity before a contradiction can be recorded. The shared validator excludes already completed probes and a same-ID advisory revision cannot erase an existing contradiction. The deep provider accepts only predictions from the exact finite menu that survived prompt fitting; optional graph/catalog/reference material is paged before that menu is omitted, and focused observations remain protected. A retained a completed output-length deep session only when its owned session is still usable and within cancellation/deadline bounds, preserving uncertain-error retirement. B's prompt-fit RED `c5cdd68` was integrated as `9f622a9`; A's ordering fix is `fe9e16d`. The D-approved desktop worker change was reviewed and integrated as `080dffd`: direct guarded submission, History, Settings and truthful activity without new authority. These changes improve admissible choices and evidence handling; they do not make model advice causal proof.
- Alternatives/failures (retrospective): B's archived actual-Qwen facts used unregistered names/values and had zero useful prospective tests. The first full v6 suite exposed three legacy assertions and then one fixture predicting an already completed probe; B repaired those test expectations without weakening the v6 validator. The first pinned-Qwen v6 attempt at `051b17c` hit a completed output-token limit, then failed retry startup with an occupied endpoint; no listener owner was captured, so a service leak was not established. B's two lifecycle tests were RED before A `3505d0b`; its same-session retry then passed live but omitted the prediction menu. B's next two RED fit tests showed the menu was discarded before much larger optional catalog/graph material. At `fe9e16d`, a live fitted menu survived, yet the first model answer failed advisory validation (exact subtype uncaptured) and the bounded second answer still contained zero expected facts. C restricted source reviews and B's independent artifact audits are recorded outside Git. An official Microsoft evaluation ISO download command for replacement of the named qualification VM was automatically rejected before execution by approval review (`blocked by policy`); the earlier guest credential entry command was also rejected. Neither rejection was retried or bypassed. The VM stayed saved and offline; no fault was injected.
- Evidence/metrics: At `fe9e16d`, final non-MCP Python passed **3,397**, skipped 31 opt-in cases, deselected one MCP case and emitted seven expected warning-path notices in 636.89 seconds. Whole Pyright had zero errors/warnings; Ruff lint passed and format checked 622 files. Offline sdist/wheel built with 262 members each and no desktop, private DB/log/media/ISO paths. Desktop backend rebuilt; 12 unit tests, 17 real-backend/fixture end-to-end tests with one packaged opt-in skip, one separate packaged executable test, TypeScript, ESLint, Prettier, Vite and unsigned NSIS installer passed. The packaged app opened a visible `SystemSense` window; no clean-machine install was run. One actual pinned Qwen v6 call at `3505d0b` reused the same reported listener after output length stop and returned validated unresolved advice in 22.985 seconds, but its fitted prediction menu was absent. One later call at `fe9e16d` kept the exact registered `direct_origin_status=online|offline` menu plus 12 focused observations in both attempts; the bounded validation retry returned three unresolved rivals, one read-only probe proposal and zero expected facts in 20.016 seconds. These are functional attempts, not matched speed trials, independent affected-task outcomes or diagnoses. No actual-model prediction-to-observation-to-second-reasoning trajectory passed.
- Next question: Can an actual local provider produce a justified version-bound rival prediction and then revise after a matching independent observation without erasing counterevidence or promoting mere abnormality into cause? A real Windows pilot additionally needs accessible disposable guest media/login, a verified clean reset, and one controlled nonce-bound HTTPS 204 origin with independent CONNECT/502 receipts. A public 200 response and a closed proxy port do not satisfy that protocol. No training, cloud deployment, repair or fault was run.
- Artifacts: Outside-Git team board `%LOCALAPPDATA%\SystemSense\team-4766113` contains B/C reviews and sanitized private logs. First failed Qwen v6 attempt SHA-256 `9D904F539161A57780CBC872D46A2A6F2C951FC5CD4843FEABA60BB0860B4549`; same-listener retry `ECE5CBDC2EF6964160D375F7799BC6390F7B5F514A27AF307E3B61153116597A`; fitted-menu attempt `E05FD0497ED860AABBC0371B66A9BCBA65EEA0375BA16965B2F8A8F2E3B68825`. Final Python log `6F096E30701BE8A8037A87D2D257F01A84A8B7A1D6E4649223160079B77D10C4`, Pyright `48B2ECE9985AA0D5CE31FCC374BDC5F0D2A61AA71C76B3D9423D63911EEEDCAD`, Ruff `0473EC5EDB766C4C52F2CD44A06728E847C60B71FEEDCC7CA7D625A72C14E4A9`. Offline sdist `6A8DC9713F280C94B69E281BE4CA79E8DA2CBCF2E22A9325E17AAA67B272746A`, wheel `B18974FFC81C5532DE0F1DF48459E4FB4977E86B08AE12A064D62F5BB1004230`. Desktop backend build log `CD37F9E2B8A4787F8DA70BFA1F4DC334BD71B1E01084A193EC452A8C551E23E9`, end-to-end log `851EE1D6F14EBCD2DD66B2BFC858C7CA4B6FE282AF1217BEA54AD8AFA3694ADA`, installer log `EA60B230A8BD2FBEFE3A8E0D9F3B1CBFAC1DA79B664DC17F3D1373742D54A262`, packaged executable test log `8CCA0CA79E8BFB54000CDD0AAE51BAC76E504E737C9DD4CC74ED1474CB76BEBD`. Unsigned installer SHA-256 `E259F7A9C8C5B138A08A07BCDD23AC29A3864090C280B1857E1DECCAA6936476` (132,411,424 bytes); bundled backend executable `990B9AB5B01481B483BE16BFC8D272B5BA9630F853F939EA311955093379C487`. Private logs, case data, screenshots and binaries are outside Git or ignored.

## 2026-09-27 20:00 PDT | Actual-model post-result and warm-frontier trials | `eaccb39`, `a2b8382`, `5920076`

- Goal/problem: The next real-model synthetic run needed a registered check selected by a model, its observed result, and a second grounded review that retains competing explanations. The first Qwen attempt at `5a48a6a` had neither an accepted source-bearing second review nor a model-origin execution link.
- Change and why: A added bounded validation-locus receipts at `2b10a2e` so a rejected return reports allowlisted field paths without raw model text. A added one late-evidence deep refresh at `eaccb39` because the prior frozen task could precede the probe result. A corrected the evaluator at `a2b8382` to separate post-result reasoning from exact model-origin execution; a same-ID proposal cannot retroactively claim an earlier fast-path execution. The one-cell runner at `5920076` prewarms pinned Laya and records bounded ranking outcomes and startup time.
- Alternatives/failures: The first source-bearing second Qwen request returned two invalid outputs. Later trials reproducibly showed `hypotheses.item.expected_facts.item.expected_value` missing; the existing strict boundary rejected it and a single bounded retry recovered. A post-result Qwen run returned validated unresolved advice with two rivals but no citation to the new probe evidence. The first warm Laya/Qwen run omitted prewarm; initial rankings hit deadlines and later rankings reported runtime errors. A trace rerun confirmed this; startup was then moved before case timing. The synthetic fixture offers retrievals only, so a successful Laya source ranking cannot be scored as a model-selected check. A third Qwen return in that first warm run exhausted output tokens; the prewarmed rerun's third return validated but still lacked new hypothesis citations. No validator, task checker or causal acceptance threshold was weakened.
- Evidence/metrics: Focused late-evidence regression passed 15 tests; evaluator correction passed three focused tests. At `9a4eeb9`, the last full non-MCP Python gate passed 3,398 with 31 opt-in skips, one MCP deselection and seven expected warning-path notices; later runtime/runner edits require final combined verification. In the `eaccb39` Qwen run, three deep requests/four returns produced one accepted post-result review in 33.147 seconds, no model-origin execution link, no assessment, terminal `no_progress`. In the prewarmed `5920076` run, Laya startup took 29.840 seconds separately, 19/19 retrieval ranks were nondegraded, app time was 39.173 seconds, Qwen completed three accepted reviews/four returns, but there were zero candidate snapshots/check links and no cited post-result rival update. These are synthetic mechanics, not matched speed or diagnostic utility.
- Next question: Can the existing general candidate catalog offer a relevant registered measurement in the exact frozen mixed frontier, preserve a model-origin admission/execution receipt, and obtain a cited post-result rival update? The named VM still lacks normal guest access and a checker-compatible controlled origin; no fault was injected. Founder permission to handle setup was acknowledged, but a prior automatic approval review denied ISO download and credential entry, so those actions were not retried.
- Artifacts: Private outside-Git manifests `a-v6-full-loop-refresh-once/manifest.json` SHA-256 `83F8981869AD34E18CE6B830820E198700D121CF23236D441F7B0060A0334FDE`, `a-warm-loop-once/manifest.json` SHA-256 `E6AC746FB74E05118030FDE541997CBD74E863262C4480D2A41BEBAD55AE8CEE`, `a-warm-loop-trace-once/manifest.json` SHA-256 `F3FAB594EC0BA916CDE9DF5A62397963B27D929CDD93BC427A3ACAC40DAF3F7A`, and `a-warm-loop-prewarm-once/manifest.json` SHA-256 `84C54390E6C6FAE4569990E03D852BBDC4EC839CE93A5492FEA20CA336FDBFE6`. Case databases, logs, hidden synthetic outcome and model text remain outside Git.

## 2026-09-27 20:28 PDT | Integrated gates and actual measurement lineage | `5920076`

- Goal/problem: Verify the combined runtime after the late-evidence change, then use an existing relevant mixed menu to test model-selected measurement admission and actual execution. Package the current backend while retaining the founder-visible Dyad instance and its case database.
- Change and why: No further production code was needed. A ran the complete non-MCP Python gate, whole static checks, offline packages, one opt-in actual Laya/Qwen synthetic performance case, rebuilt the desktop backend, and checked the desktop. The performance fixture uses the existing general candidate catalog's GPU and pressure measurements; its result distinguishes a model-origin admission from the browser fixture's unrelated same-ID probe execution.
- Alternatives/failures: The synthetic browser case had only retrieval alternatives, so its successful Laya ranks could not establish check selection. The performance case did have two exact model-selected, executed measurements, but the later Qwen response left five rivals unresolved and cited no new pressure counterobservation; no assessment followed. Desktop `npm run installer` first failed `EBUSY` when electron-builder tried to remove the `win-unpacked` directory used by the visible Dyad process. A retained that app and built into a separate outside-Git directory. An initial private packaged smoke called backend capabilities before startup completed and failed transiently; a bounded readiness retry passed. The failures and original package were preserved.
- Evidence/metrics: Non-MCP Python: 3,402 passed, 31 opt-in skips, one MCP deselection, seven warning-path notices in 689.09 seconds. Whole Pyright zero errors/warnings, Ruff lint pass, format 628 files. Offline source/wheel 262 entries each, forbidden private paths zero. Actual pinned Laya/Qwen performance test 1 passed/1 deselected in 38.47 seconds: two candidate snapshots, two matching admission/execution links, GPU and pressure status `ok`, a later Qwen task including the changed pressure evidence, final `insufficient_observability` with no assessment. Case time 21.313 seconds; active candidate ranking 9.586 distinct identities/second, below 20. Desktop rebuilt backend, 14 unit tests, 18 real-backend/fixture end-to-end tests with two opt-in package skips, TypeScript, ESLint, Prettier, Vite and unsigned private-output NSIS installer passed. A fresh packaged executable then passed isolated Dyad title, read-only capability and zero-case startup. No clean-machine install, Windows fault, matching policy-speed trial, causal accuracy or model utility was qualified.
- Next question: Can a relevant registered browser task check enter the existing candidate/admission path without broadening authority, and can a later local model cite the actual counterobservation while preserving rivals? The named VM is saved with its NAT cable off; prior automatic approval review denied ISO download and credential entry. The user authorized A to handle lab setup but normal guest access and a compatible nonce-bound 204/CONNECT-502 origin remain unresolved. No fault was injected.
- Artifacts: Outside-Git Python log SHA-256 `DFF90C18588BF8BB912CE1445E5BF1ED3F0DA3D4F1E45D6D0673C099EA40A78D`; wheel `ED1B3EC23E13928061F05B115E7B0819CF7C8D09F7E053CD58164FE3A374D610`; source distribution `6BA17E3AAE4E59E86E3991D4C7428C321FE5A4584C4AA8DA0AEFA5E4A104350F`. Performance test log `B5BF3FCC103D158C526AD005855C79EDC2F6CF6477BF6EB3D0C193BEA42D9959`, private case DB `D11EBB7D158F6C3ED6FA2B1CD17BB002FEBD272D02330F38253E9480AF0F0537`. Desktop e2e log `2712976831C3DCC7C62EEFCDF632FC763CA4C5606AC7A30A7854D334400C91F4`; private installer `D36B16D12569A3E115BD046E7921D4B5D21E126C92F51DAD331B17EAB944E421`; private packaged executable `8CC9C4AC1BA5FF6257092E9A5F00DBF909672EAFE66AA698B4C3180861B4365F`; passing packaged smoke log `D6CDAC5E2B2AAA81F7FE69827A06E52EDFD5C0B2E23AF87576AD94ED1EB77D41`. Private outputs and screenshots remain outside Git.


## 2026-09-27 | Subscription advisory loop | implementation `ac236bb`

- Scope: Continue the existing implementation worktree and preserve the four
  unpublished commits `4678e74`, `eda4d28`, `6faa2ca`, `9dd3e82` above `8f1face`.
  The user subsequently allowed same-model subagents; the lead retained integration
  and resource ownership. No old task, automation, training or VM work resumed.
- First blocker audit: The failed `9dd3e82` second request retained all nine
  evidence contexts, including 97% then 3% pressure and 92 C / 300 MHz thermal GPU
  telemetry. Offline fitting retained the focused observations. Rejected raw model
  text was not persisted, so its exact wording cannot be recovered. The existing
  focused-ID check detects omissions, not semantic correctness; it was preserved.
  No bound reported/observed affected task existed. There was no proof of upstream
  evidence loss or justification for training Laya. The latest Qwen trial remains
  failed: its second review was rejected after retry, despite successful scheduling.
- Change: Extract the existing fitted evidence and validation implementation into
  `StructuredReasoningProvider`, preserving Ollama behavior. Add explicitly enabled
  GPT-6 Sol advisory calls through an installed Codex app-server, with ChatGPT auth,
  fixed provider/model acknowledgment, ephemeral read-only threads, no environments,
  disabled/verified MCP inventory, bounded pipes/deadlines, cancellation and Windows
  Job custody. Custom routing and provider fallback fail closed. Server model
  acknowledgment is runtime evidence, not independent backend attestation; no full
  built-in tool inventory endpoint is available before the turn. Unexpected tool
  events or server requests fail closed. No paid API fallback is implemented.
- Transport failures: npm Codex 0.145.0 rejected the requested model. Bundled
  0.155.0-alpha.16 supports the tested path. The first synthetic subscription attempt
  (`sol-loop-01`) executed two Laya-selected checks but both deep calls failed.
  An explicit API base URL overrode auth-dependent subscription routing. Remove that
  override, reject custom effective routes, and add regressions; a connectivity
  check then passed. This failed attempt is not reasoning evidence.
- Exercised at `ac236bb`: `sol-loop-02` passed exact snapshot/admission/execution
  scoring for both registered GPU and pressure measurements. Both completed while
  Sol's first call was active; both appeared in the second request. Two Sol calls
  were accepted, taking 12.297 and 15.359 seconds. The later GPU rival cites thermal
  telemetry as support but says no sample is linked to slow game frames. The CPU
  rival cites the 3% reading as counterevidence while retaining the earlier 97%
  reading and possible process/power pressure. Driver/disk alternatives remain
  uncertain. The case ended `insufficient_observability`, no assessment, because no
  eligible unused probe could distinguish the remaining explanations.
- Independent review: A rubric frozen before reading the returns accepted the
  narrow subsequent-reasoning loop. Automated `score.json` explicitly leaves
  semantic correctness unevaluated. No target handle/window or affected-task
  observation was provided; missing frame-time overlap is explicit, but game/adapter
  identity analysis is absent. Changed hypothesis IDs retained seven final rivals,
  including obsolete wording requesting evidence already delivered; one same-ID
  update was rejected. This is not complete rival reconciliation, Windows diagnosis,
  a matched Qwen/Sol comparison, speed qualification or training-label qualification.
- Artifacts: Private directory `%LOCALAPPDATA%/SystemSense/team-4766113/sol-loop-02`
  retains exact model inputs/returns/runtime acknowledgments, SQLite custody and
  traces. Full Laya worker capture was off. Case DB SHA-256
  `5cc6b1734e5ab5a02fc0ac885522e292fd5818c2f239c61c122fbdb5668327f6`;
  custody JSON `0d7ebb42ff01100988de9ce313196acd84c4ee8736923a6ec8344956c2c8cb01`;
  second raw return `af9aad6d7e72519ce7d504eaff1fa8a591a03314a63c236ee94e094b45e02d17`.
  The private old-request audit SHA-256 is
  `b52ab5cd38e76187088f7a6ed727407e0afc6ce6f66777a198035ed7974c7825`.
- Boundaries: The default desktop inference profile is unchanged. The open Dyad
  package and real case database are preserved. No host fault or repair, new paid
  API, VM credential entry, ISO download, model training or bulk data was attempted.
  The prior VM/controlled endpoint restrictions still block Windows qualification.

- Verification on code `ac236bb`: Focused changed-path regressions passed, including
  rejected auth/provider/environment/MCP/custom-route preflights, malformed returns,
  expired/cancelled calls and false-positive execution scoring. Whole Pyright found
  zero errors/warnings; Ruff lint and format passed (634 files). Offline source and
  wheel builds each contain 265 entries, with no private case artifacts. Wheel
  SHA-256 `664dec2aecb4d15bd426a05386ddc9de31d27be63ca3ec8f945dc5fb9165d74e`;
  source `807dcbde9b24e218b27f2680014ae1ad4ad594c03d3aaf9e94a01e7b98d1ab01`.
  The desktop backend rebuilt; 14 unit and 18 rebuilt-backend/fixture end-to-end
  tests passed, with two packaged opt-in skips. TypeScript/Vite, ESLint and Prettier
  passed. No new installer or clean-machine qualification is claimed; the existing
  open packaged app was preserved.

- Final combined gate on `ac236bb`: `python -m pytest -m 'not mcp' -q` passed
  3,446 tests, skipped 32 opt-in/runtime-specific checks, deselected one MCP test,
  and emitted seven warning-path notices in 719.12 seconds. The successful explicit
  subscription trial is recorded separately, not counted as a default-suite pass.
  Log SHA-256 `3e13e13b874cde3b64ca2b20529e01bc4f45e3ae989acf967ca0a779db844899`.
  All seven changed Markdown documents have valid local file links; integrated
  diff whitespace checks passed. Subsequent delivery changes are documentation only.

## 2026-09-28 | Frozen development suite through v6 and v7 custody | `f4dc325`

- Scope: A frozen 12-case synthetic suite covers network/browser, application/storage
  and GPU/resource families, split six development and six heldout by case. The
  evaluator-only oracle, case/action contracts and scoring revisions are separate
  from provider inputs; every attempt remains available for audit. The heldout
  cases were not used for these development results.
- Baseline limitation: The older `fc7f814` six-case baseline verified one useful
  fast-origin loop. Its database predates durable deep-proposal origin links, so
  missing deep receipts are unknown, not zero. Early score versions were retained
  after corrections; semantic review remained independent of mechanical scoring.
- Exercised at `662a498`: One actual Laya/Sol attempt per development case gave
  four verified useful fast-origin loops and three deep-origin loops, overlapping
  in one case. All six had a registered useful choice, exact execution, later
  accepted deep response and meaningful use of the selected observation.
  All final causal assessments were null. Review of 18 saved Sol raw returns
  found no unsupported definitive cause, but found stale or incomplete retained
  rival rows, especially old false-absence wording after newly observed GPU or
  application evidence. This is a finite synthetic review, not Windows accuracy
  or complete final-state correctness.
- Reliability scope: The six v6 case times were about 30–75 seconds. Its 18 Sol
  calls had no validation retry prompts or captured failures; v5's single run had
  27 Sol calls, eight retries and three deadline failures. Those counts exclude
  Laya worker calls and are not a controlled latency or reliability guarantee.
  Laya cold startup was recorded separately at 15.891 seconds. Full worker input
  capture was absent, and sampled resources were not host/GPU peaks.
- Built at `f4dc325`: Source-verified missing-ID retention and per-rival typed
  noncausal references can preserve a newly observed limitation without treating
  it as causal support. An accepted same-ID async revision requires exact frozen
  prior, reviewed fitted source, applied response and transactional lineage.
  Focused reasoning, storage and in-process checks passed 154 tests with scoped
  Pyright and Ruff. A model's typed disposition remains advisory; this v7
  behavior had not yet received an actual-model qualification review.
- Verification boundary: The last whole non-MCP audit before this integration,
  on `d9849b7`, passed 3,631 tests with 32 skips, one MCP deselection and seven
  warning-path notices. No whole-suite, build or desktop result on `f4dc325`
  is claimed here. The older search, toy-world, VM and subscription-loop trials
  remain in their dated entries above rather than being duplicated from the
  former current-state checklist.
- Artifacts: Private review
  `%LOCALAPPDATA%/SystemSense/overnight-20260928/candidate-v6-semantic-review.md`
  has SHA-256
  `63342D0EC535D723874573D317C7B6B888AC87D6AF7D32A062137ADEB9E1A606`.
  Private `freeze-v2.json` has SHA-256
  `18587466D52E8A3A39A9B79779FA1C5639CC598D4FFD2FC5FBB8C288FEEE2994`.

## 2026-09-28 | Integrated overnight evaluation | `5866a83` through `12990ad`

- Scope: frozen 12 synthetic cases, six development and six case-heldout across
  three existing families. User authorized Sol implementation workers and one
  lead integration owner; old A/B/C/D sessions and automations stayed stopped.
  No training, paid API fallback, new faults, repair or VM denial bypass.
- At v12, retained all 123 development attempts. Baseline Laya–Sol used 22 calls/seven
  retries; candidate v12 used 16/one, with zero captured call failure in both.
  Candidate observed previously missed low disk and corrected GPU/other-app rival
  context. All six summaries current; all six final assessments null. Complete
  per-case findings, comparator limits and heldout results live in the canonical
  benchmark scorecard, not this history.
- Intermediate candidates were not hidden: v7 had 20 calls/18 returns, one retry
  and two deadlines; v8 had 21/20, two retries and one thermal deadline; v9 had
  21/20, no retry and one application deadline; v10 had 18/18 with no retry/failure
  but redundant application consultations; v11 had 15/15 with no retry/failure.
  V12 was selected after prediction-order and audit-plan hardening, not because
  its stochastic call count was the lowest. Two repeated network-configuration
  checks meet the frozen mechanical utility rule without new information gain.
- Runtime changes: retain unavailable evidence, support custodied noncausal rival
  context without turning it into causal support, meter Laya protocol requests,
  coalesce small registered follow-up batches and review their terminal basis once.
  Partial-source and queued no-new-fact turns no longer silently consume or repeat
  the terminal review. Separate source-generation freshness from semantic quality.
- First combined gate at `994305a` failed five tests (3,693 passed): a prediction
  reconciliation order failure and four incomplete test doubles. `ff348aa` restores
  prediction reconciliation immediately after collection and before deep review;
  test doubles initialize the added scheduler state without weakening assertions.
- Independent provenance review found that a wrong nonempty plan ID could earn a
  deep-origin receipt. `ef2ed6f` and `5866a83` require the full durable audit chain
  and exact execution plan/case/probe/outcome/finish time/parameter digest. Audit
  persistence now precedes the optional receipt within the same transaction.
  Empty/wrong plan and corrupt-audit tests preserve observed execution while
  rejecting false attribution. All 105 earlier scores were reissued under ef2
  with no result changes except scorer revision; old files remain intact.
- Intermediate product gates at `5866a83`: 3,702 non-MCP passed, 32 skipped, one MCP
  deselected, seven expected warning-path notices; 147 focused passed; whole
  Pyright/lint/format passed. One opt-in own-process creation-identity check passed.
  Offline wheel/source builds each contained 268 entries, excluded private
  artifact names and included migration 038. Rebuilt backend and 18 desktop E2E
  checks passed (two opt-in packaged checks skipped there). Private unpacked
  package separately passed launch/read-only case/cancellation with fresh user data.
- Original-loop `old-loop-regression-5866a83` preserved legacy mechanical false.
  Investigation proved actual Laya-selected GPU/pressure execution and later
  accepted typed noncausal review; the older scorer did not recognize that form.
  Final CPU rival did not retain its newer reference, while GPU did. A separately
  versioned benchmark check accounts for the new review protocol without altering
  the old score. Complete rival retention is not claimed; no success-seeking rerun.
- Verification evidence: `verification-5866a83.json` binds logs and artifacts.
  Wheel SHA-256 `10d843d3e306a16237d55c013da6cf151cadd61403b423c8daeef42efd6b254d`;
  sdist `83ec781667a0cb3f20d07ec30425fa50502b01a3f0c4fdd1b704d71bfcc53d4d`.
  Private packaged smoke passed one test in 4.2 seconds. The existing open
  `desktop/release/win-unpacked/Dyad.exe` hash stayed
  `8cc9c4ac1ba5ff6257092e9a5f00dbf909672eafe66aa698b4c3180861b4365f`.
  Open Dyad, the real case database and unrelated Ollama remained untouched.
- Qualification boundary: every fixture lacks an independent affected-task outcome.
  Agent semantic review is not blinded human evaluation. Real Windows causal
  accuracy, production cloud routing, signed/clean-machine installer, repair and
  training admission remain unqualified. Previously blocked VM access/endpoint
  outcome protocol remained blocked; no workaround was attempted.

- The followup was chosen before heldout answers were read: the original-loop CPU
  response combined a valid time-unbound reference with new support and changed
  prose, causing whole-proposal rejection. Worker `41b2fa4`, integrated `12990ad`,
  preserves only the validated reference while retaining all prior rival fields.
  Exact saved-response replay and 161 integrated focused tests passed. Independent
  review caught status normalization and added hostile unavailable/foreign,
  reclassification and transactional-forgery coverage. No schema or prompt changed.
  All 12 unchanged baseline heldout attempts were reused by predeclared rule;
  all 18 intermediate candidate attempts remain in the record.
- Final v13 `12990ad` retained 141 development attempts. Laya–Sol used 16 calls,
  zero retries/failures and 89 completed Laya protocol requests; hybrid used 19
  calls with zero retries/failures. Source was selected for verified custody and
  reference retention, not the lowest stochastic call count. The PageDesk third
  consultation consumed newly expanded event detail. Hybrid thermal rival
  freshness still failed despite its correct summary.
- Final heldout execution completed before grading began at 13:28 UTC. Final Laya
  used 15 calls/15 returns, zero retries/failures and four of six useful chains.
  Both GPU cases missed `local_ai.snapshot`. Baseline used 20 calls/19 returns,
  five retries and one failure. Intermediate Laya used 14 calls/14 returns.
  All 48 heldout attempts are preserved: 12 baseline, 18 intermediate, 18 final.
  No source changes followed heldout results. A broad text search accidentally
  returned generic heldout SHA/ID lines before release; this protocol slip is
  disclosed in the custody artifact. No heldout answer informed candidate choice.
- Final original-loop `12990ad` exercised CPU reference-only projection and
  retained both GPU and CPU noncausal references. Two raw Sol returns, no retry or
  failure; legacy mechanical false, version-2 review-loop true. Both raw returns
  and saved rivals were reviewed; no game-frame cause was established.
- Final `12990ad` verification: 3,738 non-MCP passed, 32 skipped, one MCP deselected,
  seven expected warnings; 161 focused passed; whole Pyright/Ruff/format passed.
  Own-process identity check passed. Offline wheel/sdist each had 268 entries and
  migration 038. Desktop backend rebuilt; 18 E2E checks passed with two packaged
  opt-ins skipped. Separate private unpacked launch/read-only case/cancel smoke
  passed. Open app ASAR/backend hashes were unchanged. `verification-12990ad.json`
  SHA-256: `8356c2c3e1158ec9f3756fdc1bbc89fcdd2ee442ce9eeac5551b1ba62e184d56`.
- Audit readers initially misdecoded UTF-8 or mishandled empty legacy fields and
  a copied suite digest. Corrected immutable v2 audits rechecked the sources and
  supersede those comparisons; the first artifacts remain preserved. All 189
  attempts are inventoried with 457 raw returns and 13 failed-call files. The
  current scorecard links the authoritative artifacts and records semantic failures.

## Reversible live host checks (2026-09-28)

- One duplicated active power plan and one dormant current-user WinINet proxy
  server value were each observed by a registered read-only collector and
  restored exactly. Neither establishes a performance or connectivity fault.
- A short-lived background process exposed two independent gaps at `25fab23`:
  explicit process wording did not select `application.snapshot`, and the
  256-row collector returned the lowest PIDs despite more than 680 processes.
  Saved source evidence from that attempt contained no application snapshot.
- `0b83e0f` routes process requests to that snapshot, preserves resource
  context for slow applications, and reserves bounded recent slices in the
  collector and exact-identity target candidate list. Live retest saved the
  temporary PID and creation time. An after-exit control lacked that identity.
  The compact report remained truncated, so the source database was checked
  separately; the unknown-cause outcome was retained. Five single-run case
  timings and limited RSS samples are in the canonical benchmark table.
- At integrated `a742ab9`, the non-MCP gate passed 3,748 tests with 32 opt-in
  skips. The two broad-suite failures on `0b83e0f` were stale test assumptions
  about seeded application probes and no-progress detail requests, corrected
  without changing product code. Whole Pyright, Ruff lint/format, and offline
  Python build passed. The rebuilt backend passed 18 desktop E2E tests; the
  private unpacked package passed one fresh-data smoke test. The original real
  case database was not used by those tests.

## Controlled affected-task trial (2026-09-28)

- At `868b94c`, an operator-only runner preregistered one temporary loopback
  fault and a separate healthy control. Trial 01 stopped before model calls when
  the exact failed GET timed out rather than refusing a connection. The runner
  accepted that exact failure class and preserved the failed attempt.
- Trial 02 independently verified both tasks healthy, the target failed with no
  listener while the control stayed healthy, and the target worked again after
  restoration. Both temporary services were removed after verification. Actual
  Laya and subscription Sol ran in both cases without receiving the operator
  action or independent outcome oracle.
- Diagnostic utility failed the frozen rubric. A complete saved target listener
  table lacked the target port, but the final Sol packet gave only a catalog
  summary, omitting the decisive rows and omission count. Sol made no false
  cause claim, but did not identify the supported sampled-time finding. The
  [benchmark record](BENCHMARKS_AND_ACCEPTANCE.md#controlled-affected-task-trial-2026-09-28)
  preserves timings and artifact hashes. The retrieval boundary, not model
  training, is the first demonstrated blocker from this trial.

## Controlled task repair and breadth (2026-09-28)

- Goal/problem: The failed controlled trial had a complete target-port listener
  table, but the final Sol brief lacked its decisive facts. The task also needed
  repeated blind outcomes, healthy controls, broader faults and measured speed.
- Change and why: `e02fb72` adds a bounded, source-linked target-port absence
  excerpt with completeness and time limits. `45d5d96` seeds the registered
  listener check for literal loopback tasks. `e9cf872` handles reused
  mixed-frontier items. `575ab7f` reserves exact-target evidence in each
  bounded reasoning brief. Deterministic code still owns probes and permissions.
- Alternatives/failures: The first optimized attempt crashed on a reused
  frontier item. The second completed but lost the decisive fact from its final
  bounded brief; no v2 heldout was run. Both faults were restored. Neither
  failure is counted as a correctness-equivalent speed result.
- Evidence/metrics: Two initial fresh no-listener cases and two optimized
  fresh cases gave the sampled-time exact-port finding with healthy controls,
  no unsupported cause and independently verified restoration. The correct
  warm failed-case means were 59.157 versus 48.477 s, an 18.05% reduction
  below the 25% target. A 503 response and a stalled response each retained
  a target listener; the actual Laya–Sol final states identified that later
  observation but left deeper cause unknown. Both healthy controls avoided a
  false failure claim. All new fixture processes were removed.
- Verification: 3,759 non-MCP tests passed, 32 opt-in skips; whole Pyright
  zero errors, Ruff lint/format and offline wheel/source build passed.
  Actual pinned Laya and acknowledged subscription Sol were exercised in
  the private live cases. The product did not itself observe the HTTP GET.
- Next question: Can a registered read-only request observation safely bind
  the affected task outcome and distinguish a responding listener from a
  stalled one while preserving the model's uncertainty? Can repeated Sol
  reviews or broad weakly relevant checks be reduced without losing useful
  exploration?
- Artifacts: The [canonical benchmark record](BENCHMARKS_AND_ACCEPTANCE.md#controlled-task-repair-and-breadth-2026-09-28)
  lists frozen protocol hashes, timing, database hashes, failed attempts and
  private custody under
  `%LOCALAPPDATA%/SystemSense/controlled-task-repair-20260928`.

## Target-listener packet and resource follow-up (2026-09-28)

- Goal/problem: Each successful no-listener Sol brief still carried a roughly
  4 KB duplicate raw listener list alongside its complete source-linked
  target-port search; process resource impact was not measured.
- Change and why: `6c278e4` omits the duplicate raw list from these
  target-search briefs while leaving persisted rows available to bounded
  detail retrieval. The source completeness and temporal limits stay in
  the brief. A red integration test reproduced the duplicate before the
  fix; 18 focused tests, whole Pyright and scoped Ruff checks then passed.
- Evidence/metrics: A frozen development/heldout pair retained the exact
  sampled-time finding, correct healthy controls and independent restoration,
  with first Sol prompts 4,065 bytes smaller. Warm failed-case mean was
  61.876 s, 4.60% slower than the initial correct baseline; a 45.625 s
  heldout Sol call dominated. The size reduction has no proven latency gain.
  A separate 513-sample owned process-tree trial peaked at 3.14 GB RSS
  and 17 processes, with CPU time at least 85.078 s. GPU use and very
  short-lived process peaks remain unmeasured.
- Alternatives/failures: The 25% speed target still failed. No repeated
  probe executions occurred in the v3 failed pair, while six of nine
  collected probe types per case were uncited in final hypotheses. That
  count alone cannot show whether their collection was useless.
  Selection and local wait phases were not separately instrumented.
- Verification: The exact `6c278e4` source passed 3,759 non-MCP tests
  with 32 opt-in skips and seven expected warning-path notices in 705.23 s.
  Whole Pyright returned zero errors; whole Ruff lint/format and offline
  wheel/source build passed. The preserved v4 and resource cases separately
  exercised the actual pinned Laya–Sol route.
- Artifacts: The [benchmark section](BENCHMARKS_AND_ACCEPTANCE.md#controlled-task-repair-and-breadth-2026-09-28)
  records the v4 and resource protocol hashes, exact results, limitations
  and private artifact paths.

## Private-alpha local task candidate (2026-09-28) | `aa5520a`

- Goal/problem: The desktop default did not expose the actual Laya–Sol path,
  and a normal one-description case did not independently observe the
  affected task. The earlier exact loopback fixture remained test-owned.
- Change and why: Add explicit model mode/readiness, fail-closed startup,
  saved task outcomes and model activity, plus one bounded user-owned exact
  local health GET. Bind its result and frontier event to the case before
  allowing Laya to select the registered listener check and Sol to review
  both timed observations. Keep Basic a meaningful response-aware comparator.
- Failed attempts preserved: The first v1 development run missed the 503
  scoped closure. A broad-suite attempt failed three tests after a legacy
  common-resource probe was removed and a factory callback changed; the
  resource behavior was restored and the test updated for the callback.
  A later 13-case speed attempt made 26 Sol calls because the exact task
  observation had no frontier result event; its median was 28.906 s and
  p90 32.375 s. The event repair reduced this to one Sol call per case in
  subsequent runs without broadening probe authority.
- Verification: Source `aa5520a` passed 3,785 non-MCP Python tests,
  32 opt-in/environment skips, one deselection, whole Pyright and Ruff,
  desktop unit/lint/type/format, packaged real-model healthy/503/cancel,
  private installed real-model healthy/503/cancel, Basic installed startup,
  and clean uninstall. The clean-source development repeat and reserved
  holdout completed 26/26 model cases with 26/26 independent restoration.
- Measured result and limit: Across 24 real-access cases, automated and
  manual screening found 24 scoped model findings versus 14 automated Basic
  candidates. Model warm median/p90 were 14.485/17.906 s; peak sampled
  evaluator-tree RSS was 2,295 MiB. Manual review found no unsupported
  definitive cause or healthy false failure. The candidate offers only one
  registered measurement per exact task and one local HTTP family. No
  three-family adaptive or verified-root-cause claim follows from it.
- Artifacts: [Benchmark and acceptance](BENCHMARKS_AND_ACCEPTANCE.md#private-alpha-local-health-task-qualification-2026-09-28)
  records the frozen inputs, report hashes, installer hash and private evidence
  location. No controlled fault or private installation remains active.

## Exact named-process investigation candidate (2026-09-29) | `420e5c7`

- Goal/problem: A normal process complaint could reach the application snapshot,
  but the compact case view omitted the exact process on this busy host. Host
  CPU samples could not distinguish the named process from other activity.
- Change: Rehydrate exact named rows from a saved source of up to 512 processes;
  prove complete-table absence only when coverage permits it. Bind a unique
  name to PID and creation time before the existing read-only target CPU
  sample, recheck identity at collection, reserve its exact timed facts for
  Sol, and remove irrelevant narrow-case storage work from streaming and
  event-driven candidate admission. Freeze 16 owned-process Windows trials
  with separate evaluator recipes and paired Basic/model scoring.
- Failed attempts preserved: The first live process pilot lacked an exact row
  in the report. The first eight-case host run had three CPU case failures:
  completed target pressure disappeared from a later Sol capability catalog,
  and one sample falsely reported PID reuse after a one-microsecond timestamp
  round trip. The repaired eight-case run completed but took 47.266 s median
  and 62.797 s p90. A later completed CPU case omitted its target sample from
  Sol's focused view and gave a generic unknown. Initial probe filtering
  missed the event frontier; another case still ran storage despite a CPU-only
  objective. The first focused suite for that filter failed 18 existing broad
  frontier tests because its case catalog was applied universally; the filter
  was narrowed to exact process cases and 190 focused tests passed.
- Evidence so far: The final exploratory busy/idle pair omitted storage,
  reported the exact 3.903–3.969% and 0% target samples respectively, took
  24.062/23.469 s warm, and restored/terminated all owned helpers. These are
  observations during measured intervals, not proof of application cause.
  See [frozen owned-process qualification](BENCHMARKS_AND_ACCEPTANCE.md#frozen-owned-process-qualification-2026-09-29)
  for protocol and remaining clean-revision gates.
- Verification so far: 190 focused tests and 48 event-frontier tests passed;
  whole-project Pyright and Ruff, desktop unit/lint/type/format and offline
  `uv build` passed. An initial `python -m build --no-isolation` failed because
  this virtual environment lacks Hatchling; the configured offline build
  succeeded. The first full non-MCP run at `420e5c7` failed nine tests after
  3,805 passes and 32 skips. Eight failures showed that candidate filtering
  had incorrectly removed broad concurrent follow-ups; one showed that a
  general application report saying "hangs" had lost its established resource
  baseline. Commit `ab01826` confines the filter to exact named-process cases
  and restores the general application baseline. The 26 overlap/follow-up
  tests and a further 68 baseline/frontier tests passed after the repair.
  The full-suite repeat and clean paired cases remain pending. A desktop E2E
  attempt passed 18 cases, skipped three opt-in checks, and failed one
  fixture-only landing-height assertion at 150% zoom; its trace is saved under
  `desktop/test-results`. It is not counted as a packaging pass. The host
  scorecard now counts Laya candidate-ranking receipts separately from the
  provider-call list, which omits those calls in process cases.

## Exact process full-loop repair (2026-09-29) | `94d1154`

- A paired host development run at `d620549` completed 8/8 observations and
  returned useful sampled facts, but Laya ranked only the four liveness cases.
  CPU target sampling used a deterministic path. Basic was upgraded to report
  the same exact process facts, so the model path gained no host usefulness
  advantage in that comparison.
- `857cf71` offered the prebound CPU target to Laya. Focused H03/H04 trials
  exposed a dispatch failure: each Laya rank was admitted, but the frozen
  rank deadline expired before the worker claim. No target sample ran; both
  final answers said CPU use was unknown despite an available decisive check.
  `9b4e5a3` reserved two bounded seconds for the worker claim. Focused busy
  and idle reruns then claimed and executed the read-only sample and reported
  the measured activity correctly.
- The paired `9b4e5a3` development run completed 8/8 exact observations,
  but H08 retained a preliminary system-wide CPU answer after its later Sol
  revision failed validation. The exact process sample was in the product
  case; the error was `ReasoningValidationError:revision intent retires unknown
  prior support`. Commit `94d1154` waits for the exact CPU sample before the
  first Sol review. A focused H08 rerun and then a clean eight-case paired
  repeat produced bounded exact-process summaries in all eight model cases.
- The `94d1154` host model median/p90 were 20.609/24.469 s with 12 Sol calls;
  Basic was 6.212/8.531 s and also summarized all eight decisive facts.
  The current-revision HTTP development repeat completed 13/13 model cases,
  with 12/12 automated real-access useful-finding candidates against Basic's
  7/12 and 13.250/17.313 s model warm median/p90. Neither test set offered
  more than one measurement to Laya per rank; adaptive multi-choice value and
  three materially different diagnostic families remain unproven. All failed
  attempts and evaluator-restoration receipts remain under the private local
  benchmark directory linked from [benchmark acceptance](BENCHMARKS_AND_ACCEPTANCE.md).
- Integrated code checks at `94d1154` passed 3,827 non-MCP Python tests,
  32 opt-in/environment skips and one MCP deselection; whole Pyright, Ruff
  lint/format and offline wheel/source build passed. Desktop 17 unit tests,
  TypeScript, ESLint and Prettier passed. The rebuilt packaged executable and
  a private silent installation each passed the live healthy/503/cancel
  Laya-Sol desktop test; the installed Basic startup/cancel test passed. The
  private copy was uninstalled with exit 0 and no remaining install path,
  Dyad process or uninstall entry. Installer SHA-256 is
  `4956ac10b1d40da474ba1e8b7b3185c7fe38360a2b2fd4920d7818a108a791cf`.
  The earlier 150%-zoom landing-height fixture assertion remains a known UI
  E2E failure; no UI work was authorized for this task.

## Exact-target exploratory repair and private installer check (2026-09-29)

- After the first host holdout at clean `48e4270`, a PDF-worded exact CPU
  question exposed a source-bound attention failure. The first four-process
  trial timed out before worker claim; after a claim-window repair, Laya
  selected `System` rather than the named test-owned process. Two more live
  trials chose `System` or `Registry` despite the named target's presence.
  Sol left target CPU unknown. All attempts and evaluator readings remain in
  the private alpha directory. These are genuine useful-check misses.
- `9cdf2b7` filters a literal named CPU request to source-matched process
  identities before ranking and preserves worker-claim time. Three subsequent
  busy/idle-with-busy-distractor pairs completed: six Laya rank/claim/sample
  chains, six applied Sol findings using exact target CPU deltas, and six
  independent idle restorations. Warm median/p90 were 21.454/22.922 s;
  sampled evaluator-tree peak RSS was 2,313 MiB. The recipes were exploratory
  and known to the evaluator, not unseen holdout cases. The one-candidate
  menu did not prove adaptive choice, and no PDF page outcome was measured.
- The first paired Basic comparison timed out twice because broad PDF routing
  waited for manual process selection. Those runs recorded failed in-run
  restoration despite exiting owned processes. A separate independent
  recovery restarted the exact test executables in idle mode, verified normal
  behavior and stopped them. `7ecce21` prioritizes explicit CPU routing on
  both paths; the next Basic pair completed in 8.016/10.125 s with the same
  decisive target facts and restored normally. No model advantage is shown
  on this CPU question. An evaluator regression now checks restoration after
  a product exception.
- Code `7ecce21` passed 3,834 non-MCP Python tests, 32 skips and one
  deselection; whole Pyright, Ruff lint/format, offline wheel/source build,
  desktop 17 unit tests, TypeScript, ESLint and Prettier passed. PyInstaller,
  NSIS, packaged metadata, bundled-backend Basic and privately installed
  backend Basic checks passed. Two installed desktop smoke attempts failed
  because the external script read the earlier case before the new case
  completed; preserved receipts show that race. The corrected third run
  completed Basic healthy/HTTP 503 cases, History reopening and endpoint
  restoration. Installed Laya–Sol correctly showed blocked readiness and
  created no case while unrelated GPU work left insufficient free VRAM.
  The private install was uninstalled; path/entry/process absence and the
  unchanged pre-existing case database hash were verified. Current-source
  actual-model and three-family adaptive qualification remain open.

## Stronger deterministic comparator and natural URL intake (2026-09-29)

- A fresh clean Basic repeat at `d0e7949` matched 8/8 frozen owned-process
  development outcomes and restored every helper. Its HTTP development repeat
  saved and restored 13/13 exact GETs but produced only 7/12 automated scoped
  findings on real-access cases: timed-out GETs did not trigger the existing
  listener check. `d9c3755` admits that read-only check after a custodied failed
  replay and reports only the later exact-port state. An exploratory 13-case
  before/after on the same recipes raised Basic to 12/12 scoped candidates;
  warm p90 rose from 2.360 to 2.797 s and sampled peak tree RSS from 73 to
  121 MiB. This removes the apparent local HTTP usefulness advantage over
  the earlier weak Basic comparator. It does not establish model value on
  another family.
- A new 26-case local HTTP cohort was frozen before using its development
  split; the 13-case holdout remains unrun. The first private evaluator
  wrapper attempt failed before any product case because its external Python
  path could not import `benchmarks`; the wrapper was repaired and the setup
  error preserved. Clean `d9c3755` then completed/restored all 13 development
  cases but saved task outcomes in only nine. Four neutral prompts placed a
  question mark immediately after the fixed URL. Intake rejected them and
  returned generic unknown, leaving only 8/12 real-access useful candidates.
  The failed product cases and scorecard are preserved unchanged.
- `2a4c1d4` accepts terminal `?` and `!` after the fixed URL while rejecting
  query strings and broader targets. Red parser tests reproduced the miss;
  focused tests and a dirty development repair then passed. A clean 13-case
  repeat saved every task outcome, restored every endpoint and screened 12/12
  real-access scoped findings; warm median/p90 were 0.344/2.812 s with
  120 MiB sampled evaluator-tree peak. Manual review found no false healthy
  failure or unsupported definitive application cause in those Basic finals.
  The 13 holdout cases were not opened or run.
- The final code passed 3,840 non-MCP tests, 32 skips, one deselection and
  seven expected warnings; whole Pyright, Ruff lint/format, offline source/
  wheel build, desktop 17 unit tests, typecheck, lint and format passed.
  PyInstaller and the unsigned NSIS installer built. A private installed
  desktop passed Basic healthy, HTTP 503, stalled-response and no-listener
  real task smokes, plus model-mode readiness denial under insufficient GPU
  headroom. Each controlled endpoint was independently restored. Uninstall
  exited 0, left no install path, owned process or uninstall entry, and did
  not change the pre-existing case database hash. This does not qualify an
  installed current-source Laya–Sol run or a clean machine.

## Resource-denial setup reporting (2026-09-29)

- The installed model route correctly blocked a case under insufficient GPU
  headroom but only displayed “The local Laya model could not start safely.”
  A red focused test first failed because there was no admission-reason
  translation. `24c0e28` captures the managed admission reason before closing
  the provider and maps only known VRAM/RAM denials to a specific wait-and-
  restart instruction. Unrecognized worker failures retain the generic text;
  the admission threshold and no-fallback policy are unchanged.
- A first ad hoc Python command to inspect the live message failed from shell
  quoting before invoking the provider. The corrected live attempt under
  3,645 MiB free VRAM returned the specific GPU reason. The full non-MCP suite
  passed 3,843 tests, 32 skips, one deselection and seven expected warnings.
  Whole Pyright, Ruff, offline wheel/source build, desktop unit/type/lint/
  format/build, PyInstaller backend, NSIS installer, packaged metadata and
  Basic health checks passed. The new private installed-desktop model check
  showed blocked readiness, disabled Investigate and no case. Its Basic
  healthy/HTTP 503 pair saved both task outcomes and restored its test server.
  Uninstall removed the private directory with no owned process or entry, and
  the pre-existing user case database hash stayed unchanged. Installer SHA-256
  is `0ea2f43e2a57cf5c4ff24191d3608c038a4f67ef060de8300691f8d069bbccc1`.
  Actual current-source Laya–Sol investigation remains blocked by the
  unrelated GPU workload.
- With a clean `a80c036` source tree, the fresh frozen v3 development Basic
  arm completed 13/13, saved 13/13 exact task outcomes, independently
  restored 13/13 endpoints and met the scoped candidate screen in 12/12
  real-access cases. Warm median/p90/max was 0.344/2.813/2.813 s; sampled
  evaluator-tree RSS peaked at 120.203 MiB. Manual review found no false
  healthy failure or unsupported definitive application cause. The one
  synthetic missing-access case was excluded from the 12 real-access cases.
  The frozen holdout remains unused, and no model arm ran at that revision.

## Healthy replay outcome and repeated private installation (2026-09-29)

- An installed healthy control returned the expected nonce but History called
  it "insufficient evidence." A red integration check reproduced that wrong
  outcome. `93964b7` now classifies a source-verified successful exact GET as
  awaiting recurrence when no trusted later listener check contradicts it.
  The check requires exact task custody, an actual successful execution and
  correct observation order. Failed GETs remain observed failures with an
  unresolved request-time cause. A copied historical actual-model healthy
  case also satisfied the new helper in read-only replay; that is not a
  current-source model investigation.
- The first whole-suite attempt after the edit was interrupted at 7% when
  the execution-status guard was added; its log is preserved. At final code
  `93964b7`, the non-MCP suite passed 3,843 tests, 32 skips, one deselection
  and seven expected warnings. Whole Pyright, Ruff lint/format, offline
  wheel/source build, desktop 17 unit tests/type/lint/format/build,
  PyInstaller backend, NSIS installer, packaged branding/storage and bundled
  backend Basic checks passed.
- The unsigned `93964b7` installer is 132,668,016 bytes, SHA-256
  `1546694a3d4b0aa76e89f8d42c970d2e2975e9b22406e7afbcd7561338a161f6`.
  Its private native desktop run saved the healthy exact-task result and
  displayed "waiting for recurrence" in History; an HTTP 503 control saved
  its failure outcome. The evaluator independently confirmed HTTP 200 after
  restoration. Installed model setup correctly remained blocked by low GPU
  headroom with no model case. Uninstall exited 0; no private install path,
  owned process or uninstall entry remained, and the pre-existing user case
  database hash was unchanged.
- A clean `93964b7` Basic run of the frozen v3 development split completed,
  observed and independently restored all 13 cases. Twelve of 12 real-access
  cases met the scoped candidate screen; the synthetic missing-access control
  is separate. Four matching GETs, including an intermittent report's healthy
  replay, ended as awaiting recurrence. Manual review found no false healthy
  failure or unsupported definitive application cause. Warm median/p90/max
  was 0.360/2.796/2.812 s, and sampled evaluator-tree RSS peaked at
  120.313 MiB. The scorecard SHA-256 is
  `5efebbb28dbee8790e45d518cd4b517c553f7c230af79d138d0eb9a7a9580f62`.
  This is a Basic-only candidate screen, not a current-source Laya–Sol
  comparison or verified root-cause diagnosis. The 13-case holdout remains
  unrun; the unrelated GPU workload still blocks Laya admission.
- Three clean `e40ca88` Basic repeats of those same 13 development cases
  completed, observed and independently restored 39/39 runs with fresh local
  ports; 36/36 real-access runs met the narrow candidate screen. Pooled warm
  median/p90/max was 0.360/2.813/2.828 s and maximum sampled tree RSS was
  121.25 MiB. A separate clean owned-process Basic repeat matched the
  independent process/CPU oracle and restored/exited helpers in 8/8 cases;
  warm median/p90/max was 6.149/8.375/8.375 s and sampled tree RSS peaked
  at 250.582 MiB. The private scorecards preserve each case and source hash.
  Repeating development cases measures narrow stability, not new blinded
  breadth or model value.
- At the same packaged code, two real-backend desktop lifecycle tests passed.
  The first external built-package lifecycle script failed because its
  readiness poll treated transient startup as terminal; that attempt is
  preserved. A corrected external script passed without changing the product:
  a cancelled case retained one evidence row, reopened after restart and left
  no active case. Built-package normal-desktop checks passed healthy,
  HTTP 503, stall and no-listener with independent endpoint restoration.
  The test package processes exited and the pre-existing user case database
  hash remained unchanged. These are Basic checks; current-source installed
  Laya–Sol execution remains blocked by the unrelated GPU workload.

## Direct process finding and installed WMI correction (2026-09-29)

- A direct “is this exact `.exe` running now?” Basic case initially ended
  `insufficient_observability` even though a complete inventory could answer
  that narrow question. The first red live test exposed missing
  `application.snapshot` routing for wording without “process”; after routing,
  a second red result exposed the missing terminal observed-finding path.
  `fc537fc` now re-reads the saved same-case source and successful execution,
  checks completeness and exact name, and emits a typed assessment citing the
  snapshot. It never turns a causal “why did it stop?” question into a cause.
  The incomplete-inventory control remains unresolved. The first whole-suite
  attempt after routing was interrupted at 7% while source-custody and citation
  checks were completed; the final code passed 3,847 non-MCP tests, 32 skips,
  one MCP deselection and seven expected warnings in 802.93 seconds. Whole
  Pyright, Ruff lint/format and offline source/wheel build passed.
- A clean installed-wheel smoke initially failed from missing CLI arguments,
  then from using a virtual environment inside the forbidden source root.
  Once run from a separate core-only environment, it exposed three stale
  fixture assumptions in order: the deterministic inference status gained
  configured/effective fields, the passive runner gained a `host_slot`
  argument, and the schema advanced from 5 to 38. The script now asserts the
  exact current contracts. The final external-wheel smoke passed package
  import, optional-dependency isolation, bundled references, passive probe
  receipts and SQLite integrity. Original attempts were not relabeled as
  passing.
- Three clean `fc537fc` repeats of the direct-process test preserved nine
  separate product databases and independent evaluator readings. All nine
  completed, matched target/control state, restored and exited helpers; six
  direct answers cited the saved process snapshot and three causal answers
  kept cause unknown. Manual review found no false healthy failure or
  unsupported definitive cause. Warm median/p90/max were
  4.359/4.578/4.578 seconds and sampled evaluator-tree peak RSS was
  214.234 MiB. These are repeated Basic development cases, not model
  qualification; raw paths and score hashes are in the canonical benchmark.
- The first `fc537fc` installer passed Basic HTTP checks but failed a live
  installed direct-process case: `application.snapshot` saved zero rows and
  `collection_status=partial` with a `ModuleNotFoundError` limitation. A new
  packaged desktop regression first failed at a transient startup poll;
  after that harness wait was corrected, it failed on the actual partial
  inventory. The PyInstaller log showed no `win32com.client` bundle for the
  collector's dynamic import. `6299d95` adds only that hidden import. Its
  PyInstaller hooks include `win32com`, `pythoncom` and the runtime hook; the
  previously red package regression then passed. All four opt-in package and
  branding checks passed on the rebuilt unsigned installer.
- The rebuilt installer passed a private silent installation, Basic healthy,
  HTTP 503, stall and no-listener cases with independently restored endpoints,
  and model-readiness denial with no case created. A separate installed
  process run observed a test-owned helper present, absent after a controlled
  stop, and present again after restoration; it cited all three direct
  findings and kept the causal question unresolved. The app and helper exited,
  the private installation uninstalled with exit 0, and the pre-existing user
  case database hash stayed unchanged. Installer SHA-256 is
  `c17b03e1d8cf8637af480962b34cf0653ab68060509b4bc12012322fb7be3b2c`.
  The earlier failed installed attempt is preserved separately.
- The full desktop E2E run had 18 passes, three opt-in skips and one Settings
  test failure before opening Settings: the landing page exceeded the viewport
  at 150% zoom. A focused rerun failed the same assertion. A separate layout
  probe measured 525 px document height against a 517 px viewport immediately
  and one second later; it is a persistent eight-pixel overflow, not a poll
  race. The trace and measurements are preserved privately. No UI change was
  made under the user's no-UI-work constraint. Current-source Laya–Sol trials
  remain blocked by the unrelated resident GPU workload, so neither adaptive
  model value nor private-alpha readiness is claimed.

## Parent-loss recovery and durable probe capacity (2026-09-29) | `da7ee3d`, `86f213d`

- An exact private Electron main-process force stop first reopened a running
  CPU case with a stale queued summary. `da7ee3d` distinguishes parent pipe
  EOF from an ordinary Stop, saves interrupted status, and replaces that stale
  summary with a specific resume instruction. A repeated packaged crash
  retained the saved case and left no active case. Attempts to wait for one
  evidence row in `packaged-parent-loss-cpu-05` and `-06` failed while the
  baseline stayed collecting; graceful harness cleanup saved unavailable
  rows. Earlier `app.process().kill()` attempts targeted Playwright's
  inspector wrapper, not the Electron main process, and remain failed tests.
- A light-polling packaged CPU case then exposed the real blocker: two fresh
  attempts waited 61.294/61.280 seconds and saved only deadline-failed
  baseline observations. The global durable ledger held four `resumed` claims
  from two earlier test-owned forced exits, while each recorded worker PID had
  exited. The original ledger was backed up, exact row and worker identities
  were checked, and only those four old test-owned claims were released.
  The next packaged case completed in 7.640 seconds with an exact target
  sample; this does not turn the failed cases into passes.
- `86f213d` creates a unique non-reused Windows Job name for each isolated
  probe reservation and atomically records its exact custodian and assignment.
  Startup and a bounded waiting-case retry independently verify that the
  owner and worker exited and that the named Job is empty or destroyed before
  releasing capacity. Unknown or older unnamed claims stay occupied. Red
  tests for the new interface and the waiting retry preceded implementation;
  native Windows Job, tampered-name, legacy, and active-worker checks then
  passed. The code also keeps parent-loss evidence and capacity custody
  separate from the model's advisory choices.
- A real packaged force stop during collection left two durable evidence rows
  and one named `resumed` claim. Reopen returned one interrupted saved case,
  no active case, and independently reconciled that claim to released. The
  next private CPU case completed in 7.591 seconds. The final unsigned
  installer SHA-256 is
  `79ffdfcac51eeb8b4d886030931086896e19a145653018cfd3bab2662b6bad77`.
  Its private installed Basic healthy/503, exact process-state and CPU cases,
  and blocked-model readiness check passed; it was uninstalled and the user
  database hash stayed unchanged. The installed CPU case took 8.657 seconds.
  Source-wide and final benchmark scores are recorded in the canonical
  [acceptance snapshot](BENCHMARKS_AND_ACCEPTANCE.md#private-alpha-acceptance-snapshot-2026-09-29).

## Frontier fallback provenance (2026-09-29) | `36e3010`

- Two isolated CPU-only Laya plus subscription-Sol development experiments
  used the ordinary case service but not the managed-CUDA desktop route. Laya
  ranking missed its deadline, and the deterministic fallback chose the one
  listener check. Sol reviewed the real task and listener evidence. Both
  endpoints were independently restored. These runs are failed Laya-selection
  attempts, not model qualification; receipts remain under
  `%LOCALAPPDATA%/SystemSense/private-alpha-20260928/cpu-laya-sol-lab-*`.
- The first case showed a provenance gap: the durable ranking snapshot said
  `deterministic_fallback`, but the user-facing case had no matching warning.
  A red integration test reproduced it. `36e3010` adds a case warning and
  exact bounded degradation reason across frontier paths. The focused event
  and process tests passed 94/94, with targeted Pyright and Ruff checks. A
  second CPU experiment confirmed the warning in saved product readback.
  No current-source managed-CUDA run or adaptive multi-choice result follows.
