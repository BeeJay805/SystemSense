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
