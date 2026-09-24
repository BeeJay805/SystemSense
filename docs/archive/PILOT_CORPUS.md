# Candidate-ID pilot corpus inventory

`systemsense.evaluation.pilot_corpus.assemble_pilot_corpus` creates a bounded,
replayable **metadata-only** inventory from persisted candidate decisions and
one-shot dispatch records. It is not a training loader, a diagnosis benchmark,
or an export of private evidence. Every candidate retains its opaque ID and
ordered position, so two targets of one probe remain different choices. A
completed execution is recorded as `execution_recorded_unreviewed`; its diagnostic utility
is still `unknown`. Unclaimed, interrupted, and unrun choices are also unknown,
never negative examples.

Version 1 accepts only declared `fixture_contract` and
`controlled_host_rehearsal` origins. Their source hashes are inventory handles,
not authenticated oracle receipts. The output has
`training_admissible=false`, `diagnostic_performance_admissible=false`, and
`source_authenticity=not_verified`. It rejects a snapshot execution link unless
the same candidate has a readback-valid, one-shot dispatch admission and claim.
The corpus manifest covers ordered episodes, candidate custody, counts by
source and label quality, and a hash-only split-group manifest. Groups include
case, machine, fault family, and optional application/version; a group cannot
cross splits inside one shard. `verify_pilot_corpus` revalidates the structure
and digests, but cannot authenticate the SQLite database or a caller's declared
source. A separate candidate-ID ledger now checks declared split groups
across shards; the historical probe-ID ledger is not reused.

`PilotSplitLedger` admits a verified `PilotCorpus` into a dedicated SQLite
database with one declared corpus ID. It rejects a machine, fault-family, or
application group assigned to different splits across shards, changed
snapshot replays, and altered shard contents. Admission is atomic, and its
reopenable manifest reports shard, episode, source, and split counts. Retain
the returned `manifest_sha256` outside the database and pass it to
`verify_manifest` for an external identity check. This is metadata custody:
the group identities and source kinds are still caller-declared, so the
manifest remains `training_admissible=false` and cannot validate labels or
worker-input parity.

The first useful pilot is a small set of controlled host snapshots plus
contract fixtures, with source and unknown counts reported separately. The
existing five `benchmarks.local_episodes` are one-probe synthetic contract
journeys, not a validated simulator or useful-test labels. The owned-loopback
rehearsal uses a harness-controlled fault and oracle, not an independent Windows
qualification. It must not be relabeled real-world or independently adjudicated.

For a replayable custody smoke check, run the synthetic fixture generator with
a **new, nonexistent** directory outside the repository:

```powershell
$pilotOutput = Join-Path $env:TEMP ('systemsense-pilot-' + [guid]::NewGuid().ToString('N'))
uv run python -m systemsense.evaluation.pilot_fixture --output-dir $pilotOutput
```

The command creates `corpus.json` and `run_manifest.json` exclusively; it
refuses to overwrite an existing directory. The replay has one
`fixture_contract` episode, two distinct candidate IDs, zero executions, two
`unknown` utility labels, and no controlled-Windows or measured diagnostic
claim. Its manifest says `worker_input_parity=not_proven`. Random snapshot IDs
and current fixture timestamps mean its content hash changes between runs;
each run's digest still verifies its own exact content.

To register that existing corpus in cross-shard split custody, keep the
database and receipt outside the repository:

```powershell
uv run --frozen python -m systemsense.evaluation.pilot_split_cli --corpus (Join-Path $pilotOutput 'corpus.json') --ledger-db (Join-Path $pilotOutput 'split-ledger.sqlite3') --corpus-id pilot_fixture_v1 --output-manifest (Join-Path $pilotOutput 'split-manifest.json')
```

The CLI accepts at most 32 MiB of corpus JSON, refuses to overwrite a receipt,
and prints only its manifest digest. Exact replay to a *new* receipt path is
idempotent. Keep the first digest independently if using `verify_manifest` to
detect later ledger changes. This is still fixture-only metadata custody.

Promotion to a trainable candidate-ID corpus still requires authenticated
case consent and source custody, independent symptom/outcome checks, a
pre-result diagnostic question, reviewed useful-versus-uninformative judgments,
authenticated global leakage-safe splits, and exact runtime worker-token
reconstruction.
Current candidate snapshots preserve hash-only worker traces, not the actual
bounded tokenizer input. No weight updates are authorized by this inventory.

Focused check:

```powershell
uv run python -m pytest -q tests/unit/evaluation/test_pilot_corpus.py tests/unit/evaluation/test_pilot_fixture.py tests/unit/evaluation/test_pilot_split_ledger.py tests/unit/evaluation/test_pilot_split_cli.py
```
