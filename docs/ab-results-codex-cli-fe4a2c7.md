# Codex CLI A/B result at `fe4a2c7`

## Verdict

Bad for the current savings goal. The controlled three-pair study does not
support a token or time savings claim. All six arms repaired the fault, but the
SystemSense arms used more context, took longer, and failed the collateral
quality gate in two pairs.

This is an MVP diagnostic result, not a final product estimate. Three pairs are
enough to expose the current failure mode, but not enough to characterize broad
Windows performance.

## Frozen setup

- SystemSense source: `fe4a2c7`
- Codex CLI: `0.145.0`
- Authentication: ChatGPT subscription copied only after VM boot
- Requested model: `gpt-5.6-sol`
- Reasoning effort: `medium`
- Scenario: `application.port_conflict`
- Schedule seed: `20260801`
- Schedule: `r01` SystemSense first; `r02` and `r03` baseline first
- Baseline MCP servers: none
- Treatment MCP servers: exactly `systemsense`
- Clean snapshot: `AB-CodexCLI-0.145.0-fe4a2c7`
- Per-arm limit: 900 seconds

Both VM fingerprints matched across all ten comparison categories. Both
non-study canaries passed. Every enrolled arm began after a clean snapshot
restore, received the same injected port-8000 conflict and human prompt, and
ended with a snapshot restore that removed the copied subscription credential.

The exact human prompt was:

> My local development app stopped starting after I resumed the PC. It prints a
> Windows socket address-in-use error and exits. Please diagnose and fix it,
> preserve my files and installed applications, and verify the app health check
> works when you are done.

## Enrolled results

Savings are calculated as `1 - SystemSense / baseline`. A negative number means
SystemSense used more of that metric.

| Pair | Baseline tokens | SystemSense tokens | Token savings | Baseline time | SystemSense time | Time savings | Hidden oracle |
|---|---:|---:|---:|---:|---:|---:|---|
| `r01` | 166,801 | 191,216 | -14.6372% | 137.303 s | 144.442 s | -5.1994% | both passed |
| `r02` | 202,242 | 382,178 | -88.9706% | 138.801 s | 179.564 s | -29.3679% | both passed |
| `r03` | 209,101 | 703,066 | -236.2327% | 143.175 s | 254.564 s | -77.7992% | both passed |

Descriptive totals across all enrolled runs:

| Metric | Baseline | SystemSense | SystemSense change |
|---|---:|---:|---:|
| Total tokens | 578,144 | 1,276,460 | 120.7858% more |
| Elapsed repair time | 419.279 s | 578.570 s | 37.9916% more |
| Tool calls | 28 | 43 | 53.5714% more |
| Tool-result bytes | 71,109 | 193,418 | 172.0021% more |
| Uncached input plus output tokens | 66,400 | 133,420 | 100.9337% more |

The gated analysis enrolled all three pairs but accepted only one as
quality-valid. Baseline and treatment repair success were both 100%. Baseline
collateral-change rate was 0%; treatment was 66.67% because `state.services`
changed in `r02` and `r03`. The allowed analysis therefore reports the only
quality-valid pair's -14.6372% token savings and -5.1994% time savings, with both
claim flags false. No savings claim is permitted.

The separate non-study canary had the opposite token direction: treatment used
28.3951% fewer total tokens but took 4.2884% longer. That reversal confirms that
single-run results are too volatile to use as proof.

## What the traces show

- `r01` and `r02` treatment never called a SystemSense tool. Merely exposing the
  MCP server did not replace manual inspection.
- `r03` made nine SystemSense calls, including repeated `open_case` and coverage
  calls, then continued with ten shell calls. SystemSense was additive instead
  of substitutive.
- One `r03` shell result was 58,974 bytes. One `r02` shell result was 46,373
  bytes. The treatment did not consistently use the bounded evidence workspace
  to avoid large manual dumps.
- `r03` retried an invalid `open_case` trait and an over-limit coverage request.
  Schema friction added round trips.
- Cached input dominated both arms, but treatment still used 100.9337% more
  uncached-input-plus-output tokens in aggregate. Caching does not explain away
  the regression.

The service collateral finding remains unexplained. The fingerprint currently
stores only the category hash, not the canonical service rows that produced it.
The harness correctly failed closed, but the artifact cannot distinguish a real
service inventory mutation from dynamic Windows inventory noise after the fact.

## Next measured slice

Do not expand to more scenarios yet. First make the treatment reliably replace
manual discovery in this one qualified scenario:

1. Deliver a short, client-visible SystemSense-first instruction that preserves
   the exact human prompt and tells the agent to open one case before shell
   inspection.
2. Make the first case response immediately useful and keep validation errors
   compact, so invalid trait or limit retries do not grow context.
3. Add output bounds to the shared shell path, with explicit continuation for
   the rare case that more data is needed.
4. Persist diffable canonical fingerprint inventories alongside hashes, then
   classify the `state.services` changes.
5. Replay the canaries and the same frozen three-pair schedule. Expand to other
   Windows families only after this scenario passes the quality and savings
   gates.

## Artifact provenance

The local evidence bundle is
`D:\SystemSense-AB\artifacts\codex-cli-fe4a2c7`.

- `analysis.json` SHA-256:
  `477f5fb4cbca83c1d27e6b075b0d6a626ca9eb629ef456528ccfd84cc50a8673`
- `study-schedule.json` SHA-256:
  `f98d87dbc7281b1864c978761a991f136cb9b91b3ff69167442ed0b769f213f3`
- `READY_FOR_BENCHMARK.json` SHA-256:
  `4f5f04a8a8534115b4e20f54a61834292ca51e228fa7b582a6c0e00065fec65b`
- Readiness digest:
  `f88eb53e16cccc41314113689e2a82eba844d956c32c1e7df8fbb5e0ebbe218d`
- Schedule hash:
  `634dee24d3cd4c8158b26ffd10004b7c59acb887938402b5e64ce68a92808ce9`

The VMs were left powered off at the clean snapshot. Baseline snapshot UUID is
`0bdf757f-2899-49f0-80dc-2ef6621dcca2`; treatment snapshot UUID is
`434f126f-bdd0-4885-8396-2d85e7643dd7`.
