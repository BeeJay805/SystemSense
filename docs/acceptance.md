# MVP acceptance matrix

| Requirement | Implementation evidence | Verification |
|---|---|---|
| Replay-safe timestamped Event Log capture | Stable source IDs, atomic bookmarks, normalized records | `tests/integration/test_sentinel_replay.py` |
| Event storms remain bounded | Fixed channel, count, polling, queue, and output limits | `tests/performance/test_event_storm.py`, `tests/integration/test_sentinel_lifecycle.py` |
| Six diagnostic families | Seven registered probes across six families | `tests/unit/orchestration/test_default_probes.py` |
| Static inventory plus change-only history | Current inventory, TTL, invalidation, history-on-change | `tests/unit/inventory/test_service.py`, `tests/unit/storage/test_writer.py` |
| Automatic bounded case plans | Common bundle, symptom matching, fresh optional suppression, budget | `tests/unit/orchestration/test_planner.py` |
| Registered, typed, timed, audited, output-limited probes | Catalog, policy, runner, circuit breaker, audit chain, manifest limits | `tests/unit/orchestration/test_probe_runner.py`, `tests/security/test_probe_policy.py`, `tests/integration/test_case_runtime.py` |
| Hanging sources are isolated | One-shot fixed-ID workers with deadline termination | `tests/unit/orchestration/test_executor.py` |
| Bounded, diverse, cited, diagnosis-free briefs | Diversity ranking, revisions, hard character budget, neutralization | `tests/unit/evidence`, `tests/security/test_no_diagnosis_output.py`, `tests/integration/mcp/test_tools.py` |
| Six bounded stdio MCP tools | Fixed schemas, opaque cursors, case ownership, no HTTP transport | `tests/integration/mcp/test_tools.py`, `tests/security/test_mcp_boundaries.py` |
| Missing evidence is explicit | Coverage records for denied, stale, failed, truncated, and unsupported sources | `tests/unit/domain/test_cases.py`, `tests/integration/test_case_runtime.py`, `tests/integration/test_sentinel_replay.py` |
| No application-level outbound network | Socket and URL entry points blocked during real common collection | `tests/security/test_no_network.py` |
| Savings are quality-gated | Hybrid fixture and recorded-run schema, invalidation on quality regression | `tests/benchmark` |
| Resource and retention bounds | Idle/RSS gates, age/size batches, reference-safe artifacts, orphan recovery | `tests/performance`, `tests/unit/storage/test_retention.py` |
| Versioned deterministic schemas | Checked-in schema exports match Pydantic models | `tests/unit/domain/test_schema_export.py` |
| Live Windows execution | All five optional family cases finish with evidence or explicit coverage | `tests/integration/windows/test_runtime_live.py` |

The code and local harness are complete for MVP testing. Real Claude savings remain
an external measurement, not an implementation claim. The paired protocol is ready
in [Benchmarking](benchmarking.md).
