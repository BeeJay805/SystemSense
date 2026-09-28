"""Frozen-suite custody tests use scripted callbacks only; no model is started."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from benchmarks.overnight_suite import (
    RunStamp,
    VisibleCase,
    _laya_worker_call_delta,  # pyright: ignore[reportPrivateUsage]
    _metrics,  # pyright: ignore[reportPrivateUsage]
    _run_with_laya_call_receipt,  # pyright: ignore[reportPrivateUsage]
    collect_case_custody,
    compare_frozen_contracts,
    load_frozen_suite,
    run_attempt,
    score_attempt,
)
from systemsense.audit import AuditChain, AuditOutcome
from systemsense.inference.laya_runtime import LayaWorkerCallMeter, LayaWorkerCallSnapshot
from systemsense.storage.sqlite_store import SQLiteStore


def test_laya_worker_case_delta_excludes_prewarm_and_labels_protocol_scope() -> None:
    before = LayaWorkerCallSnapshot(1, 1, 1, 1, 0)  # prewarm completed
    after = LayaWorkerCallSnapshot(4, 3, 3, 2, 1)
    assert _laya_worker_call_delta(before, after) == {
        "scope": "laya_rank_protocol_requests_case_delta",
        "rank_started": 3,
        "send_attempted": 2,
        "send_flushed": 2,
        "rank_completed": 1,
        "rank_failed": 1,
        "in_flight_before": 0,
        "in_flight_after": 1,
    }


def test_laya_worker_receipt_survives_fatal_case_failure(tmp_path: Path) -> None:
    meter = LayaWorkerCallMeter()
    meter.record("rank_started")  # prewarm is outside the case
    meter.record("rank_completed")

    def failed_case() -> dict[str, object]:
        meter.record("rank_started")
        meter.record("send_attempted")
        meter.record("send_flushed")
        meter.record("rank_failed")
        raise RuntimeError("original case failure")

    with pytest.raises(RuntimeError, match="original case failure"):
        _run_with_laya_call_receipt(failed_case, meter, tmp_path)
    receipt = json.loads((tmp_path / "laya-worker-calls.json").read_text(encoding="utf-8"))
    assert receipt["rank_started"] == 1
    assert receipt["send_flushed"] == 1
    assert receipt["rank_failed"] == 1
    assert receipt["in_flight_after"] == 0


def test_laya_worker_success_receipt_matches_metrics_and_legacy_unknown(tmp_path: Path) -> None:
    meter = LayaWorkerCallMeter()

    def completed_case() -> dict[str, object]:
        meter.record("rank_started")
        meter.record("send_attempted")
        meter.record("send_flushed")
        meter.record("rank_completed")
        return {"runtime": {}}

    capture, receipt = _run_with_laya_call_receipt(completed_case, meter, tmp_path)
    runtime = cast(dict[str, object], capture["runtime"])
    runtime["laya_worker_calls"] = receipt
    assert _metrics(capture)["laya_worker_calls"] == json.loads(
        (tmp_path / "laya-worker-calls.json").read_text(encoding="utf-8")
    )
    assert _metrics({"runtime": {}})["laya_worker_calls"] is None


def test_laya_receipt_write_failure_does_not_mask_case_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import benchmarks.overnight_suite as suite_module

    def failed_write(_path: Path, _value: object) -> None:
        raise OSError("receipt disk failure")

    def failed_case() -> dict[str, object]:
        raise RuntimeError("original case failure")

    monkeypatch.setattr(suite_module, "_write_once", failed_write)
    with pytest.raises(RuntimeError, match="original case failure"):
        _run_with_laya_call_receipt(failed_case, LayaWorkerCallMeter(), tmp_path)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _deep_database(
    path: Path,
    *,
    collection_status: str = "available",
    later: bool = True,
    register_manifest: bool = True,
) -> tuple[str, str]:
    """Build a real-shaped persisted async source and receipt without a model."""
    from benchmarks.overnight_suite import _canonical_sha  # pyright: ignore[reportPrivateUsage]
    from systemsense.application.deep_worker import DeepWorkerResultV1, freeze_deep_task
    from systemsense.decision.contracts import (
        DiagnosticPurpose,
        ProbeCapability,
        ProbeProposal,
        ProviderIdentity,
        ResourceClass,
    )
    from systemsense.domain.evidence import (
        CollectorReference,
        EvidenceFact,
        EvidenceRecord,
        EvidenceSource,
        Extraction,
        Sensitivity,
        StatementKind,
    )
    from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
    from systemsense.domain.probes import ProbeInvocation
    from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
    from systemsense.packs.runtime import default_probe_definitions
    from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse, ReasoningStatus
    from systemsense.storage.presented_read_set import PresentedReadSetEntryV1, PresentedReadSetV1

    case_id, evidence_id, execution_id = CaseId.new(), EvidenceId.new(), ExecutionId.new()
    now = datetime(2026, 9, 28, tzinfo=UTC)
    provider = ProviderIdentity(
        provider_id="codex-subscription-reasoning", provider_version="1", role="reasoning"
    )
    capability = ProbeCapability(
        probe_id="network.configuration",
        description="Local configuration",
        cost_ms=1,
        resource_class=ResourceClass.NETWORK,
    )
    proposal = ProbeProposal(
        probe_id="network.configuration",
        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
        priority=1,
        estimated_cost_ms=1,
        resource_class=ResourceClass.NETWORK,
        dedupe_key="deep:network.configuration",
    )

    def read_set(entries: tuple[PresentedReadSetEntryV1, ...]) -> PresentedReadSetV1:
        payload = {
            "schema_version": 1,
            "case_id": str(case_id),
            "case_generation": 1,
            "entries": [item.model_dump(mode="json") for item in entries],
        }
        return PresentedReadSetV1(
            case_id=case_id,
            case_generation=1,
            entries=entries,
            read_set_sha256=_canonical_sha(payload),
        )

    first_request = ReasoningRequest(
        case_id=case_id,
        state_version=1,
        correlation_id="first",
        deadline_at=now + timedelta(minutes=1),
        objective="Check local configuration",
        available_probes=(capability,),
        budget_ms=5000,
        max_probes=2,
    )
    first_task = freeze_deep_task(
        first_request,
        read_set(()),
        provider_identity=provider,
        hypothesis_revision=0,
    )
    first_response = ReasoningResponse(
        provider=provider,
        case_id=case_id,
        state_version=1,
        correlation_id="first",
        deadline_at=first_request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="A registered check may help",
        distinguishing_probes=(proposal,),
    )
    first_result = DeepWorkerResultV1(
        case_id=case_id,
        request_sha256=first_task.request_sha256,
        provider_identity=provider,
        status="completed",
        started_at=now,
        finished_at=now + timedelta(seconds=1),
        elapsed_ms=1000,
        response=first_response,
    )
    entry = PresentedReadSetEntryV1(
        evidence_id=evidence_id,
        kind="evidence",
        owner_case_id=case_id,
        row_sha256=_sha("row"),
    )
    later_request = ReasoningRequest(
        case_id=case_id,
        state_version=3,
        correlation_id="later",
        deadline_at=now + timedelta(minutes=1),
        objective="Assess new local configuration",
        available_probes=(capability,),
        evidence_ids=(evidence_id,),
        evidence_context=(
            EvidenceContext(
                evidence_id=evidence_id,
                observed_at=now + timedelta(seconds=3),
                captured_at=now + timedelta(seconds=3),
                probe_id="network.configuration",
                summary="Local settings observed",
                status=EvidenceContextStatus.OBSERVED,
                case_scope="current_case",
            ),
        ),
        budget_ms=5000,
        max_probes=2,
    )
    later_task = freeze_deep_task(
        later_request,
        read_set((entry,)),
        provider_identity=provider,
        hypothesis_revision=0,
    )
    later_response = ReasoningResponse(
        provider=provider,
        case_id=case_id,
        state_version=3,
        correlation_id="later",
        deadline_at=later_request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="Local settings do not prove target reachability",
        considered_evidence_ids=(evidence_id,),
    )
    later_result = DeepWorkerResultV1(
        case_id=case_id,
        request_sha256=later_task.request_sha256,
        provider_identity=provider,
        status="completed",
        started_at=now + timedelta(seconds=5),
        finished_at=now + timedelta(seconds=6),
        elapsed_ms=1000,
        response=later_response,
    )
    manifest = next(
        item.manifest
        for item in default_probe_definitions()
        if item.manifest.probe_id == "network.configuration"
    )
    invocation = ProbeInvocation(
        probe_id="network.configuration",
        probe_version=1,
        observable="network.configuration",
        parameters={},
    )
    with SQLiteStore(path) as store:
        connection = store.connection
        connection.execute(
            "INSERT INTO cases(case_id,kind,symptom,created_at) VALUES (?,?,?,?)",
            (str(case_id), "diagnostic", "local issue", now.isoformat()),
        )
        if register_manifest:
            connection.execute(
                "INSERT INTO probe_manifests(probe_id,version,manifest_json) VALUES (?,?,?)",
                (manifest.probe_id, manifest.version, _canonical(manifest.model_dump(mode="json"))),
            )
        rows = [(first_task, first_result, now, now + timedelta(seconds=2))]
        if later:
            rows.append(
                (later_task, later_result, now + timedelta(seconds=5), now + timedelta(seconds=6))
            )
        for task, result, created, updated in rows:
            connection.execute(
                "INSERT INTO deep_mailbox(case_id,request_sha256,basis_sha256,schema_version,"
                "task_json,status,result_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    str(case_id),
                    task.request_sha256,
                    task.request_sha256,
                    1,
                    task.model_dump_json(),
                    "applied",
                    result.model_dump_json(),
                    created.isoformat(),
                    updated.isoformat(),
                ),
            )
        connection.execute(
            "INSERT INTO investigation_steps(case_id,state_version,record_json) VALUES (?,?,?)",
            (
                str(case_id),
                2,
                json.dumps({"event": "deep_applied", "detail": first_task.request_sha256}),
            ),
        )
        connection.execute(
            "INSERT INTO probe_executions(execution_id,case_id,probe_id,probe_version,status,"
            "parameters_json,started_at,finished_at,state_version) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                str(execution_id),
                str(case_id),
                "network.configuration",
                1,
                "ok",
                "{}",
                (now + timedelta(seconds=3)).isoformat(),
                (now + timedelta(seconds=4)).isoformat(),
                2,
            ),
        )
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=now + timedelta(seconds=3),
            captured_at=now + timedelta(seconds=3),
            source=EvidenceSource(
                type="systemsense.probe",
                source_id="src_" + "a" * 64,
                locator={"probe_id": "network.configuration"},
            ),
            collector=CollectorReference(
                id="network.configuration",
                version=1,
                execution_id=execution_id,
            ),
            summary="Observed local configuration",
            facts=(
                EvidenceFact(
                    name="collection_status",
                    value=collection_status,
                ),
            ),
            extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        connection.execute(
            "INSERT INTO evidence(evidence_id,case_id,source_id,record_json,observed_at,"
            "captured_at,execution_id,dedupe_key,time_basis,time_quality) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                str(evidence_id),
                str(case_id),
                "src_" + "a" * 64,
                record.model_dump_json(),
                (now + timedelta(seconds=3)).isoformat(),
                (now + timedelta(seconds=3)).isoformat(),
                str(execution_id),
                "deep-fixture",
                "source_observed",
                "bounded_interval",
            ),
        )
        audit = AuditChain().append(
            event_id=f"probe_{execution_id}",
            case_id=case_id,
            probe_id="network.configuration",
            outcome=AuditOutcome.ALLOWED,
            occurred_at=now + timedelta(seconds=4),
            parameters={
                "plan_instance_id": "network.configuration",
                "parameters_sha256": _sha("{}"),
            },
        )
        connection.execute(
            "INSERT INTO audit_events(event_id,case_id,event_json,created_at,occurred_at,"
            "persisted_at) VALUES (?,?,?,?,?,?)",
            (
                audit.event_id,
                str(case_id),
                audit.model_dump_json(),
                audit.occurred_at.isoformat(),
                audit.occurred_at.isoformat(),
                audit.occurred_at.isoformat(),
            ),
        )
        connection.execute(
            "INSERT INTO audit_heads(case_id,sequence,head_hash) VALUES (?,?,?)",
            (str(case_id), 1, audit.event_hash),
        )
        if (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='deep_proposal_execution_links'"
            ).fetchone()
            is None
        ):
            connection.executescript(
                "CREATE TABLE deep_proposal_execution_links ("
                "case_id TEXT,request_sha256 TEXT,proposal_sha256 TEXT,"
                "accepted_state_version INTEGER,selected_state_version INTEGER,"
                "plan_instance_id TEXT,execution_id TEXT,probe_id TEXT,probe_version INTEGER,"
                "manifest_sha256 TEXT,manifest_json TEXT,invocation_json TEXT,"
                "invocation_sha256 TEXT,schema_version INTEGER);"
                "CREATE TRIGGER deep_proposal_execution_links_no_update "
                "BEFORE UPDATE ON deep_proposal_execution_links "
                "BEGIN SELECT RAISE(ABORT,'immutable'); END;"
                "CREATE TRIGGER deep_proposal_execution_links_no_delete "
                "BEFORE DELETE ON deep_proposal_execution_links "
                "BEGIN SELECT RAISE(ABORT,'immutable'); END;"
            )
        connection.execute(
            "INSERT INTO deep_proposal_execution_links VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(case_id),
                first_task.request_sha256,
                _canonical_sha(proposal.model_dump(mode="json")),
                2,
                2,
                "network.configuration",
                str(execution_id),
                "network.configuration",
                1,
                _canonical_sha(manifest.model_dump(mode="json")),
                _canonical(manifest.model_dump(mode="json")),
                _canonical(invocation.model_dump(mode="json")),
                _canonical_sha(invocation.model_dump(mode="json")),
                1,
            ),
        )
        connection.commit()
    return str(case_id), str(execution_id)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _suite(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / "visible-suite.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": [
                    {
                        "case_id": "case-0123456789ab",
                        "split": "development",
                        "family_group": "synthetic_pressure",
                        "source": "synthetic",
                        "visible_input_sha256": _sha("visible"),
                        "initial_evidence_sha256": _sha("evidence"),
                        "action_contract_sha256": _sha("actions"),
                        "budget_ms": 10000,
                    },
                    {
                        "case_id": "case-abcdef012345",
                        "split": "holdout",
                        "family_group": "synthetic_network",
                        "source": "synthetic",
                        "visible_input_sha256": _sha("visible2"),
                        "initial_evidence_sha256": _sha("evidence2"),
                        "action_contract_sha256": _sha("actions2"),
                        "budget_ms": 10000,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _capture(case_id: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "status": "completed",
        "contract": {
            "visible_input_sha256": _sha("visible"),
            "initial_evidence_sha256": _sha("evidence"),
            "action_contract_sha256": _sha("actions"),
        },
        "runtime": {
            "provider_calls": [
                {
                    "role": "catalog_attention",
                    "provider_id": "laya-local-decision",
                    "degraded": False,
                },
                {
                    "role": "reasoning",
                    "provider_id": "codex-subscription-reasoning",
                    "degraded": False,
                },
            ],
            "raw_invalid_retries": 1,
            "startup_ms": 1200,
            "resource_observations": [{"at": "2026-09-28T00:00:00+00:00", "rss_bytes": 42}],
        },
        "model_inputs": ["visible prompt with no answer"],
        "custody": {
            "snapshots": [
                {
                    "snapshot_id": "snap-1",
                    "request": {
                        "provider": {
                            "provider_id": "laya-local-decision",
                            "provider_version": "1",
                            "role": "fast_decision",
                        },
                        "items": [
                            {
                                "item_id": "item-1",
                                "reference": {"kind": "measure", "candidate_id": "pressure"},
                            }
                        ],
                    },
                    "response": {
                        "provider": {
                            "provider_id": "laya-local-decision",
                            "provider_version": "1",
                            "role": "fast_decision",
                        },
                        "ranking_source": "laya",
                        "ranked_item_ids": ["item-1"],
                        "considered_item_ids": ["item-1"],
                        "coverage_complete": True,
                        "model_abstained": False,
                        "degraded_reason": None,
                    },
                }
            ],
            "executions": [
                {
                    "snapshot_id": "snap-1",
                    "candidate_id": "pressure",
                    "execution_id": "execution-1",
                    "admission_id": "admission-1",
                    "probe_id": "core.resources",
                    "target_handle": "affected-process",
                    "parameters": {"window_seconds": 5},
                    "status": "ok",
                    "finished_at": "2026-09-28T00:00:02+00:00",
                    "evidence_ids": ["ev-1"],
                    "observation_quality": "supported_structured_observation",
                }
            ],
            "mailbox": [
                {
                    "request_sha256": _sha("deep2"),
                    "status": "applied",
                    "created_at": "2026-09-28T00:00:03+00:00",
                    "updated_at": "2026-09-28T00:00:05+00:00",
                    "task": {
                        "request": {
                            "evidence_ids": ["ev-1"],
                            "evidence_context": [{"evidence_id": "ev-1", "status": "observed"}],
                        }
                    },
                    "result": {
                        "response": {
                            "provider": {"provider_id": "codex-subscription-reasoning"},
                            "degraded": False,
                            "considered_evidence_ids": ["ev-1"],
                            "summary": "Pressure measurement seen; cause remains unknown",
                        }
                    },
                }
            ],
        },
    }


def _stamp(phase: str = "development_baseline") -> RunStamp:
    return RunStamp(
        phase=phase,
        arm="laya_sol",
        code_revision="a" * 40,
        baseline_revision="a" * 40,
        candidate_revision="b" * 40 if phase.startswith("heldout") else None,
    )


def test_manifest_is_frozen_partitioned_and_oracle_free(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    assert suite.sha256 == digest
    assert suite.cases[0].split == "development"
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="digest"):
        load_frozen_suite(path, digest)

    path, _ = _suite(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["cases"][0]["expected_outcome"] = "pressure"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match=r"unknown|oracle"):
        load_frozen_suite(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_attempts_are_create_only_and_hidden_oracle_never_reaches_callback(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    seen: list[object] = []

    def scripted(visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        seen.append(visible)
        return _capture("case-0123456789ab")

    first = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "attempts", scripted)
    second = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "attempts", scripted)
    assert first != second
    assert (first / "start.json").exists()
    assert (first / "capture.json").exists()
    assert (
        first.joinpath("capture.json").read_bytes() == second.joinpath("capture.json").read_bytes()
    )
    assert "oracle" not in repr(seen)
    assert "family_group" not in repr(seen)
    assert not (first / "score.json").exists()


def test_failed_attempt_is_retained_and_cannot_be_scored_as_pass(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)

    def fail(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        raise RuntimeError("transport failed")

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "attempts", fail)
    assert (attempt / "start.json").exists()
    assert (attempt / "failure.json").exists()
    assert not (attempt / "capture.json").exists()


def test_score_requires_exact_execution_and_later_response(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    capture = _capture("case-0123456789ab")

    def return_capture(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return capture

    attempt = run_attempt(
        suite,
        "case-0123456789ab",
        _stamp(),
        tmp_path / "attempts",
        return_capture,
    )
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["mechanical_choice_execution_response"] is True
    assert score["useful_choice_observed"] is True
    assert score["semantic_correctness"] == "human_review_pending"
    metrics = score["metrics"]
    assert isinstance(metrics, dict)
    assert metrics["completed_mailbox_durations_ms"] == [2000]
    assert metrics["raw_invalid_retries"] == 1

    broken = _capture("case-0123456789ab")
    broken["custody"]["executions"][0]["status"] = "failed"

    def return_broken(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return broken

    failed_attempt = run_attempt(
        suite,
        "case-0123456789ab",
        _stamp(),
        tmp_path / "attempts",
        return_broken,
    )
    failed_score = score_attempt(
        failed_attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest()
    )
    assert failed_score["mechanical_choice_execution_response"] is False
    assert failed_score["useful_choice_observed"] is False


def test_fast_choice_with_unsupported_observation_is_transport_only(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        capture = _capture("case-0123456789ab")
        capture["custody"]["executions"][0]["observation_quality"] = "unavailable_or_failed"
        return capture

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", invoke)
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["fast_complete_mechanical_loops"] == 1
    assert score["mechanical_choice_execution_response"] is True
    assert score["fast_complete_useful_observation_loops"] == 0
    assert score["useful_choice_observed"] is False


def test_holdout_partition_and_revision_guard(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)

    def return_capture(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-0123456789ab")

    def holdout(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-abcdef012345")

    with pytest.raises(ValueError, match=r"phase|split"):
        run_attempt(
            suite,
            "case-abcdef012345",
            _stamp(),
            tmp_path / "attempts",
            holdout,
        )
    with pytest.raises(ValueError, match="revision"):
        run_attempt(
            suite,
            "case-0123456789ab",
            RunStamp("development_candidate", "laya_sol", "a" * 40, "a" * 40, "b" * 40),
            tmp_path / "attempts",
            return_capture,
        )


def test_missing_response_leakage_and_repeated_scoring_fail_closed(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {
                    "case-0123456789ab": {
                        "useful_candidate_ids": ["pressure"],
                        "leak_markers": ["secret-cause"],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    missing = _capture("case-0123456789ab")
    missing["custody"]["mailbox"] = []

    def return_missing(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return missing

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", return_missing)
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["mechanical_choice_execution_response"] is False
    assert score["useful_choice_observed"] is False
    with pytest.raises(FileExistsError):
        score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())

    leaked = _capture("case-0123456789ab")
    leaked["model_inputs"] = ["Visible prompt secret-cause"]

    def return_leaked(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return leaked

    leaked_attempt = run_attempt(
        suite, "case-0123456789ab", _stamp(), tmp_path / "runs", return_leaked
    )
    leaked_score = score_attempt(
        leaked_attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest()
    )
    assert leaked_score["model_input_leakage_audit"] == "failed_hidden_marker_present"
    assert leaked_score["mechanical_choice_execution_response"] is False


def test_route_attribution_and_contract_comparison(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    bad_route = _capture("case-0123456789ab")
    bad_route["runtime"]["provider_calls"] = [
        {"role": "reasoning", "provider_id": "codex-subscription-reasoning", "degraded": False}
    ]
    bad_route["custody"]["snapshots"][0]["response"]["provider"]["provider_id"] = "other"

    def return_bad(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return bad_route

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", return_bad)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["mechanical_choice_execution_response"] is False
    route = score["route_realization"]
    assert isinstance(route, dict)
    assert route["status"] == "not_demonstrated"
    parity = compare_frozen_contracts([attempt, attempt])
    assert parity["matched_normalized_starting_contract"] is True
    assert parity["full_runtime_request_byte_parity"] == "not_claimed"


def test_frontier_snapshot_proves_laya_route_without_catalog_attention_call(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )
    capture = _capture("case-0123456789ab")
    capture["runtime"]["provider_calls"] = [
        {"role": "reasoning", "provider_id": "codex-subscription-reasoning", "degraded": False}
    ]

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return capture

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", invoke)
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    route = score["route_realization"]
    assert isinstance(route, dict)
    assert route["status"] == "demonstrated"
    assert score["mechanical_choice_execution_response"] is True


@pytest.mark.parametrize(
    "corruption", ["absent", "degraded", "fallback", "wrong_provider", "malformed"]
)
def test_claimed_laya_configuration_without_valid_frontier_readback_is_not_proof(
    corruption: str,
) -> None:
    from benchmarks.overnight_suite import _route_realization  # pyright: ignore[reportPrivateUsage]

    capture = _capture("case-0123456789ab")
    if corruption == "absent":
        capture["custody"]["snapshots"] = []
    elif corruption == "malformed":
        capture["custody"]["snapshots"][0]["request"]["items"][0]["item_id"] = []
    elif corruption == "degraded":
        capture["custody"]["snapshots"][0]["response"]["degraded_reason"] = "invalid"
    elif corruption == "fallback":
        capture["custody"]["snapshots"][0]["response"]["ranking_source"] = "deterministic_fallback"
    else:
        capture["custody"]["snapshots"][0]["response"]["provider"]["provider_id"] = "other"
    assert _route_realization(capture, "laya_sol")["status"] == "not_demonstrated"


def test_rescore_preserves_original_and_uses_revision_named_file(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_candidate_ids": ["pressure"]}},
            }
        ),
        encoding="utf-8",
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-0123456789ab")

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", invoke)
    oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
    score_attempt(attempt, suite, oracle, oracle_sha)
    original = (attempt / "score.json").read_bytes()
    revision = "b" * 40
    rescored = score_attempt(attempt, suite, oracle, oracle_sha, score_revision=revision)
    assert rescored["scorer_revision"] == revision
    assert (attempt / f"score-{revision}.json").exists()
    assert (attempt / "score.json").read_bytes() == original
    with pytest.raises(FileExistsError):
        score_attempt(attempt, suite, oracle, oracle_sha, score_revision=revision)
    with pytest.raises(ValueError, match="revision"):
        score_attempt(attempt, suite, oracle, oracle_sha, score_revision="../unsafe")


def test_holdout_rescore_preserves_original_consumption_receipt(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-abcdef012345": {"useful_candidate_ids": []}},
            }
        ),
        encoding="utf-8",
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        capture = _capture("case-abcdef012345")
        capture["contract"] = {
            "visible_input_sha256": _sha("visible2"),
            "initial_evidence_sha256": _sha("evidence2"),
            "action_contract_sha256": _sha("actions2"),
        }
        return capture

    attempt = run_attempt(
        suite,
        "case-abcdef012345",
        RunStamp("heldout_baseline", "laya_sol", "a" * 40, "a" * 40, "b" * 40),
        tmp_path / "runs",
        invoke,
    )
    oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
    score_attempt(attempt, suite, oracle, oracle_sha)
    original = (attempt / "holdout_consumption.json").read_bytes()
    score_attempt(attempt, suite, oracle, oracle_sha, score_revision="b" * 40)
    assert (attempt / "holdout_consumption.json").read_bytes() == original


def test_readback_uses_existing_case_tables_without_running_models(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        custody = collect_case_custody(store, "absent-case")
    assert custody["case_id"] == "absent-case"
    assert custody["snapshots"] == []
    assert custody["next_probe_execution_links"] == []
    assert custody["followup_admissions"] == []
    assert custody["probe_executions"] == []


@pytest.mark.parametrize(
    ("probe_id", "target_handle", "window_seconds", "expected"),
    [
        ("core.resources", "affected-process", 5, True),
        ("gpu.telemetry.sample", "affected-process", 5, False),
        ("core.resources", "other-process", 5, False),
        ("core.resources", "affected-process", 10, False),
    ],
)
def test_dynamic_candidate_requires_frozen_registered_invocation_scope(
    tmp_path: Path, probe_id: str, target_handle: str, window_seconds: int, expected: bool
) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {
                    "case-0123456789ab": {
                        "useful_candidate_ids": [],
                        "useful_probe_ids": ["core.resources"],
                        "useful_registered_checks": [
                            {
                                "probe_id": "core.resources",
                                "target_handle": "affected-process",
                                "parameter_equals": {"window_seconds": 5},
                            }
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    capture = _capture("case-0123456789ab")
    execution = capture["custody"]["executions"][0]
    execution["probe_id"] = probe_id
    execution["target_handle"] = target_handle
    execution["parameters"] = {"window_seconds": window_seconds}

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return capture

    stamp = RunStamp(
        "development_baseline",
        "laya_sol",
        "a" * 40,
        "a" * 40,
        oracle_sha256=hashlib.sha256(oracle.read_bytes()).hexdigest(),
    )
    attempt = run_attempt(suite, "case-0123456789ab", stamp, tmp_path / "runs", invoke)
    score = score_attempt(attempt, suite, oracle, stamp.oracle_sha256 or "")
    assert score["mechanical_choice_execution_response"] is True
    assert score["useful_choice_observed"] is expected
    assert score["oracle_preregistered_with_attempt"] is True


def test_deep_receipt_requires_exact_readback_and_later_applied_response(tmp_path: Path) -> None:
    from benchmarks.overnight_suite import (
        _case_db_readback,  # pyright: ignore[reportPrivateUsage]
        _score_deep_receipts,  # pyright: ignore[reportPrivateUsage]
    )

    case_id, execution_id = _deep_database(tmp_path / "case.db")
    with SQLiteStore(tmp_path / "case.db") as store:
        captured = collect_case_custody(store, case_id)
    captured_receipts = captured["deep_origin_receipts"]
    assert isinstance(captured_receipts, list)
    assert captured_receipts[0]["verified"] is True
    receipts, mailbox, quality = _case_db_readback(tmp_path, case_id)
    assert receipts is not None and len(receipts) == 1
    assert receipts[0]["verified"] is True
    assert receipts[0]["execution_id"] == execution_id
    assert quality[execution_id] == "supported_structured_observation"
    scored = _score_deep_receipts(
        receipts,
        mailbox,
        set(),
        {"network.configuration"},
        [{"probe_id": "network.configuration"}],
        "laya_sol",
    )
    assert scored["deep_mechanical_choice_execution_response"] is True
    assert scored["deep_useful_choice_observed"] is True
    links = scored["deep_origin_execution_links"]
    assert isinstance(links, list)
    assert len(cast(list[object], links)) == 1
    wrong_later = deepcopy(mailbox)
    wrong_later[-1]["task"]["request"]["evidence_ids"] = ["ev_" + "f" * 32]
    wrong_scored = _score_deep_receipts(
        receipts,
        wrong_later,
        set(),
        {"network.configuration"},
        [{"probe_id": "network.configuration"}],
        "laya_sol",
    )
    assert wrong_scored["deep_mechanical_choice_execution_response"] is False
    wrong_later = deepcopy(mailbox)
    wrong_later[-1]["result"]["response"]["considered_evidence_ids"] = []
    wrong_scored = _score_deep_receipts(
        receipts,
        wrong_later,
        set(),
        {"network.configuration"},
        [{"probe_id": "network.configuration"}],
        "laya_sol",
    )
    assert wrong_scored["deep_mechanical_choice_execution_response"] is False


def test_builtin_manifest_readback_when_store_registry_is_unpopulated(tmp_path: Path) -> None:
    from benchmarks.overnight_suite import _case_db_readback  # pyright: ignore[reportPrivateUsage]

    case_id, _ = _deep_database(tmp_path / "case.db", register_manifest=False)
    receipts, _, _ = _case_db_readback(tmp_path, case_id)
    assert receipts is not None and receipts[0]["verified"] is True
    assert receipts[0]["manifest_registry_basis"] == "current_builtin_registry"


@pytest.mark.parametrize(
    ("probe_id", "facts", "expected"),
    [
        (
            "pressure.sample",
            {"pressure": {"status": "available"}},
            "supported_structured_observation",
        ),
        (
            "gpu.telemetry.sample",
            {"gpu_telemetry_sample": {"status": "partial"}},
            "supported_structured_observation",
        ),
        ("power.snapshot", {"power": {"status": "available"}}, "supported_structured_observation"),
        (
            "incident.events",
            {"channel_status": {"Application": "available"}},
            "supported_structured_observation",
        ),
        ("core.resources", {"resources": {"cpu_percent": 42}}, "supported_structured_observation"),
        ("pressure.sample", {"collection_status": "unsupported"}, "unavailable_or_failed"),
        ("gpu.telemetry.sample", {}, "unknown_structured_status"),
    ],
)
def test_structured_collector_quality_not_keyword_guess(
    probe_id: str, facts: dict[str, object], expected: str
) -> None:
    from benchmarks.overnight_suite import _observed_quality  # pyright: ignore[reportPrivateUsage]

    record = {
        "statement_kind": "observed_fact",
        "facts": [{"name": name, "value": value} for name, value in facts.items()],
    }
    assert _observed_quality([record], probe_id) == expected


@pytest.mark.parametrize(
    "tamper",
    [
        "absent",
        "wrong_case",
        "wrong_request",
        "wrong_invocation",
        "wrong_manifest",
        "wrong_execution",
        "wrong_plan",
        "wrong_provider",
    ],
)
def test_deep_receipt_tampering_never_earns_origin(tmp_path: Path, tamper: str) -> None:
    from benchmarks.overnight_suite import (
        _case_db_readback,  # pyright: ignore[reportPrivateUsage]
        _score_deep_receipts,  # pyright: ignore[reportPrivateUsage]
    )

    case_id, _ = _deep_database(tmp_path / "case.db")
    with sqlite3.connect(tmp_path / "case.db") as connection:
        connection.execute("DROP TRIGGER deep_proposal_execution_links_no_update")
        connection.execute("DROP TRIGGER deep_proposal_execution_links_no_delete")
        if tamper == "absent":
            connection.execute("DELETE FROM deep_proposal_execution_links")
        elif tamper == "wrong_case":
            connection.execute(
                "UPDATE deep_proposal_execution_links SET case_id=?", ("case_" + "f" * 32,)
            )
        elif tamper == "wrong_request":
            connection.execute(
                "UPDATE deep_proposal_execution_links SET request_sha256=?", (_sha("wrong"),)
            )
        elif tamper == "wrong_invocation":
            connection.execute(
                "UPDATE deep_proposal_execution_links SET invocation_sha256=?", (_sha("wrong"),)
            )
        elif tamper == "wrong_manifest":
            connection.execute(
                "UPDATE deep_proposal_execution_links SET manifest_sha256=?", (_sha("wrong"),)
            )
        elif tamper == "wrong_execution":
            connection.execute(
                "UPDATE deep_proposal_execution_links SET execution_id=?", ("exec_" + "f" * 32,)
            )
        elif tamper == "wrong_plan":
            connection.execute(
                "UPDATE deep_proposal_execution_links SET plan_instance_id='other-registered-plan'"
            )
        else:
            connection.execute("DROP TRIGGER deep_mailbox_terminal")
            row = connection.execute(
                "SELECT request_sha256,result_json FROM deep_mailbox ORDER BY created_at LIMIT 1"
            ).fetchone()
            result = json.loads(row[1])
            result["response"]["provider"]["provider_id"] = "fixture-other"
            connection.execute(
                "UPDATE deep_mailbox SET result_json=? WHERE request_sha256=?",
                (json.dumps(result), row[0]),
            )
    receipts, mailbox, _ = _case_db_readback(tmp_path, case_id)
    scored = _score_deep_receipts(
        receipts,
        mailbox,
        set(),
        {"network.configuration"},
        [{"probe_id": "network.configuration"}],
        "laya_sol",
    )
    assert scored["deep_mechanical_choice_execution_response"] is False
    assert scored["deep_useful_choice_observed"] is False


@pytest.mark.parametrize("status", ["unsupported", "denied", "failed", "truncated"])
def test_deep_origin_attempt_with_unusable_result_has_no_useful_loop(
    tmp_path: Path, status: str
) -> None:
    from benchmarks.overnight_suite import (
        _case_db_readback,  # pyright: ignore[reportPrivateUsage]
        _score_deep_receipts,  # pyright: ignore[reportPrivateUsage]
    )

    case_id, _ = _deep_database(tmp_path / "case.db", collection_status=status)
    receipts, mailbox, _ = _case_db_readback(tmp_path, case_id)
    scored = _score_deep_receipts(
        receipts,
        mailbox,
        set(),
        {"network.configuration"},
        [{"probe_id": "network.configuration"}],
        "laya_sol",
    )
    assert scored["deep_mechanical_choice_execution_response"] is True
    assert scored["deep_useful_choice_observed"] is False
    links = scored["deep_origin_execution_links"]
    assert isinstance(links, list)
    assert links[0]["observation_quality"] == "unavailable_or_failed"


def test_deep_origin_without_later_response_and_v37_table_absence(tmp_path: Path) -> None:
    from benchmarks.overnight_suite import (
        _case_db_readback,  # pyright: ignore[reportPrivateUsage]
        _score_deep_receipts,  # pyright: ignore[reportPrivateUsage]
    )

    case_id, _ = _deep_database(tmp_path / "case.db", later=False)
    receipts, mailbox, _ = _case_db_readback(tmp_path, case_id)
    scored = _score_deep_receipts(
        receipts,
        mailbox,
        set(),
        {"network.configuration"},
        [{"probe_id": "network.configuration"}],
        "laya_sol",
    )
    assert scored["deep_mechanical_choice_execution_response"] is False
    with sqlite3.connect(tmp_path / "case.db") as connection:
        connection.execute("DROP TABLE deep_proposal_execution_links")
    before = hashlib.sha256((tmp_path / "case.db").read_bytes()).hexdigest()
    receipts, _, _ = _case_db_readback(tmp_path, case_id)
    assert receipts is None
    assert hashlib.sha256((tmp_path / "case.db").read_bytes()).hexdigest() == before


def test_score_reads_current_deep_receipt_without_rewriting_original_capture(
    tmp_path: Path,
) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {
                    "case-0123456789ab": {
                        "useful_registered_checks": [{"probe_id": "network.configuration"}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    def invoke(_visible: VisibleCase, _arm: str, directory: Path) -> dict[str, object]:
        runtime_case_id, _ = _deep_database(directory / "case.db")
        capture = _capture("case-0123456789ab")
        capture["runtime_case_id"] = runtime_case_id
        capture["final_state"] = {"case_id": runtime_case_id}
        capture["custody"]["executions"] = []
        capture["custody"]["deep_origin_receipts"] = [{"verified": False}]
        return capture

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", invoke)
    capture_before = (attempt / "capture.json").read_bytes()
    oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
    first = score_attempt(attempt, suite, oracle, oracle_sha)
    assert first["fast_complete_mechanical_loops"] == 0
    assert first["deep_complete_mechanical_loops"] == 1
    assert first["deep_complete_useful_observation_loops"] == 1
    assert first["useful_choice_observed"] is True
    original = (attempt / "score.json").read_bytes()
    second = score_attempt(attempt, suite, oracle, oracle_sha, score_revision="c" * 40)
    assert second["deep_complete_useful_observation_loops"] == 1
    assert (attempt / "score.json").read_bytes() == original
    assert (attempt / "capture.json").read_bytes() == capture_before


def test_fake_deep_receipt_in_capture_without_database_is_not_credited(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {
                    "case-0123456789ab": {
                        "useful_registered_checks": [{"probe_id": "network.configuration"}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        capture = _capture("case-0123456789ab")
        capture["custody"]["executions"] = []
        capture["custody"]["deep_origin_receipts"] = [
            {
                "verified": True,
                "probe_id": "network.configuration",
                "observation_quality": "supported_structured_observation",
            }
        ]
        return capture

    attempt = run_attempt(suite, "case-0123456789ab", _stamp(), tmp_path / "runs", invoke)
    score = score_attempt(attempt, suite, oracle, hashlib.sha256(oracle.read_bytes()).hexdigest())
    assert score["deep_complete_mechanical_loops"] == 0
    assert score["deep_complete_useful_observation_loops"] == 0
    assert score["deep_proposed_execution"] == "unknown_legacy_or_missing_receipt_table"


def test_oracle_change_after_preregistration_is_rejected(tmp_path: Path) -> None:
    path, digest = _suite(tmp_path)
    suite = load_frozen_suite(path, digest)
    oracle = tmp_path / "oracle.json"
    oracle.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "suite_sha256": digest,
                "cases": {"case-0123456789ab": {"useful_probe_ids": ["core.resources"]}},
            }
        ),
        encoding="utf-8",
    )
    frozen_oracle_sha = hashlib.sha256(oracle.read_bytes()).hexdigest()
    stamp = RunStamp(
        "development_baseline", "laya_sol", "a" * 40, "a" * 40, oracle_sha256=frozen_oracle_sha
    )

    def invoke(_visible: VisibleCase, _arm: str, _directory: Path) -> dict[str, object]:
        return _capture("case-0123456789ab")

    attempt = run_attempt(suite, "case-0123456789ab", stamp, tmp_path / "runs", invoke)
    oracle.write_text(oracle.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="oracle digest"):
        score_attempt(attempt, suite, oracle, frozen_oracle_sha)
