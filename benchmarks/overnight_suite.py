"""Frozen, append-only evaluation custody for existing Investigator case runners.

This module never starts a model or creates an Investigator. A caller supplies a
case runner that uses the production application with registered, read-only
collectors. Hidden outcomes are loaded only by ``score_attempt`` after capture.
Automated links are mechanical; semantic correctness needs separate review.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import sqlite3
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, Literal, cast
from uuid import uuid4

from systemsense.application.deep_worker import DeepWorkerResultV1, FrozenDeepTaskV1
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.probes import ProbeInvocation, ProbeManifest
from systemsense.storage.sqlite_store import SQLiteStore

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CASE_ID = re.compile(r"case-[0-9a-f]{12,64}\Z")
_REV = re.compile(r"[0-9a-f]{7,40}\Z")
_CASE_KEYS = frozenset(
    {
        "case_id",
        "split",
        "family_group",
        "source",
        "visible_input_sha256",
        "initial_evidence_sha256",
        "action_contract_sha256",
        "budget_ms",
    }
)
_ROUTES = frozenset({"deterministic", "laya_sol", "deterministic_search_sol"})
_PHASE_SPLIT = {
    "development_baseline": "development",
    "development_candidate": "development",
    "heldout_baseline": "holdout",
    "heldout_candidate": "holdout",
}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return cast(dict[str, Any], value)


def _write_once(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


@dataclass(frozen=True, slots=True)
class VisibleCase:
    """Only fields allowed across the runner/policy boundary."""

    case_id: str
    visible_input_sha256: str
    initial_evidence_sha256: str
    action_contract_sha256: str
    budget_ms: int


@dataclass(frozen=True, slots=True)
class CaseSpec:
    visible: VisibleCase
    split: Literal["development", "holdout"]
    family_group: str
    source: Literal["synthetic", "windows_vm", "real_user"]


@dataclass(frozen=True, slots=True)
class FrozenSuite:
    sha256: str
    path: Path
    cases: tuple[CaseSpec, ...]

    def case(self, case_id: str) -> CaseSpec:
        matches = [case for case in self.cases if case.visible.case_id == case_id]
        if len(matches) != 1:
            raise ValueError("case is absent from frozen suite")
        return matches[0]


@dataclass(frozen=True, slots=True)
class RunStamp:
    phase: str
    arm: str
    code_revision: str
    baseline_revision: str
    candidate_revision: str | None = None
    oracle_sha256: str | None = None

    def validate(self, split: str) -> None:
        if self.phase not in _PHASE_SPLIT or _PHASE_SPLIT[self.phase] != split:
            raise ValueError("run phase does not match frozen case split")
        if self.arm not in _ROUTES:
            raise ValueError("unknown policy arm")
        if not all(_REV.fullmatch(value) for value in (self.code_revision, self.baseline_revision)):
            raise ValueError("invalid revision stamp")
        if self.candidate_revision is not None and not _REV.fullmatch(self.candidate_revision):
            raise ValueError("invalid candidate revision stamp")
        if self.phase.endswith("baseline") and self.code_revision != self.baseline_revision:
            raise ValueError("baseline run must use the baseline revision")
        if self.phase.endswith("candidate") and (
            self.candidate_revision is None or self.code_revision != self.candidate_revision
        ):
            raise ValueError("candidate run must use the candidate revision")
        if split == "holdout" and self.candidate_revision is None:
            raise ValueError("heldout comparison requires frozen candidate revision")
        if self.oracle_sha256 is not None and not _SHA.fullmatch(self.oracle_sha256):
            raise ValueError("invalid preregistered oracle digest")


def load_frozen_suite(path: Path, expected_sha256: str) -> FrozenSuite:
    """Load exact bytes pinned outside the manifest; fail on changes or answer fields."""
    if not _SHA.fullmatch(expected_sha256):
        raise ValueError("expected suite digest is invalid")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("frozen suite digest mismatch")
    payload = _read_json(path)
    if set(payload) != {"schema_version", "cases"} or payload["schema_version"] != 1:
        raise ValueError("suite has unknown fields or schema version")
    rows = payload["cases"]
    if not isinstance(rows, list) or not rows:
        raise ValueError("suite requires cases")
    rows = cast(list[object], rows)
    cases: list[CaseSpec] = []
    seen: set[str] = set()
    for raw_row in rows:
        if not isinstance(raw_row, dict):
            raise ValueError("case has unknown or missing fields; oracle data is prohibited")
        row = cast(dict[str, Any], raw_row)
        if set(row) != set(_CASE_KEYS):
            raise ValueError("case has unknown or missing fields; oracle data is prohibited")
        if not isinstance(row["case_id"], str) or not _CASE_ID.fullmatch(row["case_id"]):
            raise ValueError("case ID must be opaque")
        if row["case_id"] in seen:
            raise ValueError("duplicate case ID")
        seen.add(row["case_id"])
        if row["split"] not in {"development", "holdout"}:
            raise ValueError("invalid case split")
        if row["source"] not in {"synthetic", "windows_vm", "real_user"}:
            raise ValueError("invalid case source")
        if not isinstance(row["family_group"], str) or not re.fullmatch(
            r"[a-z][a-z0-9_]{2,79}", row["family_group"]
        ):
            raise ValueError("invalid family group")
        for name in (
            "visible_input_sha256",
            "initial_evidence_sha256",
            "action_contract_sha256",
        ):
            if not isinstance(row[name], str) or not _SHA.fullmatch(row[name]):
                raise ValueError(f"invalid {name}")
        if (
            not isinstance(row["budget_ms"], int)
            or isinstance(row["budget_ms"], bool)
            or not 100 <= row["budget_ms"] <= 600_000
        ):
            raise ValueError("invalid case budget")
        visible = VisibleCase(
            row["case_id"],
            row["visible_input_sha256"],
            row["initial_evidence_sha256"],
            row["action_contract_sha256"],
            row["budget_ms"],
        )
        cases.append(CaseSpec(visible, row["split"], row["family_group"], row["source"]))
    # Groups may appear in both partitions for matched within-family comparisons.
    # This is recorded rather than misrepresented as family-disjoint holdout.
    return FrozenSuite(expected_sha256, path.resolve(), tuple(cases))


def suite_partition_counts(suite: FrozenSuite) -> dict[str, object]:
    development = sum(case.split == "development" for case in suite.cases)
    holdout = sum(case.split == "holdout" for case in suite.cases)
    family_splits: dict[str, set[str]] = {}
    for case in suite.cases:
        family_splits.setdefault(case.family_group, set()).add(case.split)
    return {
        "case_count": len(suite.cases),
        "development": development,
        "holdout": holdout,
        "family_disjoint": all(len(splits) == 1 for splits in family_splits.values()),
        "minimum_12_six_each": len(suite.cases) >= 12 and development >= 6 and holdout >= 6,
    }


CaseRunner = Callable[[VisibleCase, str, Path], dict[str, object]]


def run_attempt(
    suite: FrozenSuite,
    case_id: str,
    stamp: RunStamp,
    output_root: Path,
    invoke: CaseRunner,
) -> Path:
    """Run one existing Investigator callback and preserve failure attempts."""
    case = suite.case(case_id)
    stamp.validate(case.split)
    if hashlib.sha256(suite.path.read_bytes()).hexdigest() != suite.sha256:
        raise ValueError("frozen suite digest changed before attempt")
    parent = output_root / suite.sha256 / case_id / stamp.phase / stamp.arm
    parent.mkdir(parents=True, exist_ok=True)
    attempt = parent / f"attempt-{uuid4().hex}"
    attempt.mkdir(exist_ok=False)
    _write_once(
        attempt / "start.json",
        {
            "schema_version": 1,
            "attempt_id": attempt.name,
            "suite_sha256": suite.sha256,
            "case_id": case_id,
            "split": case.split,
            "phase": stamp.phase,
            "arm": stamp.arm,
            "code_revision": stamp.code_revision,
            "baseline_revision": stamp.baseline_revision,
            "candidate_revision": stamp.candidate_revision,
            "oracle_sha256": stamp.oracle_sha256,
            "visible_input_sha256": case.visible.visible_input_sha256,
            "initial_evidence_sha256": case.visible.initial_evidence_sha256,
            "action_contract_sha256": case.visible.action_contract_sha256,
            "budget_ms": case.visible.budget_ms,
            "started_at": datetime.now(UTC).isoformat(),
        },
    )
    try:
        capture = invoke(case.visible, stamp.arm, attempt)
        if capture.get("case_id") != case_id or capture.get("status") not in {
            "completed",
            "failed",
            "timeout",
        }:
            raise ValueError("runner did not return bound case and status")
        contract = capture.get("contract")
        if not isinstance(contract, dict) or any(
            cast(dict[str, Any], contract).get(key) != getattr(case.visible, key)
            for key in (
                "visible_input_sha256",
                "initial_evidence_sha256",
                "action_contract_sha256",
            )
        ):
            raise ValueError("runner did not attest the frozen evidence/action contract")
        _write_once(attempt / "capture.json", capture)
        _write_once(
            attempt / "capture.sha256.json",
            {"sha256": hashlib.sha256((attempt / "capture.json").read_bytes()).hexdigest()},
        )
    except Exception as error:
        _write_once(
            attempt / "failure.json",
            {
                "type": type(error).__name__,
                "message": str(error),
                "at": datetime.now(UTC).isoformat(),
            },
        )
    return attempt


def _later_applied_response(
    mailbox: list[dict[str, Any]],
    evidence_ids: set[str],
    finished_at: str,
    expected_provider: str,
    *,
    strict: bool = False,
    expected_case_id: str | None = None,
) -> list[str]:
    links: list[str] = []
    finished = datetime.fromisoformat(finished_at)
    for item in mailbox:
        if (
            item.get("status") != "applied"
            or datetime.fromisoformat(str(item["created_at"])) <= finished
        ):
            continue
        task = cast(dict[str, Any], item.get("task") or {})
        request = cast(dict[str, Any], task.get("request") or {})
        result = cast(dict[str, Any], item.get("result") or {})
        response = cast(dict[str, Any], result.get("response") or {})
        if strict:
            try:
                frozen = FrozenDeepTaskV1.model_validate(task)
                completed = DeepWorkerResultV1.model_validate(result)
                if (
                    frozen.request_sha256 != item.get("request_sha256")
                    or completed.request_sha256 != item.get("request_sha256")
                    or (
                        expected_case_id is not None
                        and str(frozen.request.case_id) != expected_case_id
                    )
                    or completed.status != "completed"
                    or completed.response is None
                    or completed.response.degraded
                ):
                    continue
                completed.response.validate_against(frozen.request)
            except (ValueError, TypeError):
                continue
        shown = {
            row.get("evidence_id")
            for row in request.get("evidence_context", [])
            if row.get("status") == "observed"
        }
        considered = set(response.get("considered_evidence_ids", []))
        provider = cast(dict[str, Any], response.get("provider") or {})
        if (
            response.get("degraded", True)
            or provider.get("provider_id") != expected_provider
            or not (evidence_ids & shown & considered & set(request.get("evidence_ids", [])))
        ):
            continue
        links.append(str(item["request_sha256"]))
    return links


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    ).hexdigest()


def _observed_quality(records: list[dict[str, Any]], probe_id: str) -> str:
    """Classify exact structured collector results, never prose or keywords."""
    paths = {
        "network.configuration": ("collection_status",),
        "incident.events": ("channel_status",),
        "storage.snapshot": ("collection_status",),
        "gpu.telemetry.sample": ("gpu_telemetry_sample", "status"),
        "local_ai.snapshot": ("nvidia_telemetry", "status"),
        "pressure.sample": ("pressure", "status"),
        "power.snapshot": ("power", "status"),
    }
    statusless_outputs = {"core.resources": "resources"}
    statuses: list[str] = []
    has_statusless_output = False
    for record in records:
        if record.get("statement_kind") != "observed_fact":
            continue
        facts: dict[str, Any] = {}
        raw_facts = record.get("facts")
        if isinstance(raw_facts, list):
            for raw_fact in cast(list[object], raw_facts):
                if isinstance(raw_fact, dict):
                    fact = cast(dict[str, Any], raw_fact)
                    name = fact.get("name")
                    if isinstance(name, str):
                        facts[name] = fact.get("value")
        key = statusless_outputs.get(probe_id)
        has_statusless_output = has_statusless_output or (
            key is not None and isinstance(facts.get(key), dict) and bool(facts[key])
        )
        collection_status = facts.get("collection_status")
        if isinstance(collection_status, str):
            statuses.append(collection_status)
        path = paths.get(probe_id, ("collection_status",))
        value: Any = facts
        for key in path:
            value = cast(dict[str, Any], value).get(key) if isinstance(value, dict) else None
        if isinstance(value, dict) and probe_id == "incident.events":
            statuses.extend(str(item) for item in cast(dict[str, Any], value).values())
        elif isinstance(value, str):
            statuses.append(value)
    if any(
        status in {"denied", "unsupported", "failed", "unavailable", "truncated"}
        for status in statuses
    ):
        return "unavailable_or_failed"
    if statuses and all(status in {"available", "partial"} for status in statuses):
        return "supported_structured_observation"
    if not statuses and has_statusless_output:
        return "supported_structured_observation"
    return "unknown_structured_status"


@cache
def _builtin_manifest_hashes() -> dict[tuple[str, int], str]:
    # Discovery constructs declarations only; it never invokes a host collector.
    from systemsense.packs.runtime import default_probe_definitions

    return {
        (item.manifest.probe_id, item.manifest.version): _canonical_sha(
            item.manifest.model_dump(mode="json")
        )
        for item in default_probe_definitions()
    }


def _verified_deep_receipts(
    connection: sqlite3.Connection, case_id: str
) -> list[dict[str, Any]] | None:
    """Re-derive origin from current read-only DB; absent v38 table stays unknown."""
    if (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='deep_proposal_execution_links'"
        ).fetchone()
        is None
    ):
        return None
    rows = connection.execute(
        "SELECT request_sha256,proposal_sha256,accepted_state_version,selected_state_version,"
        "plan_instance_id,execution_id,probe_id,probe_version,manifest_sha256,"
        "manifest_json,invocation_json,invocation_sha256,schema_version "
        "FROM deep_proposal_execution_links WHERE case_id=? ORDER BY execution_id",
        (case_id,),
    ).fetchall()
    receipts: list[dict[str, Any]] = []
    for row in rows:
        (
            request_sha,
            proposal_sha,
            accepted_version,
            selected_version,
            plan_id,
            execution_id,
            probe_id,
            probe_version,
            manifest_sha,
            manifest_json,
            invocation_json,
            invocation_sha,
            schema,
        ) = row
        receipt: dict[str, Any] = {
            "case_id": case_id,
            "request_sha256": request_sha,
            "proposal_sha256": proposal_sha,
            "execution_id": execution_id,
            "plan_instance_id": plan_id,
            "probe_id": probe_id,
            "verified": False,
        }
        receipts.append(receipt)
        try:
            if schema != 1 or selected_version < accepted_version or not plan_id:
                receipt["verification_gap"] = "receipt_shape"
                continue
            mailbox = connection.execute(
                "SELECT status,task_json,result_json,updated_at FROM deep_mailbox "
                "WHERE case_id=? AND request_sha256=?",
                (case_id, request_sha),
            ).fetchone()
            step = connection.execute(
                "SELECT record_json FROM investigation_steps WHERE case_id=? AND state_version=?",
                (case_id, accepted_version),
            ).fetchone()
            execution = connection.execute(
                "SELECT case_id,probe_id,probe_version,status,parameters_json,state_version,"
                "started_at,finished_at FROM probe_executions WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
            registry = connection.execute(
                "SELECT manifest_json FROM probe_manifests WHERE probe_id=? AND version=?",
                (probe_id, probe_version),
            ).fetchone()
            if not mailbox or not step or not execution or mailbox[0] != "applied":
                receipt["verification_gap"] = "source_or_registry_missing"
                continue
            task = FrozenDeepTaskV1.model_validate_json(str(mailbox[1]))
            result = DeepWorkerResultV1.model_validate_json(str(mailbox[2]))
            response = result.response
            if (
                task.request_sha256 != request_sha
                or str(task.request.case_id) != case_id
                or result.request_sha256 != request_sha
                or str(result.case_id) != case_id
                or result.status != "completed"
                or response is None
                or response.degraded
                or response.provider != task.provider_identity
            ):
                receipt["verification_gap"] = "source_response_mismatch"
                continue
            response.validate_against(task.request)
            proposal = [
                item
                for item in response.distinguishing_probes
                if item.probe_id == probe_id
                and _canonical_sha(item.model_dump(mode="json")) == proposal_sha
            ]
            if len(proposal) != 1:
                receipt["verification_gap"] = "proposal_hash_mismatch"
                continue
            manifest = ProbeManifest.model_validate_json(str(manifest_json))
            invocation = ProbeInvocation.model_validate_json(str(invocation_json))
            if (
                manifest.probe_id != probe_id
                or manifest.version != probe_version
                or _canonical_sha(manifest.model_dump(mode="json")) != manifest_sha
                or _builtin_manifest_hashes().get((probe_id, probe_version)) != manifest_sha
                or (
                    registry is not None
                    and _canonical_sha(json.loads(str(registry[0]))) != manifest_sha
                )
                or _canonical_sha(invocation.model_dump(mode="json")) != invocation_sha
                or invocation.probe_id != probe_id
                or invocation.probe_version != probe_version
            ):
                receipt["verification_gap"] = "manifest_or_invocation_mismatch"
                continue
            need = proposal[0].measurement_need
            if need is None:
                if invocation.target_handle is not None or invocation.window is not None:
                    receipt["verification_gap"] = "generic_selector_added"
                    continue
            elif (
                need.capability_id != invocation.probe_id
                or need.observable != invocation.observable
                or need.target_handle != invocation.target_handle
                or need.window != invocation.window
            ):
                receipt["verification_gap"] = "typed_selector_mismatch"
                continue
            accepted = json.loads(str(step[0]))
            if accepted.get("event") != "deep_applied" or request_sha not in str(
                accepted.get("detail", "")
            ):
                receipt["verification_gap"] = "acceptance_checkpoint_mismatch"
                continue
            if (
                execution[0] != case_id
                or execution[1] != probe_id
                or execution[2] != probe_version
                or execution[3] != "ok"
                or json.loads(str(execution[4])) != invocation.parameters
                or execution[5] != selected_version
                or not mailbox[3]
                or not execution[7]
                or not (
                    datetime.fromisoformat(str(mailbox[3]))
                    <= datetime.fromisoformat(str(execution[6]))
                    <= datetime.fromisoformat(str(execution[7]))
                )
            ):
                receipt["verification_gap"] = "execution_mismatch"
                continue
            evidence_rows = connection.execute(
                "SELECT evidence_id,record_json FROM evidence WHERE case_id=? AND execution_id=?",
                (case_id, execution_id),
            ).fetchall()
            evidence = [(str(item[0]), json.loads(str(item[1]))) for item in evidence_rows]
            observed: list[tuple[str, dict[str, Any]]] = []
            for identifier, record in evidence:
                typed = EvidenceRecord.model_validate(record)
                if (
                    typed.statement_kind == "observed_fact"
                    and str(typed.evidence_id) == identifier
                    and str(typed.case_id) == case_id
                    and str(typed.collector.execution_id) == execution_id
                    and typed.collector.id == probe_id
                    and typed.collector.version == probe_version
                ):
                    observed.append((identifier, typed.model_dump(mode="json")))
            if not observed:
                receipt["verification_gap"] = "observed_evidence_missing"
                continue
            receipt.update(
                {
                    "verified": True,
                    "provider_id": response.provider.provider_id,
                    "invocation": invocation.model_dump(mode="json"),
                    "finished_at": str(execution[7]),
                    "evidence_ids": [identifier for identifier, _ in observed],
                    "observation_quality": _observed_quality(
                        [record for _, record in observed], probe_id
                    ),
                    "manifest_registry_basis": "current_builtin_registry",
                }
            )
        except (ValueError, TypeError, KeyError, AttributeError, sqlite3.Error) as error:
            receipt["verification_gap"] = f"invalid_source_{type(error).__name__}"
            continue
    return receipts


def _useful_selection(
    execution: dict[str, Any],
    useful_candidates: set[str],
    useful_probes: set[str],
    scoped_checks: list[dict[str, Any]],
) -> str | None:
    for check in scoped_checks:
        if execution.get("probe_id") != check["probe_id"]:
            continue
        if "target_handle" in check and execution.get("target_handle") != check["target_handle"]:
            continue
        parameters = cast(dict[str, Any], execution.get("parameters") or {})
        expected = cast(dict[str, Any], check.get("parameter_equals") or {})
        if all(parameters.get(key) == value for key, value in expected.items()):
            return "registered_probe_target_parameter_predicate"
    if not scoped_checks and execution.get("candidate_id") in useful_candidates:
        return "exact_candidate_id"
    if not scoped_checks and execution.get("probe_id") in useful_probes:
        return "registered_probe_id_only_scope_unreviewed"
    return None


def _score_custody(
    custody: dict[str, Any],
    useful_candidates: set[str],
    useful_probes: set[str],
    scoped_checks: list[dict[str, Any]],
    arm: str,
) -> dict[str, object]:
    snapshots = cast(list[dict[str, Any]], custody.get("snapshots") or [])
    executions = cast(list[dict[str, Any]], custody.get("executions") or [])
    mailbox = cast(list[dict[str, Any]], custody.get("mailbox") or [])
    links: list[dict[str, object]] = []
    selected: list[str] = []
    required_ranking_source = "laya" if arm == "laya_sol" else "deterministic_fallback"
    required_reasoning_provider = (
        "deterministic-reasoning" if arm == "deterministic" else "codex-subscription-reasoning"
    )
    for snapshot in snapshots:
        response = cast(dict[str, Any], snapshot.get("response") or {})
        ranked = cast(list[str], response.get("ranked_item_ids") or [])
        if (
            response.get("degraded_reason")
            or response.get("ranking_source") != required_ranking_source
            or not ranked
        ):
            continue
        request = cast(dict[str, Any], snapshot.get("request") or {})
        item = next(
            (row for row in request.get("items", []) if row.get("item_id") == ranked[0]),
            None,
        )
        if item is None:
            continue
        reference = cast(dict[str, Any], item.get("reference") or {})
        if reference.get("kind") != "measure":
            continue
        candidate_id = str(reference.get("candidate_id"))
        selected.append(candidate_id)
        for execution in executions:
            if (
                execution.get("snapshot_id") != snapshot.get("snapshot_id")
                or execution.get("candidate_id") != candidate_id
                or not execution.get("admission_id")
                or execution.get("status") != "ok"
                or not execution.get("finished_at")
            ):
                continue
            evidence = set(execution.get("evidence_ids") or [])
            if not evidence:
                continue
            later = _later_applied_response(
                mailbox, evidence, str(execution["finished_at"]), required_reasoning_provider
            )
            useful_scope = _useful_selection(
                execution, useful_candidates, useful_probes, scoped_checks
            )
            links.append(
                {
                    "snapshot_id": snapshot["snapshot_id"],
                    "candidate_id": candidate_id,
                    "admission_id": execution["admission_id"],
                    "execution_id": execution["execution_id"],
                    "evidence_ids": sorted(evidence),
                    "later_applied_request_sha256": later,
                    "choice_useful_by_hidden_oracle": useful_scope is not None,
                    "observation_quality": execution.get(
                        "observation_quality", "unknown_structured_status"
                    ),
                    "useful_match_scope": useful_scope,
                }
            )
    # A deep mailbox proposal alone is never execution provenance. Existing
    # collection-followup admissions bind a decision snapshot, not necessarily
    # a deep model proposal. Keep deep-origin credit unknown until a durable
    # model-origin receipt is supplied and independently checked.
    returned = [link for link in links if link["later_applied_request_sha256"]]
    return {
        "selected_candidate_ids": selected,
        "selection_execution_links": links,
        "mechanical_choice_execution_response": bool(returned),
        "useful_choice_observed": any(
            link["choice_useful_by_hidden_oracle"]
            and link["observation_quality"] == "supported_structured_observation"
            and link["later_applied_request_sha256"]
            for link in links
        ),
        "deep_proposed_execution": "not_evaluated_without_model_origin_receipt",
        "next_probe_execution_attribution": "unknown_without_persisted_decision_response",
    }


def _score_deep_receipts(
    receipts: list[dict[str, Any]] | None,
    mailbox: list[dict[str, Any]],
    useful_candidates: set[str],
    useful_probes: set[str],
    scoped_checks: list[dict[str, Any]],
    arm: str,
) -> dict[str, object]:
    if receipts is None:
        return {
            "deep_proposed_execution": "unknown_legacy_or_missing_receipt_table",
            "deep_origin_execution_links": [],
            "deep_mechanical_choice_execution_response": False,
            "deep_useful_choice_observed": False,
        }
    expected_provider = (
        "deterministic-reasoning" if arm == "deterministic" else "codex-subscription-reasoning"
    )
    links: list[dict[str, object]] = []
    for receipt in receipts:
        if not receipt.get("verified") or receipt.get("provider_id") != expected_provider:
            continue
        invocation = cast(dict[str, Any], receipt["invocation"])
        execution = {
            "candidate_id": None,
            "probe_id": receipt["probe_id"],
            "target_handle": invocation.get("target_handle"),
            "parameters": invocation.get("parameters", {}),
        }
        useful_scope = _useful_selection(execution, useful_candidates, useful_probes, scoped_checks)
        later = _later_applied_response(
            mailbox,
            set(cast(list[str], receipt["evidence_ids"])),
            str(receipt["finished_at"]),
            expected_provider,
            strict=True,
            expected_case_id=str(receipt["case_id"]),
        )
        links.append(
            {
                "request_sha256": receipt["request_sha256"],
                "proposal_sha256": receipt["proposal_sha256"],
                "execution_id": receipt["execution_id"],
                "plan_instance_id": receipt["plan_instance_id"],
                "probe_id": receipt["probe_id"],
                "evidence_ids": receipt["evidence_ids"],
                "observation_quality": receipt["observation_quality"],
                "later_applied_request_sha256": later,
                "choice_useful_by_hidden_oracle": useful_scope is not None,
                "useful_match_scope": useful_scope,
            }
        )
    return {
        "deep_proposed_execution": "verified_receipt_readback"
        if links
        else "no_verified_deep_origin",
        "deep_origin_execution_links": links,
        "deep_origin_receipt_rows": len(receipts),
        "deep_origin_rejected_rows": sum(not item.get("verified", False) for item in receipts),
        "deep_mechanical_choice_execution_response": any(
            link["later_applied_request_sha256"] for link in links
        ),
        "deep_useful_choice_observed": any(
            link["choice_useful_by_hidden_oracle"]
            and link["observation_quality"] == "supported_structured_observation"
            and link["later_applied_request_sha256"]
            for link in links
        ),
    }


def _case_db_readback(
    attempt: Path, runtime_case_id: object
) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]], dict[str, str]]:
    """Read the preserved case database without opening SQLiteStore or migrating it."""
    path = attempt / "case.db"
    if not isinstance(runtime_case_id, str) or not path.is_file():
        return None, [], {}
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    try:
        receipts = _verified_deep_receipts(connection, runtime_case_id)
        mailbox = [
            {
                "request_sha256": row[0],
                "status": row[1],
                "created_at": row[2],
                "updated_at": row[3],
                "task": json.loads(str(row[4])),
                "result": None if row[5] is None else json.loads(str(row[5])),
            }
            for row in connection.execute(
                "SELECT request_sha256,status,created_at,updated_at,task_json,result_json "
                "FROM deep_mailbox WHERE case_id=? ORDER BY created_at",
                (runtime_case_id,),
            )
        ]
        quality: dict[str, str] = {}
        for execution_id, probe_id in connection.execute(
            "SELECT execution_id,probe_id FROM probe_executions WHERE case_id=?",
            (runtime_case_id,),
        ):
            records = [
                json.loads(str(row[0]))
                for row in connection.execute(
                    "SELECT record_json FROM evidence WHERE case_id=? AND execution_id=?",
                    (runtime_case_id, execution_id),
                )
            ]
            quality[str(execution_id)] = _observed_quality(records, str(probe_id))
        return receipts, mailbox, quality
    finally:
        connection.close()


def _valid_laya_frontier_snapshot(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    snapshot = cast(dict[str, object], value)
    request_value = snapshot.get("request")
    response_value = snapshot.get("response")
    if not isinstance(request_value, dict) or not isinstance(response_value, dict):
        return False
    request = cast(dict[str, object], request_value)
    response = cast(dict[str, object], response_value)
    items_value = request.get("items")
    ranked_value = response.get("ranked_item_ids")
    considered_value = response.get("considered_item_ids")
    if (
        not isinstance(items_value, list)
        or not items_value
        or any(not isinstance(item, dict) for item in cast(list[object], items_value))
        or not isinstance(ranked_value, list)
        or not ranked_value
        or any(not isinstance(item, str) for item in cast(list[object], ranked_value))
        or not isinstance(considered_value, list)
        or any(not isinstance(item, str) for item in cast(list[object], considered_value))
    ):
        return False
    items = cast(list[dict[str, object]], items_value)
    if any(not isinstance(item.get("item_id"), str) for item in items):
        return False
    ranked = cast(list[str], ranked_value)
    considered = cast(list[str], considered_value)
    offered_ids = {cast(str, item["item_id"]) for item in items}
    expected_provider = {
        "provider_id": "laya-local-decision",
        "provider_version": "1",
        "role": "fast_decision",
    }
    return (
        request.get("provider") == expected_provider
        and response.get("provider") == expected_provider
        and response.get("ranking_source") == "laya"
        and response.get("degraded_reason") is None
        and response.get("model_abstained") is False
        and response.get("coverage_complete") is True
        and set(considered) == offered_ids
        and set(ranked) <= offered_ids
    )


def _route_realization(capture: dict[str, Any], arm: str) -> dict[str, object]:
    runtime = cast(dict[str, Any], capture.get("runtime") or {})
    calls = cast(list[dict[str, Any]], runtime.get("provider_calls") or [])
    observed = {
        (str(call.get("role")), str(call.get("provider_id")))
        for call in calls
        if call.get("degraded") is False
    }
    required = {
        "deterministic": {
            ("fast_decision", "keyword-baseline"),
            ("reasoning", "deterministic-reasoning"),
        },
        "laya_sol": {
            ("reasoning", "codex-subscription-reasoning"),
        },
        "deterministic_search_sol": {
            ("fast_decision", "keyword-baseline"),
            ("reasoning", "codex-subscription-reasoning"),
        },
    }[arm]
    missing = sorted(f"{role}:{provider}" for role, provider in required - observed)
    if arm == "laya_sol":
        custody_value: object = capture.get("custody")
        custody = cast(dict[str, object], custody_value) if isinstance(custody_value, dict) else {}
        snapshots_value = custody.get("snapshots")
        laya_rank_observed = isinstance(snapshots_value, list) and any(
            _valid_laya_frontier_snapshot(snapshot)
            for snapshot in cast(list[object], snapshots_value)
        )
        if not laya_rank_observed:
            missing.append("frontier_rank:laya-local-decision")
    return {
        "status": "demonstrated" if not missing else "not_demonstrated",
        "missing_provider_calls": missing,
        "declared_route": arm,
        "deep_only_choice_claim": False,
    }


def _metrics(capture: dict[str, Any]) -> dict[str, object]:
    custody = cast(dict[str, Any], capture.get("custody") or {})
    mailbox = cast(list[dict[str, Any]], custody.get("mailbox") or [])
    completed: list[int] = []
    for item in mailbox:
        if item.get("status") != "applied" or not item.get("updated_at"):
            continue
        start = datetime.fromisoformat(str(item["created_at"]))
        end = datetime.fromisoformat(str(item["updated_at"]))
        if end >= start:
            completed.append(round((end - start).total_seconds() * 1000))
    runtime = cast(dict[str, Any], capture.get("runtime") or {})
    return {
        "completed_mailbox_durations_ms": completed,
        "completed_mailbox_duration_kind": "mailbox_wall_time_not_pure_model_latency",
        "raw_invalid_retries": runtime.get("raw_invalid_retries"),
        "startup_ms": runtime.get("startup_ms"),
        "provider_calls": runtime.get("provider_calls", []),
        "resource_observations": runtime.get("resource_observations", []),
        "case_started_at": runtime.get("case_started_at"),
        "case_finished_at": runtime.get("case_finished_at"),
        "cold_startup_ms": runtime.get("cold_startup_ms"),
        "warm_runtime_reused": runtime.get("warm_runtime_reused"),
        "raw_model_attempts": runtime.get("codex_raw_attempts", []),
        "raw_invalid_retry_metric_scope": runtime.get("raw_invalid_retry_metric_scope"),
        "codex_acknowledged_runtime": runtime.get("codex_acknowledged_runtime"),
    }


def _observed_probe_utility(
    custody: dict[str, Any], useful_probe_ids: set[str], case_started_at: object
) -> dict[str, object]:
    rows = cast(list[dict[str, Any]], custody.get("probe_executions") or [])
    useful_rows = [
        row
        for row in rows
        if row.get("probe_id") in useful_probe_ids
        and row.get("status") == "ok"
        and row.get("finished_at")
        and row.get("evidence_ids")
    ]
    supported_rows = [
        row
        for row in useful_rows
        if row.get("observation_quality") == "supported_structured_observation"
    ]
    first_ms: int | None = None
    if isinstance(case_started_at, str) and useful_rows:
        started = datetime.fromisoformat(case_started_at)
        finished = min(datetime.fromisoformat(str(row["finished_at"])) for row in useful_rows)
        if finished >= started:
            first_ms = round((finished - started).total_seconds() * 1000)
    return {
        "useful_registered_probe_executions": [
            {
                "probe_id": row["probe_id"],
                "execution_id": row["execution_id"],
                "observation_quality": row.get("observation_quality", "unknown_structured_status"),
            }
            for row in useful_rows
        ],
        "supported_useful_registered_probe_executions": [
            {"probe_id": row["probe_id"], "execution_id": row["execution_id"]}
            for row in supported_rows
        ],
        "useful_registered_probe_executions_scope": "probe_execution_transport_not_causal_choice",
        "time_to_first_useful_probe_evidence_ms": first_ms,
        "probe_choice_attribution": "unknown_without_model_origin_receipt",
    }


def _valid_check(item: object) -> bool:
    if not isinstance(item, dict):
        return False
    check = cast(dict[str, object], item)
    return (
        isinstance(check.get("probe_id"), str)
        and set(check) <= {"probe_id", "target_handle", "parameter_equals"}
        and ("parameter_equals" not in check or isinstance(check["parameter_equals"], dict))
    )


def score_attempt(
    attempt: Path,
    suite: FrozenSuite,
    oracle_path: Path,
    expected_oracle_sha256: str,
    *,
    score_revision: str | None = None,
) -> dict[str, object]:
    """Score after a run; hidden oracle never enters ``run_attempt``."""
    if score_revision is not None and not _REV.fullmatch(score_revision):
        raise ValueError("invalid scorer revision")
    start = _read_json(attempt / "start.json")
    if start.get("suite_sha256") != suite.sha256:
        raise ValueError("attempt suite digest mismatch")
    if hashlib.sha256(suite.path.read_bytes()).hexdigest() != suite.sha256:
        raise ValueError("frozen suite digest changed before scoring")
    case = suite.case(str(start["case_id"]))
    if any(
        start.get(key) != getattr(case.visible, key)
        for key in (
            "visible_input_sha256",
            "initial_evidence_sha256",
            "action_contract_sha256",
            "budget_ms",
        )
    ):
        raise ValueError("attempt contract differs from frozen suite")
    if (
        not _SHA.fullmatch(expected_oracle_sha256)
        or hashlib.sha256(oracle_path.read_bytes()).hexdigest() != expected_oracle_sha256
    ):
        raise ValueError("evaluator-only oracle digest mismatch")
    if start.get("oracle_sha256") not in (None, expected_oracle_sha256):
        raise ValueError("oracle differs from preregistered attempt digest")
    oracle = _read_json(oracle_path)
    if oracle.get("schema_version") != 1 or oracle.get("suite_sha256") != suite.sha256:
        raise ValueError("evaluator-only oracle binding mismatch")
    labels = cast(dict[str, dict[str, Any]], oracle.get("cases") or {}).get(case.visible.case_id)
    if start.get("split") == "holdout":
        consumption = attempt / "holdout_consumption.json"
        binding = {
            "schema_version": 1,
            "suite_sha256": suite.sha256,
            "case_id": case.visible.case_id,
            "phase": start["phase"],
            "code_revision": start["code_revision"],
            "oracle_sha256": expected_oracle_sha256,
        }
        if score_revision is not None and consumption.exists():
            prior = _read_json(consumption)
            if any(prior.get(key) != value for key, value in binding.items()):
                raise ValueError("holdout consumption binding differs from attempt")
        else:
            _write_once(
                consumption,
                {**binding, "consumed_at": datetime.now(UTC).isoformat()},
            )
    if not isinstance(labels, dict):
        raise ValueError("case is absent from evaluator-only oracle")
    useful = labels.get("useful_candidate_ids", [])
    if not isinstance(useful, list) or any(
        not isinstance(item, str) for item in cast(list[object], useful)
    ):
        raise ValueError("invalid evaluator-only useful candidate IDs")
    useful = cast(list[str], useful)
    useful_probes = labels.get("useful_probe_ids", [])
    if not isinstance(useful_probes, list) or any(
        not isinstance(item, str) for item in cast(list[object], useful_probes)
    ):
        raise ValueError("invalid evaluator-only useful probe IDs")
    useful_probes = cast(list[str], useful_probes)
    scoped_checks = labels.get("useful_registered_checks", [])
    if not isinstance(scoped_checks, list) or not all(
        _valid_check(item) for item in cast(list[object], scoped_checks)
    ):
        raise ValueError("invalid evaluator-only registered check predicates")
    scoped_checks = cast(list[dict[str, Any]], scoped_checks)
    if (attempt / "failure.json").exists() or not (attempt / "capture.json").exists():
        score: dict[str, object] = {
            "status": "failed",
            "mechanical_choice_execution_response": False,
            "useful_choice_observed": False,
            "semantic_correctness": "human_review_pending",
            "raw_rejected_response_claim_review": "human_review_pending",
            "accepted_final_claim_review": "human_review_pending",
            "failure": _read_json(attempt / "failure.json")
            if (attempt / "failure.json").exists()
            else "capture_missing",
        }
    else:
        digest_receipt = _read_json(attempt / "capture.sha256.json")
        if hashlib.sha256(
            (attempt / "capture.json").read_bytes()
        ).hexdigest() != digest_receipt.get("sha256"):
            raise ValueError("attempt capture digest mismatch")
        capture = _read_json(attempt / "capture.json")
        if capture.get("case_id") != case.visible.case_id:
            raise ValueError("capture case binding mismatch")
        contract = capture.get("contract")
        if not isinstance(contract, dict) or any(
            cast(dict[str, Any], contract).get(key) != getattr(case.visible, key)
            for key in (
                "visible_input_sha256",
                "initial_evidence_sha256",
                "action_contract_sha256",
            )
        ):
            raise ValueError("capture contract differs from frozen suite")
        custody = cast(dict[str, Any], capture.get("custody") or {})
        receipts, persisted_mailbox, execution_quality = _case_db_readback(
            attempt, capture.get("runtime_case_id")
        )
        final_state = capture.get("final_state")
        if not isinstance(final_state, dict) or cast(dict[str, Any], final_state).get(
            "case_id"
        ) != capture.get("runtime_case_id"):
            receipts = None
            persisted_mailbox = []
            execution_quality = {}
        for execution in cast(list[dict[str, Any]], custody.get("executions") or []):
            quality = execution_quality.get(str(execution.get("execution_id")))
            if quality is not None:
                execution["observation_quality"] = quality
        for execution in cast(list[dict[str, Any]], custody.get("probe_executions") or []):
            quality = execution_quality.get(str(execution.get("execution_id")))
            if quality is not None:
                execution["observation_quality"] = quality
        mechanical = _score_custody(
            custody, set(useful), set(useful_probes), scoped_checks, str(start["arm"])
        )
        deep = _score_deep_receipts(
            receipts,
            persisted_mailbox,
            set(useful),
            set(useful_probes),
            scoped_checks,
            str(start["arm"]),
        )
        route = _route_realization(capture, str(start["arm"]))
        runtime = cast(dict[str, Any], capture.get("runtime") or {})
        observed_probe_utility = _observed_probe_utility(
            custody, set(useful_probes), runtime.get("case_started_at")
        )
        model_inputs = capture.get("model_inputs")
        markers = labels.get("leak_markers", [])
        if not isinstance(markers, list) or any(
            not isinstance(item, str) for item in cast(list[object], markers)
        ):
            raise ValueError("invalid evaluator-only leak markers")
        markers = cast(list[str], markers)
        if isinstance(model_inputs, list) and any(
            not isinstance(item, str) for item in cast(list[object], model_inputs)
        ):
            raise ValueError("captured model inputs must be text")
        model_inputs = cast(list[str] | None, model_inputs)
        leakage = (
            "not_applicable_no_model"
            if start["arm"] == "deterministic"
            else "unknown_exact_input_capture_missing"
            if not isinstance(model_inputs, list) or not model_inputs
            else "failed_hidden_marker_present"
            if any(marker and marker in text for marker in markers for text in model_inputs)
            else "unknown_partial_model_input_capture"
            if runtime.get("model_input_capture_complete") is not True
            else "passed_exact_captured_inputs"
        )
        eligible = bool(
            capture.get("status") == "completed"
            and route["status"] == "demonstrated"
            and leakage != "failed_hidden_marker_present"
        )
        fast_links = cast(list[dict[str, Any]], mechanical["selection_execution_links"])
        deep_links = cast(list[dict[str, Any]], deep["deep_origin_execution_links"])
        score = {
            "status": capture.get("status"),
            **mechanical,
            **deep,
            "fast_choice_execution_links": len(fast_links) if eligible else 0,
            "deep_choice_execution_links": len(deep_links) if eligible else 0,
            "fast_useful_check_choices": sum(
                bool(link["choice_useful_by_hidden_oracle"]) for link in fast_links
            )
            if eligible
            else 0,
            "deep_useful_check_choices": sum(
                bool(link["choice_useful_by_hidden_oracle"]) for link in deep_links
            )
            if eligible
            else 0,
            "fast_complete_mechanical_loops": sum(
                bool(link["later_applied_request_sha256"]) for link in fast_links
            )
            if eligible
            else 0,
            "deep_complete_mechanical_loops": sum(
                bool(link["later_applied_request_sha256"]) for link in deep_links
            )
            if eligible
            else 0,
            "fast_complete_useful_observation_loops": sum(
                bool(link["later_applied_request_sha256"])
                and bool(link["choice_useful_by_hidden_oracle"])
                and link["observation_quality"] == "supported_structured_observation"
                for link in fast_links
            )
            if eligible
            else 0,
            "deep_complete_useful_observation_loops": sum(
                bool(link["later_applied_request_sha256"])
                and bool(link["choice_useful_by_hidden_oracle"])
                and link["observation_quality"] == "supported_structured_observation"
                for link in deep_links
            )
            if eligible
            else 0,
            "mechanical_choice_execution_response": bool(
                eligible
                and (
                    mechanical["mechanical_choice_execution_response"]
                    or deep["deep_mechanical_choice_execution_response"]
                )
            ),
            "mechanical_choice_execution_response_scope": (
                "verified_choice_execution_later_response_includes_unavailable_observation"
            ),
            "useful_choice_observed": bool(
                eligible
                and (mechanical["useful_choice_observed"] or deep["deep_useful_choice_observed"])
            ),
            "useful_choice_observed_scope": (
                "frozen_check_supported_structured_observation_later_applied_response"
            ),
            "model_input_leakage_audit": leakage,
            "route_realization": route,
            **observed_probe_utility,
            "probe_choice_attribution": "verified_deep_origin_for_listed_executions"
            if deep_links
            else observed_probe_utility["probe_choice_attribution"],
            "semantic_correctness": "human_review_pending",
            "raw_rejected_response_claim_review": "human_review_pending",
            "accepted_final_claim_review": "human_review_pending",
            "oracle_preregistered_with_attempt": start.get("oracle_sha256")
            == expected_oracle_sha256,
            "metrics": _metrics(capture),
        }
    if score_revision is not None:
        score["scorer_revision"] = score_revision
    score_name = "score.json" if score_revision is None else f"score-{score_revision}.json"
    _write_once(attempt / score_name, score)
    return score


def compare_frozen_contracts(attempts: list[Path]) -> dict[str, object]:
    """Compare normalized starting contracts; no byte-parity claim for clocks/IDs."""
    starts = [_read_json(path / "start.json") for path in attempts]
    fields = (
        "suite_sha256",
        "case_id",
        "visible_input_sha256",
        "initial_evidence_sha256",
        "action_contract_sha256",
        "budget_ms",
    )
    mismatches = [field for field in fields if len({row.get(field) for row in starts}) != 1]
    return {
        "matched_normalized_starting_contract": bool(starts) and not mismatches,
        "mismatched_fields": mismatches,
        "full_runtime_request_byte_parity": "not_claimed",
    }


def collect_case_custody(store: SQLiteStore, case_id: str) -> dict[str, object]:
    """Read the existing append-only Investigator candidate and deep mailbox rows."""
    from benchmarks.subscription_loop import collect_artifact

    artifact = collect_artifact(store, case_id)
    # Generic next-probe snapshots have a menu and execution links, but no
    # persisted provider response in this table. Expose them for independent
    # attribution rather than treating every subsequent run as model-selected.
    connection = store.connection
    bindings: dict[str, dict[str, Any]] = {}
    for row in connection.execute(
        "SELECT a.admission_id,c.probe_id,c.target_handle,c.invocation_json,"
        "c.invocation_sha256,a.invocation_sha256,l.executed_invocation_json,"
        "l.executed_invocation_sha256,x.probe_id "
        "FROM candidate_dispatch_admissions a "
        "JOIN case_measurement_candidates c ON c.candidate_id=a.candidate_id "
        "JOIN candidate_decision_execution_links l "
        "ON l.snapshot_id=a.snapshot_id AND l.candidate_id=a.candidate_id "
        "JOIN probe_executions x ON x.execution_id=l.execution_id "
        "WHERE a.case_id=?",
        (case_id,),
    ):
        candidate_json, executed_json = str(row[3]), str(row[6])
        candidate_digest = hashlib.sha256(candidate_json.encode("utf-8")).hexdigest()
        executed_digest = hashlib.sha256(executed_json.encode("utf-8")).hexdigest()
        invocation = json.loads(executed_json)
        if (
            candidate_digest != row[4]
            or row[4] != row[5]
            or executed_digest != row[7]
            or row[7] != row[5]
            or row[1] != row[8]
            or invocation.get("probe_id") != row[1]
        ):
            raise ValueError("candidate admission and executed invocation binding mismatch")
        bindings[str(row[0])] = {
            "probe_id": str(row[1]),
            "target_handle": row[2],
            "parameters": invocation.get("parameters", {}),
            "invocation_sha256": str(row[7]),
        }
    for execution in artifact["executions"]:
        binding = bindings.get(str(execution["admission_id"]))
        if binding is None:
            raise ValueError("candidate execution lacks exact invocation binding")
        execution.update(binding)
    artifact["next_probe_snapshots"] = [
        {
            "snapshot_id": row[0],
            "request_sha256": row[1],
            "candidate_probe_ids": json.loads(row[2]),
        }
        for row in connection.execute(
            "SELECT snapshot_id,request_sha256,candidate_probe_ids_json "
            "FROM decision_snapshots WHERE case_id=? ORDER BY captured_at,snapshot_id",
            (case_id,),
        )
    ]
    artifact["next_probe_execution_links"] = [
        {"snapshot_id": row[0], "probe_id": row[1], "execution_id": row[2]}
        for row in connection.execute(
            "SELECT snapshot_id,probe_id,execution_id FROM decision_execution_links "
            "WHERE case_id=? ORDER BY snapshot_id,execution_id",
            (case_id,),
        )
    ]
    artifact["followup_admissions"] = [
        {
            "admission_id": row[0],
            "request_sha256": row[1],
            "decision_snapshot_id": row[2],
            "probe_id": json.loads(row[3])["probe_id"],
            "execution_id": row[4],
        }
        for row in connection.execute(
            "SELECT a.admission_id,a.request_sha256,a.decision_snapshot_id,"
            "a.invocation_json,l.execution_id FROM collection_followup_admissions a "
            "LEFT JOIN collection_followup_execution_links l ON l.admission_id=a.admission_id "
            "WHERE a.case_id=? ORDER BY a.admitted_at,a.admission_id",
            (case_id,),
        )
    ]
    artifact["probe_executions"] = [
        {
            "execution_id": row[0],
            "probe_id": row[1],
            "status": row[2],
            "started_at": row[3],
            "finished_at": row[4],
            "evidence_ids": [
                evidence[0]
                for evidence in connection.execute(
                    "SELECT evidence_id FROM evidence WHERE case_id=? AND execution_id=?",
                    (case_id, row[0]),
                )
            ],
        }
        for row in connection.execute(
            "SELECT execution_id,probe_id,status,started_at,finished_at "
            "FROM probe_executions WHERE case_id=? ORDER BY started_at,execution_id",
            (case_id,),
        )
    ]
    artifact["deep_origin_receipts"] = _verified_deep_receipts(connection, case_id)
    return artifact


def _git_revision(repository: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    revision = result.stdout.strip()
    if not _REV.fullmatch(revision):
        raise ValueError("checked-out implementation revision is invalid")
    return revision


def _captured_codex_attempts(
    directory: Path,
) -> tuple[list[str], list[dict[str, object]], int | None]:
    """Preserve each raw return/failure and count visible validation retry requests."""
    prompts: list[str] = []
    attempts: list[dict[str, object]] = []
    invalid_retries = 0
    for prompt_path in sorted(directory.glob("codex-*.prompt.txt")):
        prefix = prompt_path.name.removesuffix(".prompt.txt")
        prompt = prompt_path.read_text(encoding="utf-8")
        prompts.append(prompt)
        try:
            packet = json.loads(prompt)
        except ValueError:
            packet = {}
        if isinstance(packet, dict) and "validation_retry" in packet:
            invalid_retries += 1
        raw_path = directory / f"{prefix}.raw-return.json"
        failure_path = directory / f"{prefix}.failure.json"
        request_path = directory / f"{prefix}.request.json"
        attempts.append(
            {
                "prefix": prefix,
                "prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
                "raw_return_sha256": hashlib.sha256(raw_path.read_bytes()).hexdigest()
                if raw_path.exists()
                else None,
                "failure_sha256": hashlib.sha256(failure_path.read_bytes()).hexdigest()
                if failure_path.exists()
                else None,
                "request": _read_json(request_path) if request_path.exists() else None,
                "validation_retry_prompt": isinstance(packet, dict)
                and "validation_retry" in packet,
                "output_limit_retry_prompt": isinstance(packet, dict) and "output_retry" in packet,
            }
        )
    return prompts, attempts, invalid_retries if attempts else None


def _run_selected_cases(args: argparse.Namespace) -> list[Path]:
    """Operator-only actual provider entrypoint; never called on import."""
    from benchmarks.subscription_loop import CapturingCodexClient
    from systemsense.cli import _v4_providers  # pyright: ignore[reportPrivateUsage]
    from systemsense.decision.baseline import KeywordBaselineDecisionProvider
    from systemsense.inference.codex import CodexInferenceConfig
    from systemsense.inference.factory import AdvisoryProviders
    from systemsense.inference.profile import load_inference_profile
    from systemsense.knowledge import ReferenceKnowledgeGraph
    from systemsense.reasoning.codex import CodexReasoningProvider

    run_case = cast(
        Callable[..., dict[str, object]],
        importlib.import_module("benchmarks.overnight_cases").run_case,
    )

    suite = load_frozen_suite(args.suite, args.suite_sha256)
    counts = suite_partition_counts(suite)
    if not counts["minimum_12_six_each"]:
        raise ValueError("operator run requires at least 12 frozen cases, six per partition")
    if not args.output_root.is_absolute() or args.output_root.resolve().is_relative_to(
        Path(__file__).resolve().parents[1]
    ):
        raise ValueError("private output root must be absolute and outside the repository")
    current_revision = _git_revision(Path(__file__).resolve().parents[1])
    stamp = RunStamp(
        args.phase,
        args.arm,
        current_revision,
        args.baseline_revision,
        args.candidate_revision,
        args.oracle_sha256,
    )
    split = _PHASE_SPLIT[args.phase]
    case_ids = args.case_id or [case.visible.case_id for case in suite.cases if case.split == split]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("duplicate selected case ID")
    for case_id in case_ids:
        case = suite.case(case_id)
        stamp.validate(case.split)
        if case.source != "synthetic":
            raise ValueError("overnight operator is limited to synthetic cases")
    if args.arm != "deterministic" and (
        args.codex_executable is None
        or not args.codex_executable.is_absolute()
        or not args.codex_executable.is_file()
    ):
        raise ValueError("actual Sol arms require an explicit installed Codex executable")

    warm = None
    cold_startup_ms: int | None = None
    if args.arm == "laya_sol":
        profile = load_inference_profile(args.profile)
        if profile.schema_version != 4 or profile.runtime_strategy != "warm-independent":
            raise ValueError("Laya/Sol requires the pinned warm-independent v4 profile")
        cold_start = time.monotonic()
        try:
            warm = _v4_providers(profile)
        except Exception as error:
            failure = f"Laya startup failed: {type(error).__name__}: {error}"

            def failed_startup(
                _visible: VisibleCase, _arm: str, _directory: Path
            ) -> dict[str, object]:
                raise RuntimeError(failure)

            failed_paths = [
                run_attempt(suite, case_id, stamp, args.output_root, failed_startup)
                for case_id in case_ids
            ]
            for case_id, attempt in zip(case_ids, failed_paths, strict=True):
                print(json.dumps({"case_id": case_id, "attempt": str(attempt)}, sort_keys=True))
            return failed_paths
        cold_startup_ms = round((time.monotonic() - cold_start) * 1000)
    paths: list[Path] = []
    try:
        for index, case_id in enumerate(case_ids):

            def invoke(
                visible: VisibleCase, arm: str, directory: Path, case_index: int = index
            ) -> dict[str, object]:
                if arm == "deterministic":
                    capture = run_case(visible, arm, directory, providers=None)
                    runtime = cast(dict[str, Any], capture.setdefault("runtime", {}))
                    runtime["cold_startup_ms"] = None
                    runtime["warm_runtime_reused"] = False
                    runtime["raw_invalid_retries"] = None
                    return capture
                assert args.codex_executable is not None
                config = CodexInferenceConfig(
                    enabled=True,
                    executable=args.codex_executable,
                    timeout_seconds=min(180, max(1, visible.budget_ms // 1000)),
                )
                client = CapturingCodexClient(config, directory)
                reasoning = CodexReasoningProvider(config, client=client)
                providers = (
                    AdvisoryProviders(
                        decision=warm.decision,
                        reasoning=reasoning,
                        knowledge=warm.knowledge,
                        catalog_attention=warm.catalog_attention,
                        frontier_ranker=warm.frontier_ranker,
                        configured_mode=warm.configured_mode,
                        effective_mode=warm.effective_mode,
                    )
                    if warm is not None
                    else AdvisoryProviders(
                        decision=KeywordBaselineDecisionProvider(),
                        reasoning=reasoning,
                        knowledge=ReferenceKnowledgeGraph.load_default(),
                        configured_mode="deterministic-search-sol",
                        effective_mode="deterministic-search-sol",
                    )
                )
                capture = run_case(visible, arm, directory, providers=providers)
                prompts, raw_attempts, invalid_retries = _captured_codex_attempts(directory)
                runtime = cast(dict[str, Any], capture.setdefault("runtime", {}))
                runtime["cold_startup_ms"] = cold_startup_ms if case_index == 0 else None
                runtime["warm_runtime_reused"] = warm is not None and case_index > 0
                runtime["codex_acknowledged_runtime"] = client.last_runtime
                runtime["codex_raw_attempts"] = raw_attempts
                runtime["raw_invalid_retries"] = invalid_retries
                runtime["raw_invalid_retry_metric_scope"] = (
                    "validation_retry_prompts_lower_bound"
                    if invalid_retries is not None
                    else "unknown"
                )
                runtime["model_input_capture_complete"] = warm is None and bool(prompts)
                runtime["model_input_capture_scope"] = (
                    "exact_codex_prompts_only_laya_worker_inputs_not_captured"
                    if warm is not None
                    else "exact_codex_prompts"
                )
                capture["model_inputs"] = prompts
                return capture

            attempt = run_attempt(suite, case_id, stamp, args.output_root, invoke)
            paths.append(attempt)
            print(json.dumps({"case_id": case_id, "attempt": str(attempt)}, sort_keys=True))
    finally:
        if warm is not None:
            warm.close()
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze", help="Validate and print a raw-byte suite commitment")
    freeze.add_argument("--suite", type=Path, required=True)
    freeze.add_argument("--oracle", type=Path)
    run = sub.add_parser("run", help="Run selected frozen cases with existing Investigator")
    run.add_argument("--suite", type=Path, required=True)
    run.add_argument("--suite-sha256", required=True)
    run.add_argument("--oracle-sha256", required=True)
    run.add_argument("--phase", choices=tuple(_PHASE_SPLIT), required=True)
    run.add_argument("--arm", choices=sorted(_ROUTES), required=True)
    run.add_argument("--case-id", action="append")
    run.add_argument("--output-root", type=Path, required=True)
    run.add_argument("--baseline-revision", required=True)
    run.add_argument("--candidate-revision")
    run.add_argument("--codex-executable", type=Path)
    run.add_argument(
        "--profile",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "examples/warm-local-development.profile.json",
    )
    score = sub.add_parser("score", help="Score an immutable attempt using evaluator-only oracle")
    score.add_argument("--suite", type=Path, required=True)
    score.add_argument("--suite-sha256", required=True)
    score.add_argument("--attempt", type=Path, required=True)
    score.add_argument("--oracle", type=Path, required=True)
    score.add_argument("--oracle-sha256", required=True)
    score.add_argument(
        "--score-revision", help="Write score-<revision>.json and preserve prior scores"
    )
    args = parser.parse_args()
    if args.command == "freeze":
        suite = load_frozen_suite(args.suite, hashlib.sha256(args.suite.read_bytes()).hexdigest())
        commitment = {"suite_sha256": suite.sha256, **suite_partition_counts(suite)}
        if args.oracle is not None:
            commitment["oracle_sha256"] = hashlib.sha256(args.oracle.read_bytes()).hexdigest()
        print(json.dumps(commitment, sort_keys=True))
    elif args.command == "run":
        _run_selected_cases(args)
    else:
        suite = load_frozen_suite(args.suite, args.suite_sha256)
        print(
            json.dumps(
                score_attempt(
                    args.attempt,
                    suite,
                    args.oracle,
                    args.oracle_sha256,
                    score_revision=args.score_revision,
                ),
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
