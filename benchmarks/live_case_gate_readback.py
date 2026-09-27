"""Read a saved live case without promoting model advice to diagnostic truth.

The output contains aggregate counts only. A case export and deep mailbox do
not contain an independent cause oracle or a verified affected-task result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from systemsense.reasoning.contracts import EvidenceDetailRequest

type MailboxRow = tuple[str, dict[str, Any], dict[str, Any]]


def _detail_key(item: object) -> str:
    return EvidenceDetailRequest.model_validate(item).key()


def review_live_case(report: Mapping[str, Any], rows: Sequence[MailboxRow]) -> dict[str, object]:
    """Account for applied advice and still-unknown outcomes in one saved case."""
    case_id = report.get("case_id")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("case export has no case identity")
    statuses = Counter[str]()
    applied = 0
    valid_citations = 0
    invalid_citations = 0
    eligible_details: set[str] = set()
    all_response_details: set[str] = set()
    for status, task, result in rows:
        if status not in {"applied", "rejected", "cancelled", "failed", "interrupted", "running"}:
            raise ValueError("unknown mailbox status")
        request = cast(dict[str, Any], task.get("request") or {})
        if request.get("case_id") != case_id:
            raise ValueError("mailbox case mismatch")
        statuses[status] += 1
        if status != "applied":
            continue
        response = cast(dict[str, Any], result.get("response") or {})
        if not response or response.get("degraded") is not False:
            continue
        applied += 1
        visible = {
            str(item["evidence_id"])
            for item in cast(list[dict[str, object]], request.get("evidence_context") or [])
        }
        considered = {
            str(item) for item in cast(list[object], response.get("considered_evidence_ids") or [])
        }
        for hypothesis in cast(list[dict[str, object]], response.get("hypotheses") or []):
            for field in ("supporting_evidence_ids", "contradicting_evidence_ids"):
                for evidence_id in cast(list[object], hypothesis.get(field) or []):
                    if str(evidence_id) in visible & considered:
                        valid_citations += 1
                    else:
                        invalid_citations += 1
        for item in cast(list[dict[str, object]], response.get("requested_details") or []):
            key = _detail_key(item)
            all_response_details.add(key)
            if str(item["evidence_id"]) in visible & considered:
                eligible_details.add(key)

    pending = {
        _detail_key(item) for item in cast(list[object], report.get("requested_details") or [])
    }
    completed = {
        _detail_key(item)
        for item in cast(list[object], report.get("completed_detail_requests") or [])
    }
    reported = cast(dict[str, Any], report.get("reported_task") or {})
    browser_task = reported.get("kind") == "browser_navigation"
    browser_target_present = bool(reported.get("target_hint"))
    expected_outcome_present = bool(reported.get("expected_outcome"))
    if browser_task and (not browser_target_present or not expected_outcome_present):
        first_gate = "affected_browser_task_unbound"
    elif reported.get("verification") == "unverified":
        first_gate = "affected_task_outcome_unverified"
    else:
        first_gate = "independent_cause_oracle_unavailable"
    return {
        "schema_version": 1,
        "mailbox_status_counts": dict(sorted(statuses.items())),
        "applied_deep_results": applied,
        "valid_visible_citations": valid_citations,
        "invalid_visible_citations": invalid_citations,
        "deep_detail_requests": len(all_response_details),
        "pending_detail_requests": len(pending),
        "completed_detail_requests": len(completed),
        "unaccounted_eligible_detail_requests": len(eligible_details - pending - completed),
        "completed_probe_count": len(set(report.get("completed_probe_ids") or [])),
        "assessment_present": report.get("assessment") is not None,
        "reported_task_unverified": reported.get("verification") == "unverified",
        "browser_target_hint_present": browser_target_present,
        "expected_outcome_present": expected_outcome_present,
        "first_evidence_gate": first_gate,
        "unknown_cause_opportunities": applied,
        "independently_supported_causes": None,
        "independently_wrong_causes": None,
        "label_basis": "no_independent_cause_oracle_in_case_export",
    }


def review_live_case_files(case_json: Path, database: Path) -> dict[str, object]:
    """Read one private export and its case DB; never echo their raw contents."""
    report = cast(dict[str, Any], json.loads(case_json.read_text(encoding="utf-8")))
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        rows: list[MailboxRow] = []
        for status, task, result in connection.execute(
            "SELECT status, task_json, result_json FROM deep_mailbox ORDER BY created_at"
        ):
            rows.append(
                (
                    cast(str, status),
                    cast(dict[str, Any], json.loads(cast(str, task))),
                    cast(dict[str, Any], json.loads(cast(str, result))) if result else {},
                )
            )
    finally:
        connection.close()
    review = review_live_case(report, rows)
    review["case_export_sha256"] = hashlib.sha256(case_json.read_bytes()).hexdigest()
    review["database_sha256"] = hashlib.sha256(database.read_bytes()).hexdigest()
    return review


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-json", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    review = review_live_case_files(args.case_json, args.database)
    args.output.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"aggregate_sha256={hashlib.sha256(args.output.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
