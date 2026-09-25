"""Read-only stage timing for a persisted mixed-frontier local investigation.

This report uses durable wall-clock timestamps, not an inference profiler. It
never turns an admitted-only sample into an all-attempt p95 or infers that a
configured model actually ran from its name. Keep raw case facts in the DB.
"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote


def _elapsed_ms(start: str | None, end: str | None) -> float | None:
    if start is None or end is None:
        return None
    earlier = datetime.fromisoformat(start)
    later = datetime.fromisoformat(end)
    elapsed = (later - earlier).total_seconds() * 1000
    return round(elapsed, 3) if elapsed >= 0 else None


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    offset = (len(ordered) - 1) * fraction
    low = math.floor(offset)
    high = math.ceil(offset)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (offset - low), 3)


def _summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "min_ms": min(values) if values else None,
        "p50_ms": _percentile(values, 0.5),
        "p95_ms": _percentile(values, 0.95),
        "max_ms": max(values) if values else None,
    }


def trace_case(database: Path, case_id: str) -> dict[str, Any]:
    """Summarize exact durable stages without opening the store for writes."""

    if not database.is_file() or not case_id.startswith("case_"):
        raise ValueError("an existing case database and case ID are required")
    uri = "file:" + quote(database.resolve().as_posix(), safe="/:") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        snapshots = connection.execute(
            "SELECT snapshot_id,request_frozen_at,captured_at,request_json,response_json "
            "FROM candidate_decision_snapshots WHERE case_id=? "
            "ORDER BY request_frozen_at,snapshot_id",
            (case_id,),
        ).fetchall()
        rankings: list[dict[str, object]] = []
        for snapshot in snapshots:
            request = json.loads(str(snapshot["request_json"]))
            response = json.loads(str(snapshot["response_json"]))
            rankings.append(
                {
                    "snapshot_id": str(snapshot["snapshot_id"]),
                    "provider_id": request["provider"]["provider_id"],
                    "model_weight_sha256": request["model_weight_sha256"],
                    "ranking_source": response["ranking_source"],
                    "degraded_reason": response["degraded_reason"],
                    "attention_notes": response.get("attention_notes", []),
                    "considered_item_ids": response.get("considered_item_ids", []),
                    "candidate_kinds": [item["reference"]["kind"] for item in request["items"]],
                    "packet_count": len(request["evidence_packets"]),
                    "frozen_to_snapshot_ms": _elapsed_ms(
                        str(snapshot["request_frozen_at"]), str(snapshot["captured_at"])
                    ),
                }
            )
        admitted = connection.execute(
            "SELECT a.admission_id,a.snapshot_id,a.candidate_id,a.admitted_at,"
            "p.trigger_execution_id,c.claimed_at,l.execution_id,x.started_at,x.finished_at,"
            "x.status AS execution_status "
            "FROM candidate_dispatch_admissions AS a "
            "LEFT JOIN candidate_followup_parents AS p ON p.admission_id=a.admission_id "
            "LEFT JOIN candidate_dispatch_claims AS c ON c.admission_id=a.admission_id "
            "LEFT JOIN candidate_decision_execution_links AS l "
            "ON l.snapshot_id=a.snapshot_id AND l.candidate_id=a.candidate_id "
            "LEFT JOIN probe_executions AS x ON x.execution_id=l.execution_id "
            "WHERE a.case_id=? ORDER BY a.admitted_at,a.admission_id",
            (case_id,),
        ).fetchall()
        measurements: list[dict[str, object]] = []
        admitted_latencies: list[float] = []
        for row in admitted:
            parent_id = row["trigger_execution_id"]
            persisted = None
            if parent_id is not None:
                source = connection.execute(
                    "SELECT MIN(t.persisted_at) FROM coordinator_events AS t "
                    "JOIN evidence AS e ON e.evidence_id=t.source_record_id "
                    "WHERE e.case_id=? AND e.execution_id=? AND t.kind='evidence'",
                    (case_id, str(parent_id)),
                ).fetchone()
                persisted = None if source is None or source[0] is None else str(source[0])
            admitted_at = str(row["admitted_at"])
            latency = _elapsed_ms(persisted, admitted_at)
            if latency is not None:
                admitted_latencies.append(latency)
            measurements.append(
                {
                    "admission_id": str(row["admission_id"]),
                    "snapshot_id": str(row["snapshot_id"]),
                    "candidate_id": str(row["candidate_id"]),
                    "source_persisted_at": persisted,
                    "admitted_at": admitted_at,
                    "claimed_at": row["claimed_at"],
                    "execution_id": row["execution_id"],
                    "execution_status": row["execution_status"],
                    "persisted_to_admitted_ms": latency,
                    "admitted_to_claimed_ms": _elapsed_ms(
                        admitted_at,
                        None if row["claimed_at"] is None else str(row["claimed_at"]),
                    ),
                    "claimed_to_probe_start_ms": _elapsed_ms(
                        None if row["claimed_at"] is None else str(row["claimed_at"]),
                        None if row["started_at"] is None else str(row["started_at"]),
                    ),
                    "probe_elapsed_ms": _elapsed_ms(
                        None if row["started_at"] is None else str(row["started_at"]),
                        None if row["finished_at"] is None else str(row["finished_at"]),
                    ),
                }
            )
        deep: list[dict[str, object]] = []
        for row in connection.execute(
            "SELECT request_sha256,status,reason,created_at,updated_at,result_json "
            "FROM deep_mailbox WHERE case_id=? ORDER BY created_at,request_sha256",
            (case_id,),
        ):
            result = None if row["result_json"] is None else json.loads(str(row["result_json"]))
            response = None if result is None else result.get("response")
            deep.append(
                {
                    "request_sha256": str(row["request_sha256"]),
                    "status": str(row["status"]),
                    "reason": str(row["reason"]),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                    "created_to_terminal_ms": _elapsed_ms(
                        str(row["created_at"]), str(row["updated_at"])
                    ),
                    "worker_started_at": None if result is None else result.get("started_at"),
                    "worker_finished_at": None if result is None else result.get("finished_at"),
                    "worker_elapsed_ms": None if result is None else result.get("elapsed_ms"),
                    "provider_identity": (
                        None if result is None else result.get("provider_identity")
                    ),
                    "response_provider": None if response is None else response.get("provider"),
                    "response_degraded": None if response is None else response.get("degraded"),
                    "failure_kind": None if result is None else result.get("failure_kind"),
                }
            )
        evidence_events = connection.execute(
            "SELECT COUNT(*) FROM coordinator_events WHERE case_id=? AND kind='evidence'",
            (case_id,),
        ).fetchone()
        provider_events = [
            {
                "persisted_at": str(row["persisted_at"]),
                **json.loads(str(row["event_json"])),
            }
            for row in connection.execute(
                "SELECT persisted_at,event_json FROM coordinator_events "
                "WHERE case_id=? AND kind='provider' ORDER BY sequence",
                (case_id,),
            )
        ]
    return {
        "schema_version": 1,
        "case_id": case_id,
        "evidence_events": 0 if evidence_events is None else int(evidence_events[0]),
        "rankings": rankings,
        "provider_events": provider_events,
        "measurements": measurements,
        "admitted_only_persisted_to_admitted": _summary(admitted_latencies),
        "all_attempt_p95_ms": None,
        "deep": deep,
        "limitations": [
            "Durable wall-clock stages omit model queue/inference phase boundaries.",
            "The eligible event denominator is not persisted here; admitted-only p95 "
            "is not the target p95.",
            "A configured model ID or laya ranking_source alone does not prove "
            "exact worker/model execution.",
            "This trace contains no independent diagnostic oracle or repair outcome.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("case_id")
    args = parser.parse_args()
    print(json.dumps(trace_case(args.database, args.case_id), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
