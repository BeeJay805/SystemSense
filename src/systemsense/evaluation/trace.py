"""Compare measured episode summaries with the persisted coordinator journal."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import cast

from systemsense.evaluation.models import EpisodeArtifact, ProviderMeasurement
from systemsense.storage.runtime_trace import export_coordinator_event_log
from systemsense.storage.sqlite_store import SQLiteStore


def verify_episode_trace(store: SQLiteStore, episode: EpisodeArtifact) -> dict[str, object]:
    """Return the bounded event log only when it agrees with durable case records."""

    case_id = str(episode.case_id)
    with store.read_snapshot():
        result = export_coordinator_event_log(store, case_id)
        verify_episode_event_projection(result, episode)
        events = cast(list[dict[str, object]], result["events"])
        probes = [event for event in events if event["kind"] == "probe"]
        evidence = [event for event in events if event["kind"] == "evidence"]
        coverage = [event for event in events if event["kind"] == "coverage"]
        db_counts = store.connection.execute(
            "SELECT "
            "(SELECT COUNT(*) FROM probe_executions WHERE case_id = ?), "
            "(SELECT COUNT(*) FROM evidence WHERE case_id = ? "
            " AND json_type(record_json, '$.status') IS NULL), "
            "(SELECT COUNT(*) FROM evidence WHERE case_id = ? "
            " AND json_type(record_json, '$.status') IS NOT NULL "
            " AND json_type(record_json, '$.category') IS NOT NULL)",
            (case_id, case_id, case_id),
        ).fetchone()
        if db_counts is None or tuple(int(value) for value in db_counts) != (
            len(probes),
            len(evidence),
            len(coverage),
        ):
            raise ValueError("coordinator trace does not match episode or stored rows")
        return result


def verify_episode_event_projection(result: dict[str, object], episode: EpisodeArtifact) -> None:
    """Check a typed event projection against its caller-held episode summary.

    This does not verify source rows. The DB-backed verifier above must run
    before custody; readback can reuse this check after raw-row retention.
    """

    if result.get("schema_version") != 1 or result.get("case_id") != str(episode.case_id):
        raise ValueError("coordinator trace does not match episode")
    raw_events = result.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise ValueError("coordinator trace does not match episode")
    events = cast(list[dict[str, object]], raw_events)
    previous_stamp: datetime | None = None
    for sequence, event in enumerate(events, start=1):
        stamp = datetime.fromisoformat(str(event["observed_at"]))
        if (
            event["event_id"] != f"trace_{sequence:06d}"
            or stamp.utcoffset() != timedelta(0)
            or (previous_stamp is not None and stamp < previous_stamp)
        ):
            raise ValueError("coordinator trace does not match episode")
        previous_stamp = stamp
    probes = [event for event in events if event["kind"] == "probe"]
    evidence = [event for event in events if event["kind"] == "evidence"]
    coverage = [event for event in events if event["kind"] == "coverage"]
    providers = [event for event in events if event["kind"] == "provider"]
    terminal = events[-1]
    statuses = Counter(str(event["status"]) for event in probes)
    expected_statuses = {
        status.value: count for status, count in episode.probe_status_counts.items() if count
    }
    if (
        terminal["kind"] != "terminal"
        or sum(event["kind"] == "terminal" for event in events) != 1
        or Counter(str(event["probe_id"]) for event in probes)
        != Counter(episode.attempted_probe_ids)
        or dict(statuses) != expected_statuses
        or len(probes) != episode.probe_attempts.total
        or sum(event["status"] != "ok" for event in probes) != episode.probe_attempts.failures
        or len(evidence) != episode.evidence_count
        or len(coverage) != episode.coverage_count
        or terminal["status"] != episode.terminal_status.value
        or terminal["outcome"] != episode.terminal_outcome.value
        or any(
            not episode.started_at
            <= datetime.fromisoformat(str(event["observed_at"]))
            <= episode.finished_at
            for event in events
        )
    ):
        raise ValueError("coordinator trace does not match episode")
    for measurement in (episode.decision, episode.reasoning):
        _check_provider(providers, measurement)


def _check_provider(events: list[dict[str, object]], measurement: ProviderMeasurement) -> None:
    actual = [event for event in events if event["role"] == measurement.role]
    effective = next(
        (
            str(event["effective_provider_id"])
            for event in reversed(actual)
            if event["effective_provider_id"] is not None
        ),
        None,
    )
    if (
        len(actual) != measurement.calls
        or sum(event["failed"] is True for event in actual) != measurement.failures
        or any(event["attempted_provider_id"] != measurement.provider_id for event in actual)
        or effective != measurement.effective_provider_id
    ):
        raise ValueError("coordinator trace does not match episode provider calls")
