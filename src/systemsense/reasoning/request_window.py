"""Parse exact request windows from source-bound observed facts."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import cast


def parse_request_window_facts(
    facts: Mapping[str, object],
) -> tuple[str, str, datetime, datetime] | None:
    """Return the exact target, action, and aware request bounds when complete.

    This parser is shared by advisory schema construction and coordinator
    custody checks. It reads structured persisted facts, never model prose.
    """

    replay = facts.get("loopback_replay")
    if "loopback_replay" in facts and not isinstance(replay, dict):
        return None
    source = cast(Mapping[str, object], replay) if isinstance(replay, dict) else facts
    target = source.get("target_handle")
    action = source.get("action")
    started = source.get("request_started_at_utc", source.get("request_started_at"))
    finished = source.get("request_finished_at_utc", source.get("request_finished_at"))
    if (
        not isinstance(target, str)
        or not isinstance(action, str)
        or not isinstance(started, str)
        or not isinstance(finished, str)
    ):
        return None
    try:
        begin = datetime.fromisoformat(started)
        end = datetime.fromisoformat(finished)
    except ValueError:
        return None
    if begin.utcoffset() is None or end.utcoffset() is None or end < begin:
        return None
    return target, action, begin, end
