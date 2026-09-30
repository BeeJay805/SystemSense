"""A live PID and a summary label are insufficient listener ownership proof."""

from copy import deepcopy
from datetime import UTC, datetime
from typing import cast

import pytest

from systemsense.application.loopback_replay_evidence import ownership_verified_at_boundaries
from systemsense.domain.ids import JsonValue


def test_ownership_requires_exact_identity_and_ordered_boundary_checks() -> None:
    creation = datetime(2026, 1, 1, tzinfo=UTC)
    facts: dict[str, JsonValue] = {
        "loopback_replay": {
            "request_started_at": "2026-01-01T00:00:02+00:00",
            "request_finished_at": "2026-01-01T00:00:03+00:00",
        },
        "listener_ownership": {
            "schema_version": 1,
            "status": "verified_at_boundaries",
            "target_pid": 123,
            "target_creation_time": creation.isoformat(),
            "target_handle": "127.0.0.1:59152",
            "before_replay": {
                "status": "verified",
                "query_started_at": "2026-01-01T00:00:01+00:00",
                "observed_at": "2026-01-01T00:00:02+00:00",
            },
            "after_replay": {
                "status": "verified",
                "query_started_at": "2026-01-01T00:00:03+00:00",
                "observed_at": "2026-01-01T00:00:04+00:00",
            },
        },
    }

    def accepted(value: dict[str, JsonValue]) -> bool:
        return ownership_verified_at_boundaries(value, pid=123, creation_time=creation, port=59152)

    assert accepted(facts)
    assert not accepted({})
    for name, value in (
        ("target_pid", 456),
        ("target_handle", "127.0.0.1:59153"),
        ("target_creation_time", "2026-01-01T00:00:01+00:00"),
        ("status", "unverified"),
    ):
        changed = deepcopy(facts)
        cast("dict[str, JsonValue]", changed["listener_ownership"])[name] = value
        assert not accepted(changed)
    for name in ("before_replay", "after_replay"):
        changed = deepcopy(facts)
        ownership = cast("dict[str, JsonValue]", changed["listener_ownership"])
        boundary = cast("dict[str, JsonValue]", ownership[name])
        boundary["status"] = "not_owned"
        assert not accepted(changed)
        boundary["status"] = "verified"
        boundary["query_started_at"] = "2026-01-01T00:00:05+00:00"
        assert not accepted(changed)


@pytest.mark.parametrize("port", [80, 49151, 65536, True])
def test_replay_rejects_broader_endpoint_before_access(port: int) -> None:
    from systemsense.platform.windows.loopback_replay import collect_loopback_replay

    with pytest.raises(ValueError):
        collect_loopback_replay({"port": port, "nonce": "a" * 32})
