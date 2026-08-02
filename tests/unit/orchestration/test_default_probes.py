from datetime import UTC, datetime
from pathlib import Path

import pytest

from systemsense.application.case_service import CaseService
from systemsense.domain.cases import CaseKind
from systemsense.mcp_server import default_planner
from systemsense.orchestration.planner import CasePlanningRequest
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.sqlite_store import SQLiteStore
from systemsense.worker import REGISTERED_PROBE_IDS

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_default_planner_selects_only_registered_runtime_probes() -> None:
    runner = default_probe_runner()
    plan = default_planner().plan(
        CasePlanningRequest(
            symptom="application audio device network update cuda python",
            target_traits=frozenset({"application", "device"}),
            fresh_probe_ids=frozenset(),
            budget_ms=60_000,
            max_probes=32,
        )
    )

    assert set(plan.probe_ids) <= runner.probe_ids
    assert runner.isolated_probe_ids <= REGISTERED_PROBE_IDS
    assert runner.isolated_probe_ids == {
        "devices.snapshot",
        "servicing.snapshot",
        "local_ai.snapshot",
    }


def test_default_planner_infers_network_probe_from_socket_error_without_target_traits() -> None:
    plan = default_planner().plan(
        CasePlanningRequest(
            symptom=(
                "My local development app stopped starting after I resumed the PC. "
                "It prints a Windows socket address-in-use error and exits."
            ),
            target_traits=frozenset(),
            fresh_probe_ids=frozenset(),
            budget_ms=5000,
            max_probes=16,
        )
    )

    assert "application.snapshot" in plan.probe_ids
    assert "network.snapshot" in plan.probe_ids


@pytest.mark.parametrize(
    ("kind", "expected_probe"),
    (
        (CaseKind.APPLICATION, "application.snapshot"),
        (CaseKind.DEVICES_AUDIO, "devices.snapshot"),
        (CaseKind.NETWORK, "network.snapshot"),
        (CaseKind.SERVICING, "servicing.snapshot"),
        (CaseKind.LOCAL_AI, "local_ai.snapshot"),
    ),
)
def test_case_kind_selects_its_probe_without_traits_or_keyword_help(
    tmp_path: Path,
    kind: CaseKind,
    expected_probe: str,
) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        opened = CaseService(store, default_planner()).open_case(
            kind=kind,
            symptom="Something is not working correctly.",
            target_traits=frozenset(),
            created_at=_NOW,
            budget_ms=5_000,
            max_probes=16,
        )

    assert expected_probe in opened.plan.probe_ids
