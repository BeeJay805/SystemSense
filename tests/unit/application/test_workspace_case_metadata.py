from datetime import UTC, datetime
from pathlib import Path

from systemsense.application.case_service import CaseService
from systemsense.application.workspace import EvidenceWorkspace
from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindowBasis
from systemsense.domain.ids import CaseId
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.storage.sqlite_store import SQLiteStore


def test_workspace_loads_persisted_case_metadata_without_rederiving_window(
    tmp_path: Path,
) -> None:
    case_id = CaseId.new()
    created_at = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    window_start = datetime(2026, 7, 30, 11, 59, tzinfo=UTC)
    window_end = datetime(2026, 7, 30, 12, 1, tzinfo=UTC)

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        store.create_case(
            case_id=str(case_id),
            kind=CaseKind.NETWORK.value,
            symptom="DNS intermittently fails",
            created_at=created_at.isoformat(),
            status=CaseStatus.COMPLETE.value,
            state_version=7,
            time_window_start=window_start.isoformat(),
            time_window_end=window_end.isoformat(),
            time_window_basis=CaseTimeWindowBasis.USER_REPORTED.value,
        )
        workspace = EvidenceWorkspace(
            store=store,
            case_service=CaseService(
                store,
                DeterministicPlanner(candidates=(), minimum_value=0.0),
            ),
        )

        loaded = workspace.get_case(case_id)

    assert loaded.status is CaseStatus.COMPLETE
    assert loaded.state_version == 7
    assert loaded.time_window.start == window_start
    assert loaded.time_window.end == window_end
    assert loaded.time_window.basis is CaseTimeWindowBasis.USER_REPORTED
