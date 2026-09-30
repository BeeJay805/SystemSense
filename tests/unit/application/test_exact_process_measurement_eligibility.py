"""Draft unit coverage for exact-name pressure eligibility, not diagnosis quality.

These tests use existing synthetic persisted process inventories. No host,
model, or process fixture is executed.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application.investigator import (
    _baseline_probe_ids,  # pyright: ignore[reportPrivateUsage]
    _prioritize_literal_process_needs,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.runtime import PersistedProbeResult
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.time import utc_now
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_investigator_pdf_target import (
    _precollected_pdf_investigator,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.parametrize(
    "objective",
    (
        "Is viewer.exe monopolizing a core?",
        "viewer.exe seems to be hogging system resources",
        "What is going on with viewer.exe?",
    ),
)
def test_exact_executable_seeds_inventory_without_cpu_keyword(objective: str) -> None:
    available = frozenset(
        {"application.snapshot", "core.resources", "core.system", "storage.snapshot"}
    )

    seeded = _baseline_probe_ids(objective, available)

    assert seeded[0] == "application.snapshot"
    assert "core.resources" not in seeded
    assert "storage.snapshot" not in seeded


def test_arbitrary_exact_process_wording_exposes_only_the_matching_identity_pressure(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "exact-process.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id)).model_copy(
            update={"objective": "Is viewer.exe monopolizing a core?"}
        )
        investigator.repository.save(
            state,
            expected_version=state.state_version,
            event="test_objective",
            detail="Natural-language wording eligibility fixture.",
        )
        target = ProcessTargetRepository(store)
        binding = target.bind_exact_process_name(case_id, "viewer.exe")
        current = investigator.repository.load(str(case_id))

        capabilities = {
            item.probe_id: item
            for item in investigator._case_capabilities(current)  # pyright: ignore[reportPrivateUsage]
        }

        pressure = capabilities["application.target_pressure"]
        assert pressure.target_handles == (binding.candidate_id,)
        assert pressure.observable_ids == ("application.target_pressure",)
        assert investigator._bound_target_proposal(current) is None  # pyright: ignore[reportPrivateUsage]


def test_present_activity_question_offers_only_the_scoped_process_measurements(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "current-activity.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        ProcessTargetRepository(store).bind_exact_process_name(case_id, "viewer.exe")
        state = investigator.repository.load(str(case_id)).model_copy(
            update={
                "objective": (
                    "viewer.exe has been lagging. What can you verify about "
                    "its current activity, and what remains unknown?"
                )
            }
        )
        capabilities = {
            item.probe_id
            for item in investigator._case_capabilities(state)  # pyright: ignore[reportPrivateUsage]
        }

        assert "application.target_pressure" in capabilities
        assert "storage.snapshot" not in capabilities
        assert "pressure.sample" not in capabilities
        assert "gpu.telemetry.sample" not in capabilities


def test_exact_name_mismatch_does_not_expose_another_process_identity(
    tmp_path: Path,
) -> None:
    at = utc_now() - timedelta(seconds=2)
    processes: list[dict[str, JsonValue]] = [
        {
            "pid": pid,
            "ppid": 1,
            "name": name,
            "creation_time": (at - timedelta(minutes=index + 1)).isoformat(),
            "identity": f"{pid}@{(at - timedelta(minutes=index + 1)).isoformat()}",
        }
        for index, (pid, name) in enumerate(((4242, "viewer.exe"), (5252, "helper.exe")))
    ]
    with SQLiteStore(tmp_path / "mismatched-target.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store, processes=processes)
        state = investigator.repository.load(str(case_id)).model_copy(
            update={"objective": "What is viewer.exe doing?"}
        )
        investigator.repository.save(
            state,
            expected_version=state.state_version,
            event="test_objective",
            detail="Mismatched stored target fixture.",
        )
        ProcessTargetRepository(store).bind_exact_process_name(case_id, "helper.exe")
        current = investigator.repository.load(str(case_id))

        assert "application.target_pressure" not in {
            item.probe_id
            for item in investigator._case_capabilities(current)  # pyright: ignore[reportPrivateUsage]
        }


def test_present_time_liveness_keeps_pressure_and_unrelated_resources_out(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "liveness-only.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        target = ProcessTargetRepository(store)
        target.bind_exact_process_name(case_id, "viewer.exe")
        state = investigator.repository.load(str(case_id)).model_copy(
            update={"objective": "Is viewer.exe running right now?"}
        )
        capabilities = {
            item.probe_id
            for item in investigator._case_capabilities(state)  # pyright: ignore[reportPrivateUsage]
        }

        assert {"application.snapshot", "incident.events", "core.system"} <= capabilities
        assert (
            not {
                "application.target_pressure",
                "core.resources",
                "pressure.sample",
                "storage.snapshot",
            }
            & capabilities
        )


@pytest.mark.parametrize("process_names", [("helper.exe",), ("viewer.exe", "viewer.exe")])
def test_missing_or_ambiguous_exact_name_cannot_authorize_pressure_binding(
    tmp_path: Path, process_names: tuple[str, ...]
) -> None:
    at = utc_now() - timedelta(seconds=2)
    processes: list[dict[str, JsonValue]] = [
        {
            "pid": 6000 + index,
            "ppid": 1,
            "name": name,
            "creation_time": (at - timedelta(minutes=index + 1)).isoformat(),
            "identity": f"{6000 + index}@{(at - timedelta(minutes=index + 1)).isoformat()}",
        }
        for index, name in enumerate(process_names)
    ]
    with SQLiteStore(tmp_path / "unresolved-target.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store, processes=processes)
        state = investigator.repository.load(str(case_id)).model_copy(
            update={"objective": "Is viewer.exe monopolizing a core?"}
        )
        investigator.repository.save(
            state,
            expected_version=state.state_version,
            event="test_objective",
            detail="Missing or ambiguous inventory fixture.",
        )

        with pytest.raises(TargetSelectionError, match="absent or ambiguous"):
            ProcessTargetRepository(store).bind_exact_process_name(case_id, "viewer.exe")
        current = investigator.repository.load(str(case_id))
        assert "application.target_pressure" not in {
            item.probe_id
            for item in investigator._case_capabilities(current)  # pyright: ignore[reportPrivateUsage]
        }


def test_mixed_cpu_disk_query_preserves_existing_storage_capabilities(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "mixed-cpu-disk.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id)).model_copy(
            update={"objective": "Is viewer.exe using CPU and disk I/O?"}
        )
        investigator.repository.save(
            state,
            expected_version=state.state_version,
            event="test_objective",
            detail="Mixed target resource question fixture.",
        )
        ProcessTargetRepository(store).bind_exact_process_name(case_id, "viewer.exe")
        current = investigator.repository.load(str(case_id))
        capabilities = {
            item.probe_id
            for item in investigator._case_capabilities(current)  # pyright: ignore[reportPrivateUsage]
        }

        assert "application.target_pressure" in capabilities
        assert "core.resources" in capabilities
        assert "storage.snapshot" in capabilities


def test_existing_manual_pdf_selection_seed_is_unchanged() -> None:
    available = frozenset({"application.snapshot", "core.resources", "core.system"})

    seeded = _baseline_probe_ids("This PDF viewer is slow", available)

    assert seeded == ("application.snapshot", "core.resources", "core.system")


def test_mixed_frontier_catalog_limits_exact_name_to_one_revalidated_candidate(
    tmp_path: Path,
) -> None:
    at = utc_now() - timedelta(seconds=2)
    processes: list[dict[str, JsonValue]] = []
    for index, (pid, name) in enumerate(((4242, "viewer.exe"), (5252, "helper.exe"))):
        created = at - timedelta(minutes=index + 1)
        processes.append(
            {
                "pid": pid,
                "ppid": 1,
                "name": name,
                "creation_time": created.isoformat(),
                "identity": f"{pid}@{created.isoformat()}",
            }
        )
    with SQLiteStore(tmp_path / "mixed-frontier-exact-process.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store, processes=processes)
        state = investigator.repository.load(str(case_id)).model_copy(
            update={"objective": "Why did viewer.exe stop?"}
        )
        state = investigator.repository.save(
            state,
            expected_version=state.state_version,
            event="test_objective",
            detail="Exact-name source-bound mixed-frontier fixture.",
        )
        deadline = (utc_now() + timedelta(minutes=2)).isoformat()
        store.connection.execute(
            "UPDATE cases SET status='collecting', state_version=? WHERE case_id=?",
            (state.state_version, str(case_id)),
        )
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
            (
                json.dumps(
                    {
                        "case_id": str(case_id),
                        "state_version": state.state_version,
                        "status": "running",
                        "deadline_at": deadline,
                        "budget_ms": 60_000,
                        "spent_cost_ms": 0,
                        "max_probes": 6,
                        "completed_probe_ids": ["application.snapshot"],
                        "pending_probe_ids": [],
                        "interrupted_probe_ids": [],
                        "unrecorded_attempt_count": 0,
                    }
                ),
                str(case_id),
            ),
        )
        row = store.connection.execute(
            "SELECT execution_id FROM evidence WHERE case_id=? "
            "AND json_extract(record_json, '$.collector.id')='application.snapshot'",
            (str(case_id),),
        ).fetchone()
        assert row is not None
        execution_id = ExecutionId(root=str(row[0]))
        parent = PersistedProbeResult(
            task_id="synthetic-parent",
            case_id=str(case_id),
            epoch_state_version=state.state_version,
            probe_id="application.snapshot",
            execution_id=execution_id,
            evidence_generation=0,
            trigger_evidence_sha256=FollowupAdmissionRepository(store).parent_evidence_digest(
                str(case_id), str(execution_id)
            ),
        )

        registry, all_needs = investigator._streaming_candidate_catalog(  # pyright: ignore[reportPrivateUsage]
            state, parent, store, None, None
        )
        eligible = _prioritize_literal_process_needs(store, case_id, state.objective, all_needs)

        assert registry is not None
        target = ProcessTargetRepository(store).list_process_candidates(case_id)
        viewer = next(item for item in target.candidates if item.name == "viewer.exe")
        helper = next(item for item in target.candidates if item.name == "helper.exe")
        pressure_needs = tuple(
            item for item in eligible if item.capability_id == "application.target_pressure"
        )
        assert tuple(item.target_handle for item in pressure_needs) == (viewer.candidate_id,)
        assert helper.candidate_id not in {item.target_handle for item in pressure_needs}
        assert investigator._bound_target_proposal(state) is None  # pyright: ignore[reportPrivateUsage]

        candidate = registry.issue(case_id, state.state_version, pressure_needs[0])
        assert not isinstance(candidate, CandidateGap)
        resolved = registry.resolve(case_id, state.state_version, candidate.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        assert resolved.invocation.target_handle == viewer.candidate_id
        assert resolved.invocation.parameters["pid"] == viewer.pid
        assert (
            datetime.fromisoformat(str(resolved.invocation.parameters["creation_time"]))
            == viewer.creation_time
        )
        case_capabilities = {
            item.probe_id
            for item in investigator._case_capabilities(state)  # pyright: ignore[reportPrivateUsage]
        }
        assert not {"core.resources", "pressure.sample", "storage.snapshot"} & case_capabilities


def test_exact_name_pdf_query_keeps_existing_manual_pdf_selection_path(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "exact-pdf-preserves-manual-selection.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id)).model_copy(
            update={"objective": "Why is viewer.exe PDF rendering slow?"}
        )
        investigator.repository.save(
            state,
            expected_version=state.state_version,
            event="test_objective",
            detail="Exact executable with the existing manual PDF-selection intent.",
        )

        result = investigator.run(str(case_id))

        assert result.status.value == "awaiting_target"
        assert ProcessTargetRepository(store).selected_process_target(case_id) is None
