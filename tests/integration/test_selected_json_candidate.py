"""Real captured-file checks through frozen candidate admission, without models."""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_case_runtime, default_investigator
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.local_json_task import (
    observe_selected_json_task,
    selected_json_definitions,
)
from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
)
from systemsense.decision.contracts import DiagnosticPurpose, ProbeProposal, ProviderIdentity
from systemsense.domain.time import utc_now
from systemsense.orchestration.scheduler import TaskStatus
from systemsense.platform.windows.selected_file import capture_selected_file
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

pytestmark = pytest.mark.skipif(os.name != "nt", reason="real Windows selected-file capture")


def test_streaming_review_uses_the_worker_database_connection(tmp_path: Path) -> None:
    path = tmp_path / "owned.json"
    path.write_bytes(b"{}")
    capture = capture_selected_file(str(path))
    database = tmp_path / "threaded.db"
    with SQLiteStore(database) as store:
        owner = default_investigator(store)
        state = owner.create(objective="Check selected capture")
        observe_selected_json_task(store, case_id=state.case_id, capture=capture)
        state = InvestigationRepository(store).load(str(state.case_id))

        def review() -> bool:
            with SQLiteStore(database) as worker_store:
                reader = default_investigator(worker_store)
                return owner._offer_deep_during_collection(  # pyright: ignore[reportPrivateUsage]
                    state, observation_reader=reader
                )

        with ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(review).result(timeout=5) is False


@pytest.mark.parametrize("probe_id", ["file.utf8", "file.json_syntax"])
def test_registered_file_candidate_claims_and_executes_once(tmp_path: Path, probe_id: str) -> None:
    path = tmp_path / "owned.json"
    path.write_bytes(b'{"value":}')
    capture = capture_selected_file(str(path))
    with SQLiteStore(tmp_path / "case.db") as store:
        app = default_investigator(store)
        state = app.create(objective="Check the selected JSON capture")
        observe_selected_json_task(store, case_id=state.case_id, capture=capture)
        repository = InvestigationRepository(store)
        state = repository.load(str(state.case_id))
        state = repository.save(
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            expected_version=state.state_version,
            event="started",
            detail="Synthetic decision over a real captured file.",
        )
        runtime = default_case_runtime(
            store, case_probe_definitions=selected_json_definitions(capture)
        )
        registry, needs = runtime.general_candidate_catalog(state.case_id)
        candidates = tuple(
            registry.issue(state.case_id, state.state_version, need) for need in needs
        )
        assert len(candidates) == 2
        assert all(not isinstance(item, CandidateGap) for item in candidates)
        candidate = next(
            item
            for item in candidates
            if not isinstance(item, CandidateGap) and item.probe_id == probe_id
        )
        reference = AdmittedCandidateRefV1(**candidate.model_dump(exclude={"schema_version"}))
        request = CandidateDecisionRequestV1(
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id="synthetic:file-candidate",
            deadline_at=state.deadline_at,
            symptom=state.objective,
            available_candidates=(reference,),
            budget_ms=10000,
            max_candidates=1,
        )
        response = CandidateDecisionResponseV1(
            provider=ProviderIdentity(
                provider_id="synthetic-decision", provider_version="1", role="fast_decision"
            ),
            case_id=state.case_id,
            state_version=state.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            considered_candidate_ids=(candidate.candidate_id,),
            ranked_candidate_ids=(candidate.candidate_id,),
            proposals=(
                CandidateProposalV1(
                    candidate_id=candidate.candidate_id,
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=1,
                ),
            ),
        )
        snapshot = CandidateDecisionSnapshotRepository(store).capture(
            request, response, request_frozen_at=utc_now()
        )
        proposal = ProbeProposal(
            probe_id=probe_id,
            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
            priority=1,
            estimated_cost_ms=candidate.cost_ms,
            resource_class=candidate.resource_class,
            safety_class=candidate.safety_class,
            dedupe_key=f"candidate:{candidate.candidate_id}",
        )
        opened = app._opened(state, (proposal,))  # pyright: ignore[reportPrivateUsage]
        results = runtime.execute_candidate_measurement(
            opened, candidate.candidate_id, snapshot.snapshot_id
        )
        assert isinstance(results, tuple), results
        assert len(results) == 1 and results[0].status is TaskStatus.SUCCEEDED, results
        satisfied = app._satisfied_probe_ids(state)  # pyright: ignore[reportPrivateUsage]
        if probe_id == "file.json_syntax":
            assert {"file.utf8", "file.json_syntax"} <= satisfied
        else:
            # Valid UTF-8 alone does not establish JSON validity.
            assert "file.json_syntax" not in satisfied
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_claims"
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_execution_links"
        ).fetchone() == (1,)
        repeated = runtime.execute_candidate_measurement(
            opened, candidate.candidate_id, snapshot.snapshot_id
        )
        assert not isinstance(repeated, tuple)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_claims"
        ).fetchone() == (1,)
