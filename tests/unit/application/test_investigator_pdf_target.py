"""A PDF investigation waits for an observed process choice before target sampling."""

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.case_service import OpenedCase
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.probes import MeasurementNeed
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContextStatus
from systemsense.orchestration.invocations import ObservabilityGap
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import NoParameters, TargetPressureParametersV1, default_probe_runner
from systemsense.storage.sqlite_store import SQLiteStore


def _application_snapshot(store: SQLiteStore, case_id: CaseId, at: datetime) -> None:
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "application.snapshot", "probe_version": 1}
    )
    created = at - timedelta(minutes=1)
    facts: dict[str, JsonValue] = {
        "collection_started_at": (at - timedelta(seconds=1)).isoformat(),
        "collection_completed_at": at.isoformat(),
        "collection_status": "available",
        "omitted_counts": {"processes": 0, "services": 0, "startup": 0},
        "processes": [
            {
                "pid": 4242,
                "ppid": 1,
                "name": "viewer.exe",
                "creation_time": created.isoformat(),
                "identity": f"4242@{created.isoformat()}",
            }
        ],
    }
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=at,
        captured_at=at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "application.snapshot"},
        ),
        collector=CollectorReference(
            id="application.snapshot", version=1, execution_id=execution_id
        ),
        summary="Application topology",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="application.snapshot",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(at - timedelta(seconds=1)).isoformat(),
            finished_at=at.isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=at.isoformat(),
            captured_at=at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )


def _precollected_pdf_investigator(store: SQLiteStore) -> tuple[Investigator, CaseId]:
    investigator = default_investigator(store)
    state = investigator.create(objective="This PDF viewer is slow")
    _application_snapshot(store, state.case_id, state.created_at)
    investigator.repository.save(
        state.model_copy(update={"completed_probe_ids": ("application.snapshot",)}),
        expected_version=state.state_version,
        event="precollected",
        detail="fixture snapshot",
    )
    return investigator, state.case_id


def test_pdf_run_waits_for_process_selection_and_generic_resume_cannot_bypass(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "pdf-wait.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)

        waiting = investigator.run(str(case_id))

        assert waiting.status is InvestigationStatus.AWAITING_TARGET
        assert waiting.outcome is InvestigationOutcome.AWAITING_TARGET
        assert waiting.completed_probe_ids == ("application.snapshot",)
        assert waiting.assessment is None
        assert not waiting.provider_calls
        with pytest.raises(ValueError, match="target"):
            investigator.resume(str(case_id))
        with pytest.raises(ValueError, match="binding"):
            investigator.resume_after_target(str(case_id))
        inventory = ProcessTargetRepository(store).list_process_candidates(case_id)
        assert len(inventory.candidates) == 1
        ProcessTargetRepository(store).bind_process_target(
            case_id, inventory.candidates[0].candidate_id
        )
        with pytest.raises(ValueError, match="target"):
            investigator.resume(str(case_id))

        queued = investigator.resume_after_target(str(case_id))

        assert queued.status is InvestigationStatus.QUEUED
        assert queued.outcome is InvestigationOutcome.INVESTIGATING
        assert queued.completed_probe_ids == ("application.snapshot",)


def _waiting_with_binding(investigator: Investigator, case_id: CaseId) -> None:
    waiting = investigator.run(str(case_id))
    assert waiting.status is InvestigationStatus.AWAITING_TARGET
    targets = ProcessTargetRepository(investigator.store)
    inventory = targets.list_process_candidates(case_id)
    targets.bind_process_target(case_id, inventory.candidates[0].candidate_id)
    investigator.resume_after_target(str(case_id))


def test_resumed_pdf_samples_only_bound_target_and_failure_is_not_diagnosis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "pdf-failed-probe.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def unavailable(parameters: dict[str, JsonValue]):
            calls.append(parameters)
            raise RuntimeError("counter unavailable")

        monkeypatch.setattr(
            investigator.runtime,
            "_probe_runner",
            ProbeRunner(
                definitions=(
                    ProbeDefinition(
                        manifest=manifest,
                        parameter_model=TargetPressureParametersV1,
                        handler=unavailable,
                        isolated=False,
                    ),
                )
            ),
        )

        finished = investigator.run(str(case_id))

        assert len(calls) == 1
        assert calls[0]["pid"] == 4242
        assert finished.completed_probe_ids == (
            "application.snapshot",
            "application.target_pressure",
        )
        assert not finished.pending_probe_ids
        assert finished.assessment is None
        assert finished.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
        context = investigator.context(str(case_id))
        assert any(
            item.probe_id == "performance.coverage" and item.status is EvidenceContextStatus.FAILED
            for item in context
        ), [(item.probe_id, item.status) for item in context]
        completed_version = finished.state_version
        with pytest.raises(ValueError, match="not awaiting"):
            investigator.resume_after_target(str(case_id))
        assert investigator.repository.load(str(case_id)).state_version == completed_version


def test_pdf_fast_brain_selects_exact_bound_process_measurement(tmp_path: Path) -> None:
    class TargetSelectingDecision:
        identity = ProviderIdentity(
            provider_id="test-target-selection", provider_version="1", role="fast_decision"
        )

        def __init__(self) -> None:
            self.seen: list[DecisionRequest] = []

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.seen.append(request)
            capabilities = [
                item
                for item in request.available_probes
                if item.probe_id == "application.target_pressure"
            ]
            assert len(capabilities) == 1
            capability = capabilities[0]
            assert capability.observable_ids == ("application.target_pressure",)
            assert len(capability.target_handles) == 1
            proposal = ProbeProposal(
                schema_version=2,
                probe_id=capability.probe_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
                estimated_cost_ms=capability.cost_ms,
                resource_class=ResourceClass.PROCESS,
                dedupe_key="bound-pdf:fast",
                measurement_need=MeasurementNeed(
                    capability_id=capability.probe_id,
                    observable=capability.observable_ids[0],
                    target_handle=capability.target_handles[0],
                ),
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(proposal,),
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-fast-route.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one snapshot and one selected process measurement",
        )
        _waiting_with_binding(investigator, case_id)
        decision = TargetSelectingDecision()
        investigator.decision = decision
        selected = ProcessTargetRepository(store).selected_process_target(case_id)
        assert selected is not None
        observed: list[dict[str, JsonValue]] = []
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None

        def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
            observed.append(parameters)
            at = utc_now()
            return ProbeObservation(
                summary="Selected process pressure",
                facts={"pid": parameters["pid"]},
                observed_at=at,
                captured_at=at,
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=collect,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert decision.seen
        assert decision.seen[0].available_probes[-1].target_handles == (selected.candidate_id,)
        assert len(observed) == 1
        assert observed[0]["pid"] == selected.pid
        target_audit = [
            item
            for item in store.audit_entries(case_id=str(case_id))
            if item.probe_id == "application.target_pressure"
        ]
        assert len(target_audit) == 1
        assert target_audit[0].parameters["measurement_invocation_id"]
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM decision_execution_links AS link "
                "JOIN probe_executions AS execution ON execution.execution_id = link.execution_id "
                "WHERE link.case_id = ? AND execution.probe_id = ?",
                (str(case_id), "application.target_pressure"),
            ).fetchone()[0]
            == 1
        )
        assert finished.completed_probe_ids.count("application.target_pressure") == 1


def test_untyped_target_proposal_cannot_execute_and_typed_gap_is_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UntypedDecision:
        identity = ProviderIdentity(
            provider_id="test-untyped-target", provider_version="1", role="fast_decision"
        )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            capability = next(
                item
                for item in request.available_probes
                if item.probe_id == "application.target_pressure"
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key="untyped-model-target",
                    ),
                ),
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-untyped-gap.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2, "max_rounds": 1}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        investigator.decision = UntypedDecision()
        selected = ProcessTargetRepository(store).selected_process_target(case_id)
        assert selected is not None
        routed: list[MeasurementNeed] = []

        def refuse_generic(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("untyped target must not reach generic plan execution")

        def typed_gap(
            opened: OpenedCase, need: MeasurementNeed, **_kwargs: object
        ) -> ObservabilityGap:
            assert opened.plan.probes[0].reason == DiagnosticPurpose.REFRESH_EVIDENCE.value
            routed.append(need)
            return ObservabilityGap(
                need=need, reason="selected process target changed before execution"
            )

        monkeypatch.setattr(investigator.runtime, "execute_plan", refuse_generic)
        monkeypatch.setattr(investigator.runtime, "execute_measurement_need", typed_gap)

        finished = investigator.run(str(case_id))

        assert len(routed) == 1
        assert routed[0].target_handle == selected.candidate_id
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id = ? AND probe_id = ?",
                (str(case_id), "application.target_pressure"),
            ).fetchone()[0]
            == 0
        )
        assert finished.completed_probe_ids.count("application.target_pressure") == 0
        assert len(finished.measurement_gaps) == 1
        assert finished.measurement_gaps[0].need == routed[0]
        assert investigator.repository.load(str(case_id)).schema_version == 5
        assert any("selected process target changed" in warning for warning in finished.warnings)
        assert any(
            step.event == "measurement_gap" for step in investigator.repository.steps(str(case_id))
        )


def test_pdf_typed_gap_is_not_reexecuted_or_counted_as_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RepeatingDecision:
        identity = ProviderIdentity(
            provider_id="test-repeated-target", provider_version="1", role="fast_decision"
        )

        def __init__(self) -> None:
            self.calls = 0

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.calls += 1
            capability = next(
                (
                    item
                    for item in request.available_probes
                    if item.probe_id == "application.target_pressure"
                ),
                None,
            )
            proposals = (
                ()
                if capability is None
                else (
                    ProbeProposal(
                        schema_version=2,
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key="repeat-target",
                        measurement_need=MeasurementNeed(
                            capability_id=capability.probe_id,
                            observable=capability.observable_ids[0],
                            target_handle=capability.target_handles[0],
                        ),
                    ),
                )
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=proposals,
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-gap-repeat.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 4, "max_rounds": 3}),
            expected_version=state.state_version,
            event="test_budget",
            detail="gap must not consume a probe or loop",
        )
        _waiting_with_binding(investigator, case_id)
        investigator.capabilities = tuple(
            capability
            for capability in investigator.capabilities
            if capability.probe_id == "application.snapshot"
        )
        decision = RepeatingDecision()
        investigator.decision = decision
        executions: list[MeasurementNeed] = []

        def no_execution(
            _opened: OpenedCase, need: MeasurementNeed, **_kwargs: object
        ) -> ObservabilityGap:
            executions.append(need)
            return ObservabilityGap(
                need=need, reason="selected process target changed before execution"
            )

        monkeypatch.setattr(investigator.runtime, "execute_measurement_need", no_execution)

        finished = investigator.run(str(case_id))

        assert len(executions) == 1
        assert decision.calls <= 3
        assert finished.completed_probe_ids == ("application.snapshot",)
        assert len(finished.measurement_gaps) == 1
        assert investigator._attempts_consumed(finished) == 1  # pyright: ignore[reportPrivateUsage]
        assert (
            investigator.repository.load(str(case_id)).measurement_gaps == finished.measurement_gaps
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id = ? AND probe_id = ?",
                (str(case_id), "application.target_pressure"),
            ).fetchone()[0]
            == 0
        )
        assert finished.status is InvestigationStatus.COMPLETE


def test_stale_immutable_pdf_binding_surfaces_new_case_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "pdf-stale-selection.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        _waiting_with_binding(investigator, case_id)
        queued = investigator.repository.load(str(case_id))
        investigator.repository.save(
            queued.model_copy(update={"max_probes": 1}),
            expected_version=queued.state_version,
            event="test_budget",
            detail="no generic probe after stale binding",
        )

        def stale(_targets: ProcessTargetRepository, _case_id: CaseId):
            raise TargetSelectionError("snapshot is stale")

        monkeypatch.setattr(ProcessTargetRepository, "resolve_process_target_for_sampling", stale)
        finished = investigator.run(str(case_id))

        assert any("new case" in warning.lower() for warning in finished.warnings)
        assert len(finished.measurement_gaps) == 1
        assert finished.measurement_gaps[0].reason.startswith("selected process binding")
        assert "application.target_pressure" not in finished.completed_probe_ids
        assert not store.connection.execute(
            "SELECT 1 FROM probe_executions WHERE case_id = ? AND probe_id = ?",
            (str(case_id), "application.target_pressure"),
        ).fetchone()


def test_pdf_catalog_does_not_advertise_incompatible_target_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "pdf-incompatible-registration.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        _waiting_with_binding(investigator, case_id)
        state = investigator.repository.load(str(case_id))
        original = investigator.runtime.probe_manifest
        manifest = original("application.target_pressure")
        assert manifest is not None

        def incompatible(probe_id: str):
            if probe_id == "application.target_pressure":
                return manifest.model_copy(update={"input_model": "NoParameters"})
            return original(probe_id)

        monkeypatch.setattr(investigator.runtime, "probe_manifest", incompatible)
        assert "application.target_pressure" not in {
            item.probe_id
            for item in investigator._case_capabilities(state)  # pyright: ignore[reportPrivateUsage]
        }


def test_queued_v4_checkpoint_upgrades_to_v5_on_resume(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-v4-upgrade.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        _waiting_with_binding(investigator, case_id)
        queued = investigator.repository.load(str(case_id))
        legacy = queued.model_copy(
            update={"schema_version": 4, "max_probes": 1, "measurement_gaps": ()}
        )
        with store.transaction():
            store.connection.execute(
                "UPDATE investigation_checkpoints SET record_json = ? WHERE case_id = ?",
                (legacy.model_dump_json(), str(case_id)),
            )

        finished = investigator.run(str(case_id))

        assert finished.schema_version == 5
        assert investigator.repository.load(str(case_id)).schema_version == 5


def test_pdf_model_can_choose_other_probe_before_selected_target(tmp_path: Path) -> None:
    class OtherFirstDecision:
        identity = ProviderIdentity(
            provider_id="test-other-first", provider_version="1", role="fast_decision"
        )

        def __init__(self) -> None:
            self.calls = 0

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.calls += 1
            selected_id = "core.resources" if self.calls == 1 else "application.target_pressure"
            capability = next(
                item for item in request.available_probes if item.probe_id == selected_id
            )
            need = (
                MeasurementNeed(
                    capability_id=capability.probe_id,
                    observable=capability.observable_ids[0],
                    target_handle=capability.target_handles[0],
                )
                if capability.target_handles
                else None
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        schema_version=2 if need is not None else 1,
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key=f"test-choice:{self.calls}",
                        measurement_need=need,
                    ),
                ),
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-other-first.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 3}),
            expected_version=state.state_version,
            event="test_budget",
            detail="snapshot, one model choice, then selected process",
        )
        _waiting_with_binding(investigator, case_id)
        decision = OtherFirstDecision()
        investigator.decision = decision
        calls: list[str] = []
        runner = default_probe_runner()
        core_manifest = runner.manifest("core.resources")
        target_manifest = runner.manifest("application.target_pressure")
        assert core_manifest is not None and target_manifest is not None

        def collect_core(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append("core.resources")
            at = utc_now()
            return ProbeObservation(
                summary="Resource sample", facts={"cpu_percent": 5}, observed_at=at, captured_at=at
            )

        def collect_target(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append("application.target_pressure")
            at = utc_now()
            return ProbeObservation(
                summary="Target sample", facts={"cpu_percent": 5}, observed_at=at, captured_at=at
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=core_manifest,
                    parameter_model=NoParameters,
                    handler=collect_core,
                    isolated=False,
                ),
                ProbeDefinition(
                    manifest=target_manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=collect_target,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert decision.calls >= 2
        assert calls == ["core.resources", "application.target_pressure"]
        assert finished.completed_probe_ids.count("application.target_pressure") == 1


def test_interrupted_pending_target_is_not_replayed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-interrupted.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        queued = investigator.repository.load(str(case_id))
        investigator.repository.save(
            queued.model_copy(update={"pending_probe_ids": ("application.target_pressure",)}),
            expected_version=queued.state_version,
            event="test_crash",
            detail="target may have been observed before worker crashed",
        )

        def must_not_replay(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("uncertain prior target attempt must not repeat")

        investigator.runtime.execute_measurement_need = must_not_replay  # type: ignore[method-assign]
        finished = investigator.run(str(case_id))

        assert "application.target_pressure" in finished.completed_probe_ids
        assert not finished.pending_probe_ids
        assert any("not automatically repeated" in warning for warning in finished.warnings)
        assert finished.assessment is None
        assert finished.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION


def test_pdf_case_with_too_small_budget_does_not_await_unrunnable_target(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-low-budget.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        limited = investigator.repository.save(
            state.model_copy(
                update={
                    "budget_ms": 5_000,
                    "deadline_at": utc_now() + timedelta(milliseconds=1),
                }
            ),
            expected_version=state.state_version,
            event="test_budget",
            detail="target collection cost exceeds configured case budget",
        )

        finished = investigator.run(str(case_id))

        assert limited.completed_probe_ids == ("application.snapshot",)
        assert finished.status is not InvestigationStatus.AWAITING_TARGET
        assert finished.outcome is not InvestigationOutcome.AWAITING_TARGET
        assert any("10-second case budget" in warning for warning in finished.warnings)
        assert "application.target_pressure" not in finished.completed_probe_ids
