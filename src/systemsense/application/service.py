"""Local application lifecycle shared by UI and CLI adapters."""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import traceback
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import IO, cast

from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationStatus,
)
from systemsense.application.investigator import Investigator
from systemsense.application.passive import PassiveRecorder, PassiveRecorderConfig
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.domain.ids import CaseId
from systemsense.evidence.retrieval import EvidenceRetrievalQuery, EvidenceRetriever
from systemsense.inference.context import EvidenceContext
from systemsense.inference.settings import ProviderStatus
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

_LOGGER = logging.getLogger(__name__)


def _log_worker_failure(error: Exception) -> None:
    """Keep code locations for diagnosis without logging private exception payloads."""
    frames = traceback.extract_tb(error.__traceback__)
    locations = " > ".join(
        f"{Path(frame.filename).name}:{frame.lineno}:{frame.name}" for frame in frames[-12:]
    )
    code = getattr(error, "sqlite_errorname", None) if isinstance(error, sqlite3.Error) else None
    _LOGGER.error("Worker failure: %s; code=%s; stack=%s", type(error).__name__, code, locations)


class WorkspaceLease:
    """An OS-released workspace lock prevents two application coordinators."""

    def __init__(self, database: Path) -> None:
        database.parent.mkdir(parents=True, exist_ok=True)
        self._file: IO[bytes] = database.with_suffix(".lock").open("a+b")
        if self._file.tell() == 0:
            self._file.write(b"0")
            self._file.flush()
        self._file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self._file.close()
            raise RuntimeError(
                "This evidence workspace already has an active application."
            ) from error

    def close(self) -> None:
        self._file.close()


class ApplicationService:
    """One active investigation; each worker owns its SQLite connection."""

    def __init__(
        self,
        database: Path,
        *,
        factory: Callable[[SQLiteStore], Investigator],
        inference_status: dict[str, object] | None = None,
        passive_factory: Callable[[SQLiteStore, PassiveRecorderConfig], PassiveRecorder]
        | None = None,
    ) -> None:
        self.database = database.resolve()
        self._lease = WorkspaceLease(self.database)
        self._factory = factory
        self._passive_factory = passive_factory
        self._inference_status = inference_status or {"enabled": False, "mode": "deterministic"}
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="systemsense-case")
        self._future: Future[None] | None = None
        self._active_case_id: str | None = None
        self._cancel = threading.Event()
        self._closed = False
        self._passive_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="systemsense-recorder"
        )
        self._passive_future: Future[None] | None = None
        self._passive_cancel = threading.Event()
        self._recorder: PassiveRecorder | None = None
        self._passive_error: str | None = None
        try:
            with SQLiteStore(self.database) as store:
                self._recover(store)
        except BaseException:
            self._executor.shutdown(wait=False)
            self._passive_executor.shutdown(wait=False)
            self._lease.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._cancel.set()
            self._passive_cancel.set()
        self._executor.shutdown(wait=True, cancel_futures=True)
        self._passive_executor.shutdown(wait=True, cancel_futures=True)
        self._lease.close()

    def list_cases(self) -> dict[str, object]:
        with SQLiteStore(self.database) as store:
            rows = store.connection.execute(
                "SELECT case_id, json_extract(record_json, '$.objective'), "
                "json_extract(record_json, '$.status'), json_extract(record_json, '$.outcome'), "
                "cases.created_at, json_extract(record_json, '$.updated_at') "
                "FROM investigation_checkpoints JOIN cases USING(case_id) "
                "ORDER BY cases.created_at DESC, cases.case_id DESC LIMIT 100"
            ).fetchall()
            # History is polled independently of the selected case. Do not send
            # up to 100 full evidence/model checkpoints on every refresh.
            fields = ("case_id", "objective", "status", "outcome", "created_at", "updated_at")
            return {"cases": [dict(zip(fields, row, strict=True)) for row in rows]}

    def get_case(self, case_id: str) -> dict[str, object]:
        CaseId(root=case_id)
        with SQLiteStore(self.database) as store, store.read_snapshot():
            repo = InvestigationRepository(store)
            state = repo.load(case_id)
            data = cast("dict[str, object]", state.model_dump(mode="json"))
            # This is an internal durable reasoning cache. Public reports expose
            # only the case/time-scoped projection assembled under ``evidence``.
            data.pop("assessed_context", None)
            data["timeline"] = [step.model_dump(mode="json") for step in repo.steps(case_id)]
            investigator = self._factory(store)
            packet = investigator.packet(case_id)
            context = investigator.context(case_id)
            context_by_id = {str(item.evidence_id): item for item in context}
            retrieved_by_id = {str(item.evidence_id): item for item in packet.evidence}
            coverage_by_id = {str(item.evidence_id): item for item in packet.coverage}
            assessed_by_id = {str(item.evidence_id): item for item in state.assessed_context}
            cited_ids = tuple(
                dict.fromkeys(
                    (
                        *(state.assessment.evidence_ids if state.assessment is not None else ()),
                        *(
                            evidence_id
                            for hypothesis in state.hypotheses
                            for evidence_id in (
                                *hypothesis.supporting_evidence_ids,
                                *hypothesis.contradicting_evidence_ids,
                            )
                        ),
                    )
                )
            )
            visible_ids = {str(item.evidence_id) for item in context}
            hydrated_context: list[EvidenceContext] = []
            outside_incident = (
                "Current collection is outside the incident window; "
                "it does not establish conditions during that incident."
            )
            for evidence_id in cited_ids:
                key = str(evidence_id)
                assessed = assessed_by_id.get(key)
                if assessed is None or key in visible_ids:
                    continue
                citation_packet = EvidenceRetriever(store).retrieve(
                    EvidenceRetrievalQuery(
                        current_case_id=state.case_id,
                        include_historical=bool(state.historical_case_ids),
                        historical_case_ids=state.historical_case_ids,
                        observed_from=state.incident_start,
                        observed_until=state.incident_end,
                        current_collection_start=state.created_at,
                        evidence_ids=(evidence_id,),
                        evidence_limit=1,
                        coverage_limit=1,
                        candidate_limit=1,
                        max_chars=100_000,
                        max_facts_per_record=0,
                    )
                )
                if citation_packet.evidence:
                    persisted = citation_packet.evidence[0]
                    if (
                        assessed.observed_at != persisted.observed_at
                        or assessed.captured_at != persisted.captured_at
                        or assessed.probe_id != persisted.category
                    ):
                        continue
                    retrieved_by_id[key] = persisted
                    is_outside_incident = (
                        persisted.case_id == state.case_id
                        and not state.incident_start <= persisted.observed_at <= state.incident_end
                    )
                elif citation_packet.coverage:
                    persisted_coverage = citation_packet.coverage[0]
                    if (
                        assessed.observed_at != persisted_coverage.captured_at
                        or assessed.captured_at != persisted_coverage.captured_at
                        or assessed.probe_id != f"{persisted_coverage.category}.coverage"
                    ):
                        continue
                    coverage_by_id[key] = persisted_coverage
                    is_outside_incident = (
                        persisted_coverage.case_id == state.case_id
                        and not state.incident_start
                        <= persisted_coverage.captured_at
                        <= state.incident_end
                    )
                else:
                    continue
                if is_outside_incident:
                    assessed = assessed.model_copy(
                        update={
                            "limitations": tuple(
                                dict.fromkeys((outside_incident, *assessed.limitations))
                            )[:16]
                        }
                    )
                hydrated_context.append(assessed)
                visible_ids.add(key)
            report_context = (*context, *hydrated_context)
            report_evidence: list[dict[str, object]] = []
            for context_item in report_context:
                assessed = assessed_by_id.get(str(context_item.evidence_id))
                # A citation must open the same facts that informed its hypothesis,
                # not a newly compacted first page of a large observation.
                displayed = assessed if assessed is not None else context_item
                if assessed is not None:
                    temporal_notes = tuple(
                        note
                        for note in context_item.limitations
                        if "outside the incident window" in note
                    )
                    if temporal_notes:
                        displayed = displayed.model_copy(
                            update={
                                "limitations": tuple(
                                    dict.fromkeys((*temporal_notes, *displayed.limitations))
                                )[:16]
                            }
                        )
                view = cast("dict[str, object]", displayed.model_dump(mode="json"))
                view["fact_view"] = (
                    "exact_assessed_excerpt" if assessed is not None else "bounded_overview"
                )
                retrieved = retrieved_by_id.get(str(context_item.evidence_id))
                coverage = coverage_by_id.get(str(context_item.evidence_id))
                if retrieved is not None:
                    view.update(
                        {
                            "case_id": str(retrieved.case_id),
                            "source_id": retrieved.source_id,
                            "source_type": retrieved.source_type,
                            "category": retrieved.category,
                            "collector_id": retrieved.collector_id,
                            "execution_id": str(retrieved.execution_id),
                            "statement_kind": retrieved.statement_kind.value,
                            "historical": str(retrieved.case_id) != case_id,
                        }
                    )
                elif coverage is not None:
                    execution_id = (
                        None if coverage.execution_id is None else str(coverage.execution_id)
                    )
                    view.update(
                        {
                            "case_id": str(coverage.case_id),
                            "source_id": coverage.source_id,
                            "source_type": coverage.source_type,
                            "execution_id": execution_id,
                            "historical": str(coverage.case_id) != case_id,
                        }
                    )
                report_evidence.append(view)
            data["evidence"] = report_evidence
            executions = store.connection.execute(
                "SELECT execution_id, probe_id, status FROM probe_executions WHERE case_id = ? "
                "ORDER BY started_at",
                (case_id,),
            ).fetchall()
            probe_by_execution = {str(row[0]): str(row[1]) for row in executions}
            latest_execution = {str(row[1]): (str(row[0]), str(row[2])) for row in executions}
            coverage_by_execution = {
                str(item.execution_id): item
                for item in packet.coverage
                if item.execution_id is not None
            }
            for view in report_evidence:
                execution_id = view.get("execution_id")
                if isinstance(execution_id, str) and execution_id in probe_by_execution:
                    view["probe_id"] = probe_by_execution[execution_id]
            coverage_view: list[dict[str, object]] = []
            for capability in investigator.capabilities:
                attempt = latest_execution.get(capability.probe_id)
                if attempt is None:
                    coverage_view.append(
                        {
                            "probe_id": capability.probe_id,
                            "summary": capability.description,
                            "status": "not_collected",
                            "reason": "No observation collected in this case.",
                        }
                    )
                    continue
                execution_id, status = attempt
                coverage = coverage_by_execution.get(execution_id)
                coverage_item: dict[str, object] = {
                    "probe_id": capability.probe_id,
                    "summary": capability.description,
                    "status": status,
                    "execution_id": execution_id,
                    "reason": "Recorded probe attempt.",
                }
                if coverage is not None:
                    coverage_item.update(
                        {
                            "evidence_id": str(coverage.evidence_id),
                            "captured_at": coverage.captured_at.isoformat(),
                            "reason": coverage.reason or "Recorded probe attempt.",
                            "source_id": coverage.source_id,
                            "source_type": coverage.source_type,
                        }
                    )
                    coverage_context = context_by_id.get(str(coverage.evidence_id))
                    if coverage_context is not None and coverage_context.limitations:
                        coverage_item["limitations"] = list(coverage_context.limitations)
                coverage_view.append(coverage_item)
            data["coverage"] = coverage_view
            evidence_count = int(
                store.connection.execute(
                    "SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,)
                ).fetchone()[0]
            )
            data["evidence_count"] = evidence_count
            data["evidence_view_truncated"] = evidence_count > len(context)
            data["read_only"] = True
            data["retrieval"] = {
                "truncated": packet.truncated,
                "omitted_evidence_count": packet.omitted_evidence_count,
                "omitted_coverage_count": packet.omitted_coverage_count,
                "historical_cases": [str(item) for item in state.historical_case_ids],
            }
            data["relationships"] = [
                r.model_dump(mode="json") for r in investigator.relationships(context)
            ]
            data["reference_knowledge"] = investigator.reference_context(state)
            data["error_references"] = [
                item.model_dump(mode="json") for item in investigator.error_references(state)
            ]
            data["next_action"] = (
                [{"summary": "Collection in progress", "probe_ids": state.pending_probe_ids}]
                if state.status in {InvestigationStatus.RUNNING, InvestigationStatus.QUEUED}
                else [
                    {
                        "summary": "Choose one process from this case's observed snapshot",
                        "detail": "Selection is required before read-only process checks continue.",
                    }
                ]
                if state.status is InvestigationStatus.AWAITING_TARGET
                else [
                    {
                        "summary": state.stop_reason or "Review the evidence and coverage.",
                        "detail": "For an intermittent problem, capture a recurrence and compare "
                        "its incident window. No repair has been authorized or executed.",
                    }
                ]
            )
            if state.status is InvestigationStatus.AWAITING_TARGET:
                try:
                    inventory = ProcessTargetRepository(store).list_process_candidates(
                        state.case_id
                    )
                except TargetSelectionError as error:
                    data["process_target_inventory"] = {
                        "candidates": [],
                        "inventory_complete": False,
                        "unavailable_reason": str(error),
                    }
                    data["next_action"] = [
                        {
                            "summary": "Start a new investigation for a fresh process snapshot",
                            "detail": "The previous candidate inventory is unavailable. "
                            "No target was guessed or sampled.",
                        }
                    ]
                else:
                    data["process_target_inventory"] = inventory.model_dump(mode="json")
                    if not inventory.candidates:
                        data["next_action"] = [
                            {
                                "summary": "Start a new investigation for a fresh process snapshot",
                                "detail": "No selectable target remains in this case. "
                                "No process was guessed or sampled.",
                            }
                        ]
            return data

    def start_case(self, objective: str, budget_ms: int, max_rounds: int) -> dict[str, object]:
        with self._lock:
            self._require_idle()
            with SQLiteStore(self.database) as store:
                state = self._factory(store).create(
                    objective=objective,
                    budget_ms=budget_ms,
                    max_rounds=max_rounds,
                )
            self._launch(str(state.case_id))
        return self.get_case(str(state.case_id))

    def cancel_case(self, case_id: str) -> dict[str, object]:
        CaseId(root=case_id)
        with self._lock:
            if (
                self._active_case_id == case_id
                and self._future is not None
                and not self._future.done()
            ):
                self._cancel.set()
            else:
                with SQLiteStore(self.database) as store:
                    repo = InvestigationRepository(store)
                    state = repo.load(case_id)
                    if state.status in {
                        InvestigationStatus.RUNNING,
                        InvestigationStatus.QUEUED,
                        InvestigationStatus.AWAITING_TARGET,
                    }:
                        repo.save(
                            state.model_copy(
                                update={
                                    "status": InvestigationStatus.CANCELLED,
                                    "outcome": InvestigationOutcome.CANCELLED,
                                    "stop_reason": "Cancelled by the user.",
                                }
                            ),
                            expected_version=state.state_version,
                            event="cancelled",
                            detail="Cancelled by the user.",
                        )
        result = self.get_case(case_id)
        result["cancellation_requested"] = True
        return result

    def resume_case(self, case_id: str) -> dict[str, object]:
        CaseId(root=case_id)
        with self._lock:
            self._require_idle()
            with SQLiteStore(self.database) as store:
                if (
                    InvestigationRepository(store).load(case_id).status
                    is InvestigationStatus.AWAITING_TARGET
                ):
                    raise TargetSelectionError("Select a process target before resuming this case")
                self._factory(store).resume(case_id)
            self._launch(case_id)
        return self.get_case(case_id)

    def select_process_target(self, case_id: str, candidate_id: str) -> dict[str, object]:
        validated_case = CaseId(root=case_id)
        with self._lock:
            if self._closed:
                raise RuntimeError("application is closed")
            with SQLiteStore(self.database) as store:
                state = InvestigationRepository(store).load(case_id)
                targets = ProcessTargetRepository(store)
                if state.status is not InvestigationStatus.AWAITING_TARGET:
                    existing = targets.selected_process_target(validated_case)
                    if (
                        existing is not None
                        and existing.candidate_id == candidate_id
                        and state.status
                        in {InvestigationStatus.QUEUED, InvestigationStatus.RUNNING}
                    ):
                        return self.get_case(case_id)
                    raise TargetSelectionError("Case is not awaiting process selection")
                self._require_idle()
                targets.bind_process_target(validated_case, candidate_id)
                self._factory(store).resume_after_target(case_id)
            self._launch(case_id)
        return self.get_case(case_id)

    def export_case(self, case_id: str) -> dict[str, object]:
        # Export contains the same bounded redacted view, never raw traces or files.
        return {
            "format": "systemsense-case-report-v1",
            "case": self.get_case(case_id),
            "limitations": [
                "Hypotheses are advisory; no machine changes were executed.",
                "This report is bounded. Full local evidence may contain more detail.",
            ],
        }

    def capabilities(self) -> dict[str, object]:
        with SQLiteStore(self.database) as store:
            app = self._factory(store)
            return {
                "read_only": True,
                "inference": self._live_inference_status(app),
                "recorder": self.recorder_status(),
                "active_case_id": self._active_case_id
                if self._future and not self._future.done()
                else None,
                "probes": [p.model_dump(mode="json") for p in app.capabilities],
                "repairs": {
                    "executable": False,
                    "reason": "No reviewed repair executor is enabled.",
                },
            }

    def _live_inference_status(self, investigator: Investigator) -> dict[str, object]:
        result = dict(self._inference_status)
        for role, provider in (
            ("decision", investigator.decision),
            ("reasoning", investigator.reasoning),
        ):
            status = getattr(provider, "status", None)
            if not isinstance(status, ProviderStatus):
                continue
            result[f"{role}_status"] = (
                "ready"
                if status.available
                else "not_checked"
                if status.detail == "not_checked"
                else "unavailable"
            )
            result[f"{role}_detail"] = status.detail
        return result

    def recorder_status(self) -> dict[str, object]:
        with self._lock:
            status: dict[str, object] = (
                cast("dict[str, object]", self._recorder.status().model_dump(mode="json"))
                if self._recorder is not None
                else {"cycles_completed": 0}
            )
            status.update(
                {
                    "available": self._passive_factory is not None,
                    "active": self._passive_future is not None and not self._passive_future.done(),
                    "error": self._passive_error,
                    "detail": "Opt-in local context: resource snapshots and registered Event Logs. "
                    "No startup installation, inference, or repair.",
                }
            )
            return status

    def start_recorder(
        self, interval_seconds: int = 30, max_cycles: int = 120
    ) -> dict[str, object]:
        if isinstance(max_cycles, bool) or not 1 <= max_cycles <= 288:
            raise ValueError("recorder cycles must be between 1 and 288")
        config = PassiveRecorderConfig(interval_seconds=interval_seconds)
        with self._lock:
            if self._closed:
                raise RuntimeError("application is closed")
            if self._passive_factory is None:
                raise ValueError("passive recorder is not configured")
            if self._passive_future is not None and not self._passive_future.done():
                raise RuntimeError("passive recorder is already active")
            self._passive_cancel = threading.Event()
            self._passive_error = None
            self._recorder = None
            self._passive_future = self._passive_executor.submit(
                self._record,
                config,
                max_cycles,
                self._passive_cancel,
            )
        return self.recorder_status()

    def stop_recorder(self) -> dict[str, object]:
        self._passive_cancel.set()
        return self.recorder_status()

    def wait_recorder(self, timeout: float | None = None) -> None:
        if self._passive_future is not None:
            self._passive_future.result(timeout=timeout)

    def _record(
        self, config: PassiveRecorderConfig, max_cycles: int, cancel: threading.Event
    ) -> None:
        try:
            with SQLiteStore(self.database) as store:
                if self._passive_factory is None:
                    raise RuntimeError("passive recorder is unavailable")
                recorder = self._passive_factory(store, config)
                with self._lock:
                    self._recorder = recorder
                recorder.run(cancel, max_cycles=max_cycles)
        except Exception as error:
            _log_worker_failure(error)
            with self._lock:
                self._passive_error = (
                    f"Recorder stopped: {type(error).__name__}. Existing evidence is preserved."
                )

    def wait(self, timeout: float | None = None) -> None:
        future = self._future
        if future is not None:
            future.result(timeout=timeout)

    def _require_idle(self) -> None:
        if self._closed:
            raise RuntimeError("application is closed")
        if self._future is not None and not self._future.done():
            raise RuntimeError(
                "An investigation is already active; cancel or wait for it to finish."
            )

    def _launch(self, case_id: str) -> None:
        self._cancel = threading.Event()
        self._active_case_id = case_id
        self._future = self._executor.submit(self._run, case_id, self._cancel)

    def _run(self, case_id: str, cancellation: threading.Event) -> None:
        with SQLiteStore(self.database) as store:
            try:
                self._factory(store).run(case_id, cancel_event=cancellation)
            except Exception as error:
                _log_worker_failure(error)
                repo = InvestigationRepository(store)
                state = repo.load(case_id)
                repo.save(
                    state.model_copy(
                        update={
                            "status": InvestigationStatus.FAILED,
                            "outcome": InvestigationOutcome.FAILED,
                            "stop_reason": (
                                f"Investigation failed: {type(error).__name__}. "
                                "Existing evidence is preserved."
                            ),
                        }
                    ),
                    expected_version=state.state_version,
                    event="failed",
                    detail=f"Investigation failed: {type(error).__name__}.",
                )

    @staticmethod
    def _recover(store: SQLiteStore) -> None:
        repo = InvestigationRepository(store)
        for row in store.connection.execute(
            "SELECT case_id FROM investigation_checkpoints"
        ).fetchall():
            state = repo.load(str(row[0]))
            if state.status in {InvestigationStatus.RUNNING, InvestigationStatus.QUEUED}:
                repo.save(
                    state.model_copy(
                        update={
                            "status": InvestigationStatus.INTERRUPTED,
                            "outcome": InvestigationOutcome.INTERRUPTED,
                            "stop_reason": (
                                "The previous application stopped before this case finished. "
                                "Resume explicitly."
                            ),
                        }
                    ),
                    expected_version=state.state_version,
                    event="interrupted",
                    detail="Recovered an interrupted case; no work was automatically replayed.",
                )
