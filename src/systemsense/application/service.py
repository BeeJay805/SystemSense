"""Local application lifecycle shared by UI and CLI adapters."""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import traceback
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import IO, cast

from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
)
from systemsense.application.investigator import Investigator
from systemsense.application.loopback_task_observation import (
    observe_user_owned_loopback_task,
    parse_user_owned_loopback_task,
)
from systemsense.application.native_file_capture import capture_selected_file_bounded
from systemsense.application.native_json_repair import (
    JsonRepairError,
    NativeJsonRepairSession,
    json_copy_available,
    saved_json_copy_receipts,
)
from systemsense.application.passive import PassiveRecorder, PassiveRecorderConfig
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.domain.affected_task import AffectedTaskKind, ReportedAffectedTaskV1
from systemsense.domain.ids import CaseId
from systemsense.evidence.retrieval import (
    EvidenceCatalogQuery,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
)
from systemsense.evidence.targets import select_target_evidence
from systemsense.inference.context import EvidenceContext
from systemsense.inference.settings import ProviderStatus
from systemsense.platform.windows.selected_file import SelectedFileCapture
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


def _summary_freshness(state: InvestigationState, current_generation: int) -> dict[str, object]:
    """Report whether the retained advisory was based on the current case generation.

    A generation match does not mean the provider reviewed every available item.
    Older checkpoints and non-advisory summaries have no frozen reasoning basis.
    """
    reviewed = state.summary_reviewed_evidence_generation
    status = "unknown"
    if state.summary_source in {"advisory_async", "advisory_sync"} and reviewed is not None:
        if reviewed == current_generation:
            status = "current"
        elif reviewed < current_generation:
            status = "stale"
    return {
        "status": status,
        "source": state.summary_source,
        "reviewed_generation": reviewed,
        "current_generation": current_generation,
        "scope": "case_evidence_generation_match_only",
    }


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


class _CaseStopSignal(threading.Event):
    """Distinguish an owner pipe loss from an explicit cancellation."""

    def __init__(self) -> None:
        super().__init__()
        self.interrupted = False

    def mark_interrupted(self) -> None:
        if not self.is_set():
            self.interrupted = True
        self.set()


class ApplicationService:
    """One active investigation; each worker owns its SQLite connection."""

    def __init__(
        self,
        database: Path,
        *,
        factory: Callable[[SQLiteStore], Investigator],
        inference_status: dict[str, object] | Callable[[], dict[str, object]] | None = None,
        passive_factory: Callable[[SQLiteStore, PassiveRecorderConfig], PassiveRecorder]
        | None = None,
        enable_local_json: bool = False,
        enable_json_copy: bool = False,
    ) -> None:
        self.database = database.resolve()
        self._lease = WorkspaceLease(self.database)
        self._factory = factory
        self._passive_factory = passive_factory
        self._inference_status = inference_status or {"enabled": False, "mode": "deterministic"}
        self._enable_local_json = enable_local_json
        self._enable_json_copy = enable_json_copy and enable_local_json
        self._json_repair = NativeJsonRepairSession(self.database)
        self._native_copy_done = threading.Event()
        self._native_copy_done.set()
        self._selected_file: tuple[str, SelectedFileCapture] | None = None
        self._file_capture_pending = False
        self._file_capture_cancel = threading.Event()
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="systemsense-case")
        self._future: Future[None] | None = None
        self._active_case_id: str | None = None
        self._cancel = _CaseStopSignal()
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
            self._json_repair.recover_interrupted()
        except BaseException:
            self._executor.shutdown(wait=False)
            self._passive_executor.shutdown(wait=False)
            self._lease.close()
            raise

    def request_shutdown(self, *, interrupted: bool = False) -> None:
        """Signal owner shutdown promptly, including a native selection before case creation."""
        with self._lock:
            self._closed = True
            if interrupted:
                self._cancel.mark_interrupted()
            else:
                self._cancel.set()
            self._passive_cancel.set()
            self._file_capture_cancel.set()

    def close(self, *, interrupted: bool = False) -> None:
        self.request_shutdown(interrupted=interrupted)
        self._executor.shutdown(wait=True, cancel_futures=True)
        self._passive_executor.shutdown(wait=True, cancel_futures=True)
        if not self._native_copy_done.wait(timeout=8):
            raise RuntimeError("native copy shutdown remains uncertain")
        self._lease.close()
        self._selected_file = None

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
            data["json_copy"] = {
                "available": self._enable_json_copy
                and state.status is InvestigationStatus.COMPLETE
                and self._selected_file is not None
                and self._selected_file[0] == case_id
                and json_copy_available(self._selected_file[1]),
                "receipts": saved_json_copy_receipts(store, case_id),
            }
            # This is an internal durable reasoning cache. Public reports expose
            # only the case/time-scoped projection assembled under ``evidence``.
            data.pop("assessed_context", None)
            current_generation = (
                EvidenceRetriever(store)
                .discover(EvidenceCatalogQuery(case_id=state.case_id, limit=1))
                .case_evidence_generation
            )
            data["summary_freshness"] = _summary_freshness(state, current_generation)
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
                                *(
                                    item.evidence_id
                                    for item in hypothesis.noncausal_observation_refs
                                ),
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
            application_context = tuple(
                item
                for item in context
                if item.probe_id == "application.snapshot" and item.case_scope == "current_case"
            )
            focused_process = select_target_evidence(store, application_context, state.objective)
            focused_process_by_id = (
                {}
                if focused_process.truncated
                else {str(item.evidence_id): item for item in focused_process.context}
            )
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
                focused = focused_process_by_id.get(str(context_item.evidence_id))
                if (
                    focused is not None
                    and focused.observed_at == context_item.observed_at
                    and focused.captured_at == context_item.captured_at
                    and focused.probe_id == context_item.probe_id
                ):
                    displayed = focused
                view = cast("dict[str, object]", displayed.model_dump(mode="json"))
                view["fact_view"] = (
                    "exact_target_excerpt"
                    if focused is not None and displayed is focused
                    else "exact_assessed_excerpt"
                    if assessed is not None
                    else "bounded_overview"
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

    def start_case(
        self,
        objective: str,
        budget_ms: int,
        max_rounds: int,
        *,
        reported_task: ReportedAffectedTaskV1 | None = None,
    ) -> dict[str, object]:
        with self._lock:
            self._require_case_start_allowed()
            self._require_idle()
            user_loopback = (
                parse_user_owned_loopback_task(objective) if reported_task is None else None
            )
            if user_loopback is not None:
                target = f"127.0.0.1:{user_loopback.port}"
                reported_task = ReportedAffectedTaskV1(
                    kind=AffectedTaskKind.NETWORK_CONNECTION,
                    action=f"GET http://{target}/health/{user_loopback.nonce}",
                    target_hint=target,
                    expected_outcome="HTTP 200 with the requested nonce",
                    reported_outcome="The user asked Dyad to check this exact local health GET.",
                )
            with SQLiteStore(self.database) as store:
                state = self._factory(store).create(
                    objective=objective,
                    reported_task=reported_task,
                    budget_ms=budget_ms,
                    max_rounds=max_rounds,
                )
                if user_loopback is not None:
                    try:
                        observe_user_owned_loopback_task(
                            store, case_id=state.case_id, scope=user_loopback
                        )
                    except Exception as error:
                        _log_worker_failure(error)
                        InvestigationRepository(store).save(
                            state.model_copy(
                                update={
                                    "status": InvestigationStatus.FAILED,
                                    "outcome": InvestigationOutcome.FAILED,
                                    "stop_reason": (
                                        "The exact local health check could not be recorded."
                                    ),
                                }
                            ),
                            expected_version=state.state_version,
                            event="task_observation_failed",
                            detail="The exact local health check could not be recorded.",
                        )
                        raise RuntimeError(
                            "The exact local health check could not be recorded."
                        ) from error
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

    def start_local_json_case(self, selected_path: str) -> dict[str, object]:
        """Native-parent-only grant; never expose this path argument through HTTP or models."""
        from systemsense.application.local_json_task import (
            SELECTED_JSON_ACTION,
            observe_selected_json_task,
        )

        with self._lock:
            if not self._enable_local_json:
                raise RuntimeError("unavailable")
            self._require_case_start_allowed()
            self._require_idle()
            self._file_capture_pending = True
            self._file_capture_cancel = threading.Event()
        try:
            capture = capture_selected_file_bounded(selected_path, self._file_capture_cancel)
        finally:
            with self._lock:
                self._file_capture_pending = False
        with self._lock:
            # Shutdown may have arrived while the exact native capture was running.
            self._require_case_start_allowed()
            self._require_idle()
            if self._file_capture_cancel.is_set():
                raise RuntimeError("native selection cancelled")
            identity = capture.observation.identity_sha256
            # A failed open has no verified file identity. Keep it as an explicit
            # unbound observation rather than guessing or reopening a path.
            reported = (
                ReportedAffectedTaskV1(
                    kind=AffectedTaskKind.OTHER,
                    action=SELECTED_JSON_ACTION,
                    target_hint=f"selected_file_{identity}",
                    expected_outcome="Accepted by Dyad's bounded strict UTF-8 JSON parser.",
                    reported_outcome="The user selected one file for this parser check.",
                )
                if identity is not None
                else None
            )
            with SQLiteStore(self.database) as store:
                state = self._factory(store).create(
                    objective=(
                        "Check whether the selected local file is accepted as strict UTF-8 JSON."
                    ),
                    reported_task=reported,
                    budget_ms=60_000,
                    max_rounds=6,
                )
                observe_selected_json_task(store, case_id=state.case_id, capture=capture)
            self._selected_file = (str(state.case_id), capture)
            self._launch(str(state.case_id))
        return self.get_case(str(state.case_id))

    def resume_case(self, case_id: str) -> dict[str, object]:
        CaseId(root=case_id)
        with self._lock:
            self._require_case_start_allowed()
            self._require_idle()
            with SQLiteStore(self.database) as store:
                reference = InvestigationRepository(store).load(case_id).task_observation_reference
                if reference is not None and reference.scope == "user_selected_file":
                    raise RuntimeError(
                        "Select the file again to start a fresh check. "
                        "Saved evidence remains readable."
                    )
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
            self._require_case_start_allowed()
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

    def native_json_repair(self, kind: str, fields: dict[str, str]) -> dict[str, object]:
        """Called only by the parent's private pipe, never an HTTP or model route."""
        expected = {
            "json_repair_prepare": {"case_id"},
            "json_repair_bind_destination": {"offer_token", "destination_path"},
            "json_repair_execute": {"proposal_token", "proposal_digest"},
            "json_repair_status": {"proposal_token"},
            "json_repair_abandon": {"offer_token"},
        }
        if kind not in expected or set(fields) != expected[kind]:
            raise JsonRepairError("invalid_request")
        for key, value in fields.items():
            if (
                (key.endswith("token") and re.fullmatch(r"[A-Za-z0-9_-]{16,256}", value) is None)
                or (key == "proposal_digest" and re.fullmatch(r"[0-9a-f]{64}", value) is None)
                or (key == "case_id" and re.fullmatch(r"case_[0-9a-f]{32}", value) is None)
            ):
                raise JsonRepairError("invalid_request")
        with self._lock:
            if not self._enable_json_copy or self._closed:
                raise JsonRepairError("unavailable")
            if kind == "json_repair_status":
                return self._json_repair.status(fields["proposal_token"])
            if kind == "json_repair_abandon":
                self._json_repair.abandon(fields["offer_token"])
                return {"type": "json_repair_abandoned"}
            self._require_idle()
            if kind == "json_repair_prepare":
                if self._selected_file is None or self._selected_file[0] != fields["case_id"]:
                    raise JsonRepairError("source_unavailable")
                return self._json_repair.prepare(fields["case_id"], self._selected_file[1])
            if kind == "json_repair_bind_destination":
                return self._json_repair.bind(fields["offer_token"], fields["destination_path"])
            self._native_copy_done.clear()
        try:
            return self._json_repair.execute(
                fields["proposal_token"], fields["proposal_digest"], self._file_capture_cancel
            )
        finally:
            self._native_copy_done.set()

    def export_case(self, case_id: str) -> dict[str, object]:
        # Export contains the same bounded redacted view, never raw traces or files.
        return {
            "format": "systemsense-case-report-v1",
            "case": self.get_case(case_id),
            "limitations": [
                "Investigations are read-only. Separately approved copy operations, if any, "
                "are recorded in json_copy.receipts.",
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
                    "executable": self._enable_json_copy,
                    "reason": "Only native-approved captured JSON copies; no automatic repair."
                    if self._enable_json_copy
                    else "No reviewed repair executor is enabled.",
                },
                "local_json_task": {"enabled": self._enable_local_json, "max_bytes": 262144},
            }

    def _live_inference_status(self, investigator: Investigator) -> dict[str, object]:
        configured = (
            self._inference_status() if callable(self._inference_status) else self._inference_status
        )
        result = dict(configured)
        for role, provider in (
            ("decision", investigator.decision),
            ("reasoning", investigator.reasoning),
        ):
            status = getattr(provider, "status", None)
            if not isinstance(status, ProviderStatus):
                continue
            if callable(self._inference_status) and f"{role}_status" in configured:
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

    def _require_case_start_allowed(self) -> None:
        status = (
            self._inference_status() if callable(self._inference_status) else self._inference_status
        )
        if status.get("start_allowed") is False:
            raise RuntimeError("The requested model investigation is unavailable. Check Settings.")

    def _require_idle(self) -> None:
        if self._closed:
            raise RuntimeError("application is closed")
        if self._file_capture_pending:
            raise RuntimeError("A native file selection is already active.")
        if not self._native_copy_done.is_set():
            raise RuntimeError("An approved native copy is already active.")
        if self._future is not None and not self._future.done():
            raise RuntimeError(
                "An investigation is already active; cancel or wait for it to finish."
            )

    def _launch(self, case_id: str) -> None:
        self._cancel = _CaseStopSignal()
        self._active_case_id = case_id
        self._future = self._executor.submit(self._run, case_id, self._cancel)

    def _run(self, case_id: str, cancellation: threading.Event) -> None:
        with SQLiteStore(self.database) as store:
            try:
                app = self._factory(store)
                if self._selected_file is not None and self._selected_file[0] == case_id:
                    from systemsense.application.bootstrap import default_case_runtime
                    from systemsense.application.local_json_task import (
                        selected_json_capabilities,
                        selected_json_definitions,
                    )

                    app.runtime = default_case_runtime(
                        store,
                        case_probe_definitions=selected_json_definitions(self._selected_file[1]),
                    )
                    app.capabilities = (*app.capabilities, *selected_json_capabilities())
                app.run(case_id, cancel_event=cancellation)
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
                queued_summary = state.summary == "Queued for read-only investigation."
                repo.save(
                    state.model_copy(
                        update={
                            "status": InvestigationStatus.INTERRUPTED,
                            "outcome": InvestigationOutcome.INTERRUPTED,
                            "stop_reason": (
                                "The previous application stopped before this case finished. "
                                "Resume explicitly."
                            ),
                            **(
                                {
                                    "summary": (
                                        "Investigation interrupted before a supported answer. "
                                        "The case was saved; resume explicitly."
                                    ),
                                    "summary_source": "coordinator",
                                    "summary_reviewed_evidence_generation": None,
                                }
                                if queued_summary
                                else {}
                            ),
                        }
                    ),
                    expected_version=state.state_version,
                    event="interrupted",
                    detail="Recovered an interrupted case; no work was automatically replayed.",
                )
