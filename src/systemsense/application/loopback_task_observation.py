"""Exact, opt-in observation of the disposable local HTTP trial task.

This is deliberately not a catalog probe or a general URL fetcher. The trial
owner supplies the fixture's port and nonce; neither model can supply either.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import time
from typing import Annotated, Literal

from pydantic import Field

from systemsense.domain.affected_task import (
    TaskObservationFactPathsV1,
    TaskObservationReferenceV1,
)
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    FrozenModel,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.time import utc_now
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import RelevantVersionsV1, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore


class TestOwnedLoopbackTaskV1(FrozenModel):
    """One exact disposable fixture endpoint, with no URL or host input."""

    __test__ = False

    port: Annotated[int, Field(ge=49152, le=65535)]
    nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


class UserOwnedLoopbackTaskV1(FrozenModel):
    """One user-specified high-port loopback nonce health GET, never a model URL."""

    port: Annotated[int, Field(ge=49152, le=65535)]
    nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


def parse_user_owned_loopback_task(objective: str) -> UserOwnedLoopbackTaskV1 | None:
    """Recognize one exact fixed-shape loopback URL in user intake text."""

    urls = re.findall(r"https?://[^\s]+", objective, flags=re.IGNORECASE)
    if len(urls) != 1:
        return None
    url = urls[0].rstrip(".,;)")
    match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})/health/([0-9a-f]{32})", url)
    if match is None:
        return None
    try:
        return UserOwnedLoopbackTaskV1(port=int(match.group(1)), nonce=match.group(2))
    except ValueError:
        return None


def observe_test_owned_loopback_task(
    store: SQLiteStore,
    *,
    case_id: CaseId,
    scope: TestOwnedLoopbackTaskV1,
    timeout_seconds: float = 2.0,
) -> EvidenceRecord:
    return _observe_loopback_task(
        store,
        case_id=case_id,
        scope=scope,
        scope_kind="test_owned_loopback",
        timeout_seconds=timeout_seconds,
    )


def observe_user_owned_loopback_task(
    store: SQLiteStore,
    *,
    case_id: CaseId,
    scope: UserOwnedLoopbackTaskV1,
    timeout_seconds: float = 2.0,
) -> EvidenceRecord:
    return _observe_loopback_task(
        store,
        case_id=case_id,
        scope=scope,
        scope_kind="user_owned_loopback",
        timeout_seconds=timeout_seconds,
    )


def _observe_loopback_task(
    store: SQLiteStore,
    *,
    case_id: CaseId,
    scope: TestOwnedLoopbackTaskV1 | UserOwnedLoopbackTaskV1,
    scope_kind: Literal["test_owned_loopback", "user_owned_loopback"],
    timeout_seconds: float,
) -> EvidenceRecord:
    """Execute one bounded GET and persist its result as first-party case evidence.

    The caller owns the disposable server and has consent for this exact task.
    No redirects, proxies, DNS, retries, or response content are admitted.
    """

    if not 0.1 <= timeout_seconds <= 2.0:
        raise ValueError("loopback trial timeout must be 0.1..2 seconds")
    state = InvestigationRepository(store).load(str(case_id))
    if state.task_observation_reference is not None or state.status.value != "queued":
        raise ValueError("task observation requires one unstarted case")
    target = f"127.0.0.1:{scope.port}"
    path = f"/health/{scope.nonce}"
    if state.reported_task is not None and (
        state.reported_task.target_hint != target
        or state.reported_task_action_sha256
        != hashlib.sha256(f"GET http://{target}{path}".encode()).hexdigest()
    ):
        raise ValueError("test-owned task scope does not match the reported exact action")
    started_at = utc_now()
    start = time.monotonic()
    status: int | None = None
    nonce_match: bool | None = None
    outcome = "request_error"
    error_type: str | None = None
    connection = http.client.HTTPConnection("127.0.0.1", scope.port, timeout=timeout_seconds)
    try:
        connection.request("GET", path, headers={"Cache-Control": "no-store"})
        response = connection.getresponse()
        status = response.status
        if status == 200:
            nonce_match = response.read(65) == (scope.nonce + "\n").encode("ascii")
            outcome = "http_200_nonce_match" if nonce_match else "wrong_response"
        elif status == 503:
            outcome = "http_503"
        else:
            outcome = "http_other_status"
    except ConnectionRefusedError:
        outcome = "connection_refused"
        error_type = "ConnectionRefusedError"
    except TimeoutError:
        outcome = "timeout"
        error_type = "TimeoutError"
    except OSError as error:
        error_type = type(error).__name__
    finally:
        connection.close()
    observed_at = utc_now()
    elapsed_ms = round((time.monotonic() - start) * 1000, 3)
    captured_at = utc_now()
    sample_window_ms = max(1, round((observed_at - started_at).total_seconds() * 1000))
    execution_id = ExecutionId.new()
    evidence_id = EvidenceId.new()
    collector_id = "task.loopback_http"
    source_id = stable_source_id(
        "systemsense.probe", {"case_id": str(case_id), "target": target, "path": path}
    )
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=captured_at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": collector_id, "target_handle": target, "path": path},
        ),
        collector=CollectorReference(id=collector_id, version=1, execution_id=execution_id),
        summary=f"Exact {scope_kind.replace('_', '-')} HTTP task at {target}: {outcome}.",
        facts=(
            EvidenceFact(name="target_handle", value=target),
            EvidenceFact(name="action", value=f"GET {path}"),
            EvidenceFact(name="expected", value="HTTP 200 with matching nonce"),
            EvidenceFact(name="outcome", value=outcome),
            EvidenceFact(name="http_status", value=status),
            EvidenceFact(name="nonce_match", value=nonce_match),
            EvidenceFact(name="error_type", value=error_type),
            EvidenceFact(name="elapsed_ms", value=elapsed_ms, unit="ms"),
            EvidenceFact(name="request_started_at_utc", value=started_at.isoformat()),
            EvidenceFact(name="request_finished_at_utc", value=observed_at.isoformat()),
            EvidenceFact(name="sample_window_ms", value=sample_window_ms, unit="ms"),
        ),
        extraction=Extraction(confidence=1.0, parser=collector_id, parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
        limitations=(
            (
                "One GET to an exact test-owned loopback fixture; "
                "no application-internal cause proof."
                if scope_kind == "test_owned_loopback"
                else "One GET to an exact user-owned loopback health endpoint; "
                "no application-internal cause proof."
            ),
            (
                "The independent evaluator outcome is outside this case."
                if scope_kind == "test_owned_loopback"
                else "This check does not establish why an application returned its result."
            ),
        ),
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id=collector_id,
            probe_version=1,
            status="ok",
            parameters_json=json.dumps(
                {
                    "port": scope.port,
                    "nonce": scope.nonce,
                    "timeout_seconds": timeout_seconds,
                    "scope": scope_kind,
                },
                sort_keys=True,
            ),
            started_at=started_at.isoformat(),
            finished_at=observed_at.isoformat(),
            state_version=state.state_version,
        )
        inserted = transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=observed_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"{collector_id}:{case_id}",
            time_basis="collector_observed",
            time_quality="exact",
        )
        if not inserted:
            raise ValueError("case already has a loopback task observation")
        generation_row = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        if generation_row is None:
            raise ValueError("task observation evidence generation is unavailable")
        SearchFrontierRepository(store).append_result_event(
            case_id,
            source_evidence_id=evidence_id,
            source_execution_id=execution_id,
            versions=RelevantVersionsV1(objective=1, evidence=int(generation_row[0])),
        )
    reference = TaskObservationReferenceV1(
        case_id=case_id,
        evidence_id=evidence_id,
        source_id=source_id,
        collector_id=collector_id,
        collector_version=1,
        execution_id=execution_id,
        record_sha256=hashlib.sha256(record.model_dump_json().encode("utf-8")).hexdigest(),
        fact_paths=TaskObservationFactPathsV1(
            target_handle="target_handle",
            action="action",
            expected="expected",
            observed="outcome",
            window_start="request_started_at_utc",
            window_end="request_finished_at_utc",
            window_ms="sample_window_ms",
        ),
        scope=scope_kind,
    )
    from systemsense.application.task_observation import resolve_task_observation

    resolve_task_observation(store, case_id=case_id, reference=reference)
    InvestigationRepository(store).save(
        state.model_copy(update={"task_observation_reference": reference}),
        expected_version=state.state_version,
        event="task_observed",
        detail=f"Exact {scope_kind.replace('_', '-')} loopback task result bound to this case.",
    )
    return record
