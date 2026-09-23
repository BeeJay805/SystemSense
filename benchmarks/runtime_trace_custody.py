"""Host-only custody bridge for one verified coordinator episode.

This sidecar is not the fixed-sequence arm-result capture. It stores the digest
and times of a caller-held episode artifact, not the artifact bytes. It binds
those to a bounded journal projection before source-row retention closes the
export window. Hashes establish local readback consistency, not guest identity.
If a late or interrupted write has reached the custody root, exclusive creation
leaves it as an orphan for review; it is never silently deleted or admitted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from benchmarks.lab_episodes import ArmKind, LabModel
from benchmarks.oracle_evidence_binding import CoordinatorEventLogV1
from benchmarks.vm_lab_custody import (
    CaptureKind,
    CaptureReceipt,
    capture_bytes,
    verify_capture,
)
from systemsense.evaluation.models import EpisodeArtifact
from systemsense.evaluation.trace import verify_episode_event_projection, verify_episode_trace
from systemsense.storage.sqlite_store import SQLiteStore

_MAX_TRACE_BYTES = 48 * 1024
_MAX_PAYLOAD_BYTES = 64 * 1024
_MAX_CAPTURE_LAG = timedelta(minutes=5)


class RuntimeTraceCaptureV1(LabModel):
    """No objective or raw evidence is copied into the host sidecar."""

    schema_version: Literal[1] = 1
    classification: Literal["host_runtime_trace_capture_only"] = "host_runtime_trace_capture_only"
    episode_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    arm_kind: ArmKind
    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_started_at: datetime
    artifact_finished_at: datetime
    trace_json: str = Field(min_length=1, max_length=_MAX_TRACE_BYTES)
    trace_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trace_byte_count: int = Field(ge=1, le=_MAX_TRACE_BYTES)

    @model_validator(mode="after")
    def valid_trace(self) -> Self:
        trace_bytes = self.trace_json.encode("utf-8")
        if (
            len(trace_bytes) != self.trace_byte_count
            or hashlib.sha256(trace_bytes).hexdigest() != self.trace_sha256
            or self.artifact_started_at.utcoffset() != timedelta(0)
            or self.artifact_finished_at.utcoffset() != timedelta(0)
            or self.artifact_finished_at < self.artifact_started_at
        ):
            raise ValueError("runtime trace digest, size, or time is invalid")
        trace = CoordinatorEventLogV1.model_validate_json(trace_bytes)
        if trace.case_id != self.case_id:
            raise ValueError("runtime trace case identity is invalid")
        if any(
            not self.artifact_started_at <= event.observed_at <= self.artifact_finished_at
            for event in trace.events
        ):
            raise ValueError("runtime trace event lies outside episode")
        return self


@dataclass(frozen=True, slots=True)
class RuntimeTraceBinding:
    schema_version: Literal[1]
    classification: Literal["host_runtime_trace_consistency_only"]
    episode_id: str
    arm_kind: ArmKind
    case_id: str
    artifact_sha256: str
    trace_sha256: str
    trace_byte_count: int
    capture_sha256: str
    trace_digest_verified: Literal[False]


@dataclass(frozen=True, slots=True)
class CapturedRuntimeTrace:
    receipt: CaptureReceipt
    binding: RuntimeTraceBinding


def capture_runtime_episode_trace(
    root: Path,
    store: SQLiteStore,
    artifact: EpisodeArtifact,
    *,
    episode_id: str,
    arm_kind: ArmKind,
    capture_id: str,
    controller_id: str,
) -> CapturedRuntimeTrace:
    """Verify committed source rows and exclusively capture their projection.

    The short SQLite writer lock prevents concurrent retention from deleting
    source rows between verification and the write-once host capture.
    """

    artifact = EpisodeArtifact.model_validate(artifact.model_dump(mode="json"))
    if not timedelta(0) <= datetime.now(UTC) - artifact.finished_at <= _MAX_CAPTURE_LAG:
        raise ValueError("runtime episode is not freshly completed")
    with store.transaction():
        case = store.case(str(artifact.case_id))
        if case is None or case.symptom != artifact.objective:
            raise ValueError("runtime artifact objective does not match source case")
        exported = verify_episode_trace(store, artifact)
        CoordinatorEventLogV1.model_validate(exported)
        trace_bytes = json.dumps(
            exported, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if not 0 < len(trace_bytes) <= _MAX_TRACE_BYTES:
            raise ValueError("runtime trace exceeds host capture budget")
        payload = RuntimeTraceCaptureV1(
            episode_id=episode_id,
            arm_kind=arm_kind,
            case_id=str(artifact.case_id),
            artifact_sha256=artifact.integrity_sha256(),
            artifact_started_at=artifact.started_at,
            artifact_finished_at=artifact.finished_at,
            trace_json=trace_bytes.decode("utf-8"),
            trace_sha256=hashlib.sha256(trace_bytes).hexdigest(),
            trace_byte_count=len(trace_bytes),
        )
        data = json.dumps(
            payload.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(data) > _MAX_PAYLOAD_BYTES:
            raise ValueError("runtime trace sidecar exceeds host capture budget")
        receipt = capture_bytes(
            root,
            episode_id=episode_id,
            capture_id=capture_id,
            kind=CaptureKind.RUNTIME_EPISODE_TRACE,
            controller_id=controller_id,
            source_observed_at=artifact.finished_at,
            data=data,
        )
        if receipt.collected_at - artifact.finished_at > _MAX_CAPTURE_LAG:
            raise ValueError("runtime trace host capture lag exceeded")
    binding = read_runtime_episode_trace(
        root, receipt, artifact, episode_id=episode_id, arm_kind=arm_kind
    )
    return CapturedRuntimeTrace(receipt=receipt, binding=binding)


def read_runtime_episode_trace(
    root: Path,
    receipt: CaptureReceipt,
    artifact: EpisodeArtifact,
    *,
    episode_id: str,
    arm_kind: ArmKind,
) -> RuntimeTraceBinding:
    """Read back a sidecar and match it to the caller-held exact episode."""

    if receipt.kind is not CaptureKind.RUNTIME_EPISODE_TRACE or not verify_capture(root, receipt):
        raise ValueError("runtime trace receipt is invalid")
    path = root / receipt.episode_id / receipt.role / f"{receipt.capture_id}.bin"
    try:
        with path.open("rb") as capture_file:
            data = capture_file.read(_MAX_PAYLOAD_BYTES + 1)
    except OSError as error:
        raise ValueError("runtime trace readback failed") from error
    if (
        len(data) > _MAX_PAYLOAD_BYTES
        or len(data) != receipt.byte_count
        or hashlib.sha256(data).hexdigest() != receipt.sha256
    ):
        raise ValueError("runtime trace receipt readback differs")
    try:
        payload = RuntimeTraceCaptureV1.model_validate_json(data)
        artifact = EpisodeArtifact.model_validate(artifact.model_dump(mode="json"))
    except ValueError as error:
        raise ValueError("runtime trace payload or artifact is invalid") from error
    if payload.episode_id != episode_id or receipt.episode_id != episode_id:
        raise ValueError("runtime trace episode identity differs")
    if payload.arm_kind != arm_kind:
        raise ValueError("runtime trace arm identity differs")
    if (
        payload.case_id != str(artifact.case_id)
        or payload.artifact_sha256 != artifact.integrity_sha256()
        or payload.artifact_started_at != artifact.started_at
        or payload.artifact_finished_at != artifact.finished_at
        or receipt.source_observed_at != artifact.finished_at
    ):
        raise ValueError("runtime trace artifact identity differs")
    verified_trace = CoordinatorEventLogV1.model_validate_json(payload.trace_json)
    verify_episode_event_projection(verified_trace.model_dump(mode="json"), artifact)
    if (
        receipt.source_observed_at.utcoffset() != timedelta(0)
        or receipt.collected_at.utcoffset() != timedelta(0)
        or not timedelta(0) <= receipt.collected_at - receipt.source_observed_at <= _MAX_CAPTURE_LAG
    ):
        raise ValueError("runtime trace receipt is stale")
    return RuntimeTraceBinding(
        schema_version=1,
        classification="host_runtime_trace_consistency_only",
        episode_id=episode_id,
        arm_kind=arm_kind,
        case_id=payload.case_id,
        artifact_sha256=payload.artifact_sha256,
        trace_sha256=payload.trace_sha256,
        trace_byte_count=payload.trace_byte_count,
        capture_sha256=receipt.sha256,
        trace_digest_verified=False,
    )
