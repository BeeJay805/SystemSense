"""Bounded evidence and artifact retention with crash-safe orphan recovery."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, ensure_utc
from systemsense.storage.sqlite_store import SQLiteStore


class RetentionPolicy(FrozenModel):
    max_evidence_age_days: int = Field(ge=1, le=3650)
    max_evidence_bytes: int = Field(ge=1)
    max_artifact_bytes: int = Field(ge=1)
    batch_size: int = Field(ge=1, le=1000)


class RetentionResult(FrozenModel):
    evidence_deleted: int = Field(ge=0)
    artifact_metadata_deleted: int = Field(ge=0)
    artifact_files_deleted: int = Field(ge=0)
    orphan_files_deleted: int = Field(ge=0)
    remaining_evidence_bytes: int = Field(ge=0)
    remaining_artifact_bytes: int = Field(ge=0)
    evidence_cap_blocked: bool
    artifact_cap_blocked: bool


class RetentionManager:
    """Delete only raw or unreferenced data, in small deterministic batches."""

    def __init__(
        self,
        *,
        store: SQLiteStore,
        artifact_root: Path,
        policy: RetentionPolicy,
    ) -> None:
        self._store = store
        self._artifact_root = artifact_root.resolve()
        self._policy = policy
        self._artifact_root.mkdir(parents=True, exist_ok=True)

    def prune(self, *, now: UtcDateTime) -> RetentionResult:
        checked_at = ensure_utc(now)
        cutoff = checked_at - timedelta(days=self._policy.max_evidence_age_days)
        evidence_deleted = self._store.delete_expired_raw_evidence(
            captured_before=cutoff.isoformat(),
            limit=self._policy.batch_size,
        )
        remaining_slots = self._policy.batch_size - evidence_deleted
        evidence_bytes = self._store.raw_evidence_bytes()
        if evidence_bytes > self._policy.max_evidence_bytes and remaining_slots > 0:
            evidence_deleted += self._store.delete_oldest_raw_evidence(limit=remaining_slots)
            evidence_bytes = self._store.raw_evidence_bytes()

        metadata_deleted = 0
        artifact_files_deleted = 0
        artifact_bytes = self._store.artifact_total_bytes()
        for artifact in self._store.unreferenced_artifacts(limit=self._policy.batch_size):
            created_at = ensure_utc(datetime.fromisoformat(artifact.created_at))
            expired = created_at < cutoff
            over_size = artifact_bytes > self._policy.max_artifact_bytes
            if not expired and not over_size:
                continue
            if not self._store.delete_unreferenced_artifact(artifact_id=artifact.artifact_id):
                continue
            metadata_deleted += 1
            artifact_bytes = max(0, artifact_bytes - artifact.byte_size)
            object_path = self._object_path(artifact.sha256)
            if object_path.is_file():
                object_path.unlink()
                artifact_files_deleted += 1

        orphan_files_deleted = self._clean_orphan_files()
        artifact_bytes = self._store.artifact_total_bytes()
        return RetentionResult(
            evidence_deleted=evidence_deleted,
            artifact_metadata_deleted=metadata_deleted,
            artifact_files_deleted=artifact_files_deleted,
            orphan_files_deleted=orphan_files_deleted,
            remaining_evidence_bytes=evidence_bytes,
            remaining_artifact_bytes=artifact_bytes,
            evidence_cap_blocked=evidence_bytes > self._policy.max_evidence_bytes,
            artifact_cap_blocked=artifact_bytes > self._policy.max_artifact_bytes,
        )

    def _clean_orphan_files(self) -> int:
        objects = self._artifact_root / "objects"
        if not objects.is_dir():
            return 0
        deleted = 0
        for path in objects.rglob("*"):
            if deleted == self._policy.batch_size:
                break
            if not path.is_file():
                continue
            resolved = path.resolve()
            if not resolved.is_relative_to(self._artifact_root):
                raise RuntimeError("artifact path escaped retention root")
            digest = path.name
            canonical = re.fullmatch(
                r"[0-9a-f]{64}", digest
            ) is not None and resolved == self._object_path(digest)
            if canonical and self._store.has_artifact_sha(digest):
                continue
            resolved.unlink()
            deleted += 1
        return deleted

    def _object_path(self, digest: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise RuntimeError("artifact digest is invalid")
        candidate = (self._artifact_root / "objects" / digest[:2] / digest).resolve()
        if not candidate.is_relative_to(self._artifact_root):
            raise RuntimeError("artifact path escaped retention root")
        return candidate
