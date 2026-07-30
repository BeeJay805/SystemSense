"""Content-addressed, case-scoped storage for bounded evidence artifacts."""

import hashlib
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

from pydantic import Field

from systemsense.domain.evidence import FrozenModel, Sensitivity
from systemsense.domain.ids import ArtifactId, CaseId
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.redaction import Redactor
from systemsense.storage.sqlite_store import ArtifactRow, SQLiteStore

_TEXT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/x-ndjson",
        "application/xml",
        "application/yaml",
    }
)
_MAX_EXCERPT_BYTES = 32_768


class ArtifactAccessDenied(PermissionError):
    """The case does not own the requested artifact."""


class BinaryArtifactError(ValueError):
    """Binary content cannot be emitted through the evidence API."""


class ArtifactCorruptError(RuntimeError):
    """Persisted metadata or content does not match the artifact contract."""


class ArtifactMetadata(FrozenModel):
    artifact_id: ArtifactId
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_size: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)
    sensitivity: Sensitivity
    created_at: UtcDateTime


class TextExcerpt(FrozenModel):
    artifact: ArtifactMetadata
    text: str
    offset_bytes: int = Field(ge=0)
    returned_bytes: int = Field(ge=0, le=_MAX_EXCERPT_BYTES)
    truncated: bool
    redaction_count: int = Field(ge=0)


class ArtifactStore:
    def __init__(
        self,
        root: Path,
        store: SQLiteStore,
        *,
        redactor: Redactor | None = None,
    ) -> None:
        self._root = root.resolve()
        self._store = store
        self._redactor = redactor or Redactor()
        self._root.mkdir(parents=True, exist_ok=True)

    def put(
        self,
        *,
        case_id: CaseId,
        content: bytes,
        media_type: str,
        sensitivity: Sensitivity,
    ) -> ArtifactMetadata:
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = ArtifactId(root=f"artifact_{digest[:32]}")
        object_path = self._object_path(digest)
        self._write_object(object_path, content)
        created_at = utc_now()

        with self._store.transaction() as transaction:
            transaction.link_artifact(
                artifact_id=str(artifact_id),
                case_id=str(case_id),
                sha256=digest,
                byte_size=len(content),
                media_type=media_type,
                sensitivity=sensitivity.value,
                created_at=created_at.isoformat(),
            )

        row = self._store.artifact_for_case(
            case_id=str(case_id),
            artifact_id=str(artifact_id),
        )
        if row is None:
            raise RuntimeError("artifact relation was not persisted")
        return self._metadata(row)

    def get_text_excerpt(
        self,
        *,
        case_id: CaseId,
        artifact_id: ArtifactId,
        offset_bytes: int = 0,
        max_bytes: int = 4096,
    ) -> TextExcerpt:
        if offset_bytes < 0:
            raise ValueError("offset_bytes cannot be negative")
        if not 1 <= max_bytes <= _MAX_EXCERPT_BYTES:
            raise ValueError(f"max_bytes must be between 1 and {_MAX_EXCERPT_BYTES}")

        row = self._store.artifact_for_case(
            case_id=str(case_id),
            artifact_id=str(artifact_id),
        )
        if row is None:
            raise ArtifactAccessDenied("artifact is not related to this case")
        metadata = self._metadata(row)
        if not self._is_text(metadata.media_type):
            raise BinaryArtifactError("binary artifacts cannot be returned as excerpts")

        object_path = self._object_path(metadata.sha256)
        if not object_path.is_file():
            raise ArtifactCorruptError("artifact object is missing")
        with object_path.open("rb") as artifact_file:
            artifact_file.seek(offset_bytes)
            raw = artifact_file.read(max_bytes + 1)

        redaction = self._redactor.redact_text(raw[:max_bytes].decode("utf-8", errors="replace"))
        bounded_text, redaction_truncated = self._bounded_utf8(redaction.text, max_bytes)
        truncated = (
            len(raw) > max_bytes
            or offset_bytes + min(len(raw), max_bytes) < metadata.byte_size
            or redaction_truncated
        )
        return TextExcerpt(
            artifact=metadata,
            text=bounded_text,
            offset_bytes=offset_bytes,
            returned_bytes=len(bounded_text.encode("utf-8")),
            truncated=truncated,
            redaction_count=redaction.replacements,
        )

    def object_count(self) -> int:
        objects = self._root / "objects"
        if not objects.exists():
            return 0
        return sum(1 for path in objects.rglob("*") if path.is_file())

    def _object_path(self, digest: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ArtifactCorruptError("invalid artifact digest")
        candidate = (self._root / "objects" / digest[:2] / digest).resolve()
        if not candidate.is_relative_to(self._root):
            raise ArtifactCorruptError("artifact path escaped the object store")
        return candidate

    def _write_object(self, object_path: Path, content: bytes) -> None:
        if object_path.exists():
            return
        object_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_directory = (self._root / "temporary").resolve()
        if not temporary_directory.is_relative_to(self._root):
            raise ArtifactCorruptError("temporary path escaped the object store")
        temporary_directory.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(dir=temporary_directory)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as temporary_file:
                temporary_file.write(content)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, object_path)
        finally:
            temporary_path.unlink(missing_ok=True)

    @staticmethod
    def _is_text(media_type: str) -> bool:
        normalized = media_type.partition(";")[0].strip().lower()
        return normalized.startswith("text/") or normalized in _TEXT_MEDIA_TYPES

    @staticmethod
    def _metadata(row: ArtifactRow) -> ArtifactMetadata:
        return ArtifactMetadata(
            artifact_id=ArtifactId(root=row.artifact_id),
            sha256=row.sha256,
            byte_size=row.byte_size,
            media_type=row.media_type,
            sensitivity=Sensitivity(row.sensitivity),
            created_at=datetime.fromisoformat(row.created_at),
        )

    @staticmethod
    def _bounded_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
        encoded = text.encode("utf-8")
        if len(encoded) <= max_bytes:
            return text, False
        return encoded[:max_bytes].decode("utf-8", errors="ignore"), True
