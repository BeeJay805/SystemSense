from pathlib import Path

import pytest

from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import CaseId
from systemsense.storage.artifact_store import (
    ArtifactAccessDenied,
    ArtifactStore,
    BinaryArtifactError,
)
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = "2026-07-30T12:00:00+00:00"
_CASE_ONE = CaseId(root="case_0123456789abcdef0123456789abcdef")
_CASE_TWO = CaseId(root="case_fedcba9876543210fedcba9876543210")


def _seed_cases(store: SQLiteStore) -> None:
    for case_id in (_CASE_ONE, _CASE_TWO):
        store.create_case(
            case_id=str(case_id),
            kind="application",
            symptom="App fails during startup",
            created_at=_NOW,
        )


def test_identical_content_deduplicates_but_links_to_each_case(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_cases(store)
        artifacts = ArtifactStore(tmp_path / "artifacts", store)

        first = artifacts.put(
            case_id=_CASE_ONE,
            content=b"Faulting module: example.dll",
            media_type="text/plain",
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        second = artifacts.put(
            case_id=_CASE_TWO,
            content=b"Faulting module: example.dll",
            media_type="text/plain",
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )

        assert first.artifact_id == second.artifact_id
        assert first.sha256 == second.sha256
        assert artifacts.object_count() == 1
        assert (
            artifacts.get_text_excerpt(
                case_id=_CASE_ONE,
                artifact_id=first.artifact_id,
            ).text
            == "Faulting module: example.dll"
        )
        assert (
            artifacts.get_text_excerpt(
                case_id=_CASE_TWO,
                artifact_id=second.artifact_id,
            ).text
            == "Faulting module: example.dll"
        )


def test_retrieval_requires_case_artifact_relation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_cases(store)
        artifacts = ArtifactStore(tmp_path / "artifacts", store)
        stored = artifacts.put(
            case_id=_CASE_ONE,
            content=b"Only case one may read this",
            media_type="text/plain",
            sensitivity=Sensitivity.SENSITIVE,
        )

        with pytest.raises(ArtifactAccessDenied):
            artifacts.get_text_excerpt(
                case_id=_CASE_TWO,
                artifact_id=stored.artifact_id,
            )


def test_binary_artifact_is_never_returned_as_an_excerpt(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_cases(store)
        artifacts = ArtifactStore(tmp_path / "artifacts", store)
        stored = artifacts.put(
            case_id=_CASE_ONE,
            content=b"\x00\x01\x02\xff",
            media_type="application/octet-stream",
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )

        with pytest.raises(BinaryArtifactError):
            artifacts.get_text_excerpt(
                case_id=_CASE_ONE,
                artifact_id=stored.artifact_id,
            )


def test_excerpt_is_redacted_and_byte_bounded(tmp_path: Path) -> None:
    content = (
        b"API_TOKEN=super-secret-value "
        + b"x" * 200
        + b" https://user:pass@example.test/private?token=secret"
    )
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_cases(store)
        artifacts = ArtifactStore(tmp_path / "artifacts", store)
        stored = artifacts.put(
            case_id=_CASE_ONE,
            content=content,
            media_type="text/plain",
            sensitivity=Sensitivity.SENSITIVE,
        )

        excerpt = artifacts.get_text_excerpt(
            case_id=_CASE_ONE,
            artifact_id=stored.artifact_id,
            max_bytes=64,
        )

    assert len(excerpt.text.encode("utf-8")) <= 64
    assert "super-secret-value" not in excerpt.text
    assert "<redacted-secret>" in excerpt.text
    assert excerpt.truncated
