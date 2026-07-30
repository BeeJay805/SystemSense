import inspect
from pathlib import Path

import pytest
from pydantic import ValidationError

from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import ArtifactId, CaseId
from systemsense.storage.artifact_store import ArtifactAccessDenied, ArtifactStore
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = "2026-07-30T12:00:00+00:00"
_CASE_ONE = CaseId(root="case_0123456789abcdef0123456789abcdef")
_CASE_TWO = CaseId(root="case_fedcba9876543210fedcba9876543210")


def test_artifact_ids_cannot_encode_path_traversal() -> None:
    with pytest.raises(ValidationError):
        ArtifactId.model_validate("artifact_../../windows/system32")


def test_artifact_api_has_no_caller_supplied_path_surface() -> None:
    forbidden = {"path", "filename", "url", "uri"}

    assert forbidden.isdisjoint(inspect.signature(ArtifactStore.put).parameters)
    assert forbidden.isdisjoint(inspect.signature(ArtifactStore.get_text_excerpt).parameters)


def test_cross_case_lookup_cannot_reach_an_existing_object(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        for case_id in (_CASE_ONE, _CASE_TWO):
            store.create_case(
                case_id=str(case_id),
                kind="application",
                symptom="App fails during startup",
                created_at=_NOW,
            )
        artifacts = ArtifactStore(tmp_path / "artifacts", store)
        stored = artifacts.put(
            case_id=_CASE_ONE,
            content=b"private case evidence",
            media_type="text/plain",
            sensitivity=Sensitivity.SENSITIVE,
        )

        with pytest.raises(ArtifactAccessDenied):
            artifacts.get_text_excerpt(
                case_id=_CASE_TWO,
                artifact_id=stored.artifact_id,
            )
