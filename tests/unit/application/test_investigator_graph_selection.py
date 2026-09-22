from datetime import UTC, datetime
from typing import cast

import pytest

from systemsense.application.investigator import Investigator
from systemsense.domain.ids import EntityId, EvidenceId, JsonValue
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.retrieval import EvidenceRelationRepository
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.storage.sqlite_store import SQLiteStore


def _context() -> EvidenceContext:
    observed_at = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
    return EvidenceContext(
        evidence_id=EvidenceId(root="ev_11111111111111111111111111111111"),
        observed_at=observed_at,
        captured_at=observed_at,
        probe_id="application.snapshot",
        summary="Process and service state",
        facts={
            "processes": [
                {
                    "pid": 4242,
                    "name": "service-host.exe",
                    "creation_time": "2026-09-22T11:59:00+00:00",
                    "state": "running",
                }
            ],
            "services": [{"name": "AudioSrv", "state": "running"}],
            "value": 0,
            "disk_index": 0,
        },
        status=EvidenceContextStatus.OBSERVED,
    )


def _relation(index: int, metadata: dict[str, JsonValue]) -> EvidenceRelation:
    return EvidenceRelation(
        relation_id=f"rel_{index:032x}",
        source_entity_id=EntityId(root=f"entity_{index:032x}"),
        target_entity_id=EntityId(root=f"entity_{index + 100:032x}"),
        relationship=RelationKind.RUNS_IN_PROCESS,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(EvidenceId(root="ev_11111111111111111111111111111111"),),
        version_metadata=metadata,
    )


def test_identity_values_are_field_aware_and_ignore_common_state_scalars() -> None:
    identities = Investigator._identity_values(  # pyright: ignore[reportPrivateUsage]
        _context().facts
    )

    assert "process_id:4242" in identities
    assert "process_name:service-host.exe" in identities
    assert "service_name:audiosrv" in identities
    assert "disk_index:0" in identities
    assert all("running" not in item for item in identities)
    assert "number:0" not in identities


def test_relationship_selection_prefers_real_identity_and_reports_omission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoys = tuple(_relation(index, {"state": "running"}) for index in range(1, 65))
    true_identity = _relation(999, {"pid": 4242, "target_process_name": "service-host.exe"})

    def relations(
        _repository: EvidenceRelationRepository,
        *,
        limit: int = 1000,
        evidence_ids: tuple[EvidenceId, ...] | None = None,
    ) -> tuple[EvidenceRelation, ...]:
        del limit, evidence_ids
        return (*decoys, true_identity)

    monkeypatch.setattr(EvidenceRelationRepository, "relations", relations)
    investigator = object.__new__(Investigator)
    investigator.store = cast("SQLiteStore", object())

    selection = investigator._relationships(  # pyright: ignore[reportPrivateUsage]
        (_context(),)
    )

    assert true_identity in selection.relationships
    assert len(selection.relationships) == 64
    assert any("omitted 1" in item for item in selection.context[0].limitations)
    assert any("does not establish causality" in item for item in selection.context[0].limitations)
