"""Global split custody remains metadata-only and never admits training."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.domain.ids import CaseId
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.evaluation.attention_labels import (
    AttentionSnapshot,
    ExpertAttentionLabel,
    RedactionAttestation,
    RegisteredProbe,
    SplitKeys,
    candidate_catalog_sha256,
)
from systemsense.evaluation.split_ledger import SplitGroupLedger

_AT = datetime(2026, 9, 23, tzinfo=UTC)


def _catalog() -> dict[str, ProbeManifest]:
    manifest = ProbeManifest(
        probe_id="network.adapter",
        version=1,
        implementation_id="builtin.network.adapter",
        question="Inspect network adapter state",
        safety=ProbeSafety(
            safety_class=SafetyClass.R1,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
        ),
        input_model="ProbeV1",
        limits=ProbeLimits(timeout_ms=100, max_output_bytes=1024, max_records=10),
        category="windows",
    )
    return {manifest.probe_id: manifest}


def _label(
    number: int,
    *,
    machine: int | None = None,
    family: str | None = None,
    application: int | None = None,
    version: str | None = None,
) -> ExpertAttentionLabel:
    candidate = RegisteredProbe.from_manifest(_catalog()["network.adapter"])
    reviewer = "reviewer_01"
    return ExpertAttentionLabel(
        schema_version=2,
        label_id=f"label_{number:032x}",
        split_keys=SplitKeys(
            case_id=CaseId(f"case_{number:032x}"),
            machine_key=f"{machine if machine is not None else number:064x}",
            application_key=f"{application:064x}" if application is not None else None,
            application_version=version,
            fault_family=family or f"family_{number}",
        ),
        snapshot=AttentionSnapshot(
            state_version=1,
            case_opened_at=_AT - timedelta(minutes=1),
            captured_at=_AT,
            evidence_ids=(),
            candidate_probes=(candidate,),
            visible_evidence_sha256="a" * 64,
            candidate_catalog_sha256=candidate_catalog_sha256((candidate,)),
            candidate_context_sha256="b" * 64,
        ),
        useful_probe_ids=(),
        negative_probe_ids=(),
        abstain=True,
        outcomes=(),
        reviewer_id=reviewer,
        reviewed_at=_AT,
        label_origin="human_expert",
        source_kind="recorded",
        synthetic=False,
        redaction=RedactionAttestation(
            method="identifiers_only", checked_by=reviewer, checked_at=_AT
        ),
    )


def test_persists_idempotent_group_assignments_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "splits.db"
    label = _label(1)
    with SplitGroupLedger(path, corpus_id="pilot_2026") as ledger:
        first = ledger.admit({"train": (label,)}, trusted_catalog=_catalog())
        assert first.total_labels == 1
        assert first.split_counts == {"train": 1}
        assert first.training_admissible is False

    with SplitGroupLedger(path, corpus_id="pilot_2026") as ledger:
        repeated = ledger.admit({"train": (label,)}, trusted_catalog=_catalog())
        assert repeated.total_labels == 1
        assert repeated.manifest_sha256 == first.manifest_sha256


def test_pages_past_500_without_losing_global_split_group_check(tmp_path: Path) -> None:
    path = tmp_path / "splits.db"
    first_shard = tuple(_label(index) for index in range(1, 501))
    with SplitGroupLedger(path, corpus_id="large_pilot") as ledger:
        assert ledger.admit({"train": first_shard}, trusted_catalog=_catalog()).total_labels == 500

    conflicting = _label(501, machine=1)
    with SplitGroupLedger(path, corpus_id="large_pilot") as ledger:
        before = ledger.manifest()
        with pytest.raises(ValueError, match="machine group crosses split shards"):
            ledger.admit({"heldout": (conflicting,)}, trusted_catalog=_catalog())
        assert ledger.manifest() == before
        after = ledger.admit({"heldout": (_label(501),)}, trusted_catalog=_catalog())
        assert after.total_labels == 501
        assert after.split_counts == {"train": 500, "heldout": 1}
        assert after.training_admissible is False


@pytest.mark.parametrize("shared_group", ["case", "fault_family", "application"])
def test_rejects_cross_shard_group_leakage_after_reopen(tmp_path: Path, shared_group: str) -> None:
    path = tmp_path / "splits.db"
    first = _label(1, application=10, version="1.0")
    second = _label(2, application=11, version="1.0")
    if shared_group == "case":
        second = second.model_copy(
            update={
                "split_keys": second.split_keys.model_copy(
                    update={"case_id": first.split_keys.case_id}
                )
            }
        )
    elif shared_group == "fault_family":
        second = second.model_copy(
            update={
                "split_keys": second.split_keys.model_copy(
                    update={"fault_family": first.split_keys.fault_family}
                )
            }
        )
    else:
        second = second.model_copy(
            update={
                "split_keys": second.split_keys.model_copy(
                    update={"application_key": first.split_keys.application_key}
                )
            }
        )
    with SplitGroupLedger(path, corpus_id="pilot_2026") as ledger:
        ledger.admit({"train": (first,)}, trusted_catalog=_catalog())
    with SplitGroupLedger(path, corpus_id="pilot_2026") as ledger:
        before = ledger.manifest()
        with pytest.raises(ValueError, match=f"{shared_group} group crosses split shards"):
            ledger.admit({"heldout": (second,)}, trusted_catalog=_catalog())
        assert ledger.manifest() == before


def test_same_label_id_with_altered_review_record_is_not_idempotent(tmp_path: Path) -> None:
    label = _label(1)
    altered = label.model_copy(update={"reviewed_at": label.reviewed_at + timedelta(seconds=1)})
    with SplitGroupLedger(tmp_path / "splits.db", corpus_id="pilot_2026") as ledger:
        before = ledger.admit({"train": (label,)}, trusted_catalog=_catalog())
        with pytest.raises(ValueError, match="existing label changed"):
            ledger.admit({"train": (altered,)}, trusted_catalog=_catalog())
        assert ledger.manifest() == before


def test_same_application_different_version_is_kept_in_one_split(tmp_path: Path) -> None:
    with SplitGroupLedger(tmp_path / "splits.db", corpus_id="pilot_2026") as ledger:
        ledger.admit(
            {"train": (_label(1, application=10, version="1.0"),)},
            trusted_catalog=_catalog(),
        )
        with pytest.raises(ValueError, match="application group crosses split shards"):
            ledger.admit(
                {"heldout": (_label(2, application=10, version="2.0"),)},
                trusted_catalog=_catalog(),
            )
        result = ledger.admit(
            {"heldout": (_label(2, application=11, version="1.0"),)},
            trusted_catalog=_catalog(),
        )
        assert result.split_counts == {"train": 1, "heldout": 1}


def test_manifest_digest_can_be_checked_after_reopen(tmp_path: Path) -> None:
    path = tmp_path / "splits.db"
    with SplitGroupLedger(path, corpus_id="pilot_2026") as ledger:
        expected = ledger.admit({"train": (_label(1),)}, trusted_catalog=_catalog())
    with SplitGroupLedger(path, corpus_id="pilot_2026") as ledger:
        ledger.verify_manifest(expected_sha256=expected.manifest_sha256)
        with pytest.raises(ValueError, match="manifest identity"):
            ledger.verify_manifest(expected_sha256="0" * 64)


def test_rejects_other_corpus_and_unsupported_storage_version(tmp_path: Path) -> None:
    path = tmp_path / "splits.db"
    with SplitGroupLedger(path, corpus_id="pilot_2026"):
        pass
    with pytest.raises(ValueError, match="another corpus"):
        SplitGroupLedger(path, corpus_id="other_2026")
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=2")
    with pytest.raises(ValueError, match="schema is unsupported"):
        SplitGroupLedger(path, corpus_id="pilot_2026")


def test_persists_digests_not_reviewer_or_fault_family_text(tmp_path: Path) -> None:
    path = tmp_path / "splits.db"
    with SplitGroupLedger(path, corpus_id="pilot_2026") as ledger:
        ledger.admit(
            {"train": (_label(1, family="sensitivefaultfamily"),)},
            trusted_catalog=_catalog(),
        )
    content = path.read_bytes()
    assert b"sensitivefaultfamily" not in content
    assert b"reviewer_01" not in content
