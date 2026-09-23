"""Training export admits independently reviewed, persisted decisions only."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from systemsense.decision.contracts import DecisionRequest, ProbeCapability
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.evaluation import training_admission
from systemsense.evaluation.attention_labels import (
    AttentionSnapshot,
    ExpertAttentionLabel,
    ProbeOutcome,
    RedactionAttestation,
    RegisteredProbe,
    SplitKeys,
    candidate_catalog_sha256,
)
from systemsense.evaluation.attention_replay import (
    candidate_context_sha256,
    visible_evidence_sha256,
)
from systemsense.evaluation.training_admission import (
    ExportAuthorization,
    PrivacyReviewReceipt,
    ReviewerAuthorization,
    TrainingExport,
    prepare_training_export,
    training_content_sha256,
    verified_export_payloads,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.decision_snapshots import (
    DecisionSnapshot,
    DecisionSnapshotRepository,
    ProbeManifestRef,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _manifest(probe_id: str) -> ProbeManifest:
    return ProbeManifest(
        probe_id=probe_id,
        version=1,
        implementation_id=f"builtin.{probe_id}",
        question=f"Inspect {probe_id}",
        safety=ProbeSafety(
            safety_class=SafetyClass.R1,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
        ),
        input_model="ProbeV1",
        limits=ProbeLimits(timeout_ms=100, max_output_bytes=1024, max_records=10),
        category="windows",
    )


def _fixture(
    store: SQLiteStore,
    *,
    symptom: str = "connection failure",
    late_baseline: bool = False,
    freeze_missing: bool = False,
) -> tuple[ExpertAttentionLabel, DecisionSnapshot, dict[str, ProbeManifest]]:
    case_id = CaseId.new()
    baseline_id = EvidenceId.new()
    now = datetime.now(UTC)
    baseline_at = now - timedelta(microseconds=500) if late_baseline else now
    manifests = {
        probe_id: _manifest(probe_id) for probe_id in ("windows.eventlog", "windows.proxy")
    }
    store.create_case(
        case_id=str(case_id),
        kind="incident",
        symptom=symptom,
        created_at=(now - timedelta(hours=1)).isoformat(),
        state_version=2,
    )
    baseline = CoverageRecord(
        evidence_id=baseline_id,
        case_id=case_id,
        category="network",
        status=CoverageStatus.COVERED,
        captured_at=baseline_at,
        reason="baseline coverage",
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(baseline_id),
            source_id=stable_source_id("systemsense.coverage", {"category": "network"}),
            record_json=baseline.model_dump_json(),
            observed_at=baseline_at.isoformat(),
            captured_at=baseline_at.isoformat(),
            execution_id=None,
            time_basis="probe_attempt_finish",
            time_quality="exact",
        )
    request_frozen_at = now - timedelta(milliseconds=1) if late_baseline else datetime.now(UTC)
    request = DecisionRequest(
        case_id=case_id,
        state_version=2,
        correlation_id="training_test",
        deadline_at=now + timedelta(minutes=3),
        symptom=symptom,
        evidence_ids=(baseline_id,),
        available_probes=tuple(
            ProbeCapability(
                probe_id=probe_id,
                description=f"Inspect {probe_id}",
                cost_ms=10,
                resource_class=ResourceClass.CPU,
            )
            for probe_id in manifests
        ),
        budget_ms=100,
        max_probes=2,
    )
    repository = DecisionSnapshotRepository(store)
    frozen = repository.capture(
        request,
        probe_manifest_refs=tuple(
            ProbeManifestRef.from_manifest(probe_id, manifest)
            for probe_id, manifest in manifests.items()
        ),
        request_frozen_at=None if freeze_missing else request_frozen_at,
    )
    outcome_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    instant = frozen.captured_at.isoformat()
    outcome_source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "windows.eventlog", "probe_version": 1}
    )
    outcome_record = EvidenceRecord(
        evidence_id=outcome_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=frozen.captured_at,
        captured_at=frozen.captured_at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=outcome_source_id,
            locator={"probe_id": "windows.eventlog"},
        ),
        collector=CollectorReference(id="windows.eventlog", version=1, execution_id=execution_id),
        summary="Relevant event observed",
        facts=(EvidenceFact(name="event_id", value=42),),
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="windows.eventlog",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=instant,
            finished_at=instant,
            state_version=3,
        )
        transaction.link_decision_execution(
            snapshot_id=frozen.snapshot_id,
            execution_id=str(execution_id),
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(outcome_id),
            source_id=outcome_source_id,
            record_json=outcome_record.model_dump_json(),
            observed_at=instant,
            captured_at=instant,
            execution_id=str(execution_id),
            time_basis="collector_observed",
            time_quality="exact",
        )
    candidates = tuple(RegisteredProbe.from_manifest(item) for item in manifests.values())
    label = ExpertAttentionLabel(
        schema_version=2,
        label_id="label_" + "1" * 32,
        split_keys=SplitKeys(
            case_id=case_id,
            machine_key="a" * 64,
            fault_family="connectivity",
        ),
        snapshot=AttentionSnapshot(
            state_version=request.state_version,
            case_opened_at=now - timedelta(hours=1),
            captured_at=frozen.captured_at,
            evidence_ids=request.evidence_ids,
            candidate_probes=candidates,
            visible_evidence_sha256=visible_evidence_sha256(request),
            candidate_catalog_sha256=candidate_catalog_sha256(candidates),
            candidate_context_sha256=candidate_context_sha256(request),
        ),
        useful_probe_ids=("windows.eventlog",),
        negative_probe_ids=(),
        abstain=False,
        outcomes=(
            ProbeOutcome(
                probe_id="windows.eventlog",
                execution_id=execution_id,
                started_at=frozen.captured_at,
                finished_at=frozen.captured_at,
                evidence_ids=(outcome_id,),
                result="informative",
            ),
        ),
        reviewer_id="reviewer_01",
        reviewed_at=frozen.captured_at,
        label_origin="human_expert",
        source_kind="recorded",
        synthetic=False,
        redaction=RedactionAttestation(
            method="identifiers_only",
            checked_by="reviewer_01",
            checked_at=frozen.captured_at,
        ),
    )
    return label, frozen, manifests


class _Authorizer:
    def __init__(self) -> None:
        self.review_calls = 0
        self.export_calls = 0
        self.privacy_payloads: list[str] = []
        self.consent_content_digests: list[str] = []

    def verify_reviewer(
        self, *, label: ExpertAttentionLabel, label_sha256: str
    ) -> ReviewerAuthorization:
        self.review_calls += 1
        return ReviewerAuthorization(
            label_id=label.label_id,
            reviewer_id=label.reviewer_id,
            label_sha256=label_sha256,
            authorization_id="review_verified_01",
        )

    def verify_export(
        self, *, case_id: str, snapshot_id: str, training_content_sha256: str
    ) -> ExportAuthorization:
        self.export_calls += 1
        self.consent_content_digests.append(training_content_sha256)
        return ExportAuthorization(
            case_id=case_id,
            snapshot_id=snapshot_id,
            training_content_sha256=training_content_sha256,
            authorization_id="consent_verified_01",
            purpose="local_model_training",
            retention_until=datetime.now(UTC) + timedelta(days=30),
        )

    def review_privacy(
        self, *, payload_json: str, payload_sha256: str
    ) -> PrivacyReviewReceipt | None:
        self.privacy_payloads.append(payload_json)
        return PrivacyReviewReceipt(
            payload_sha256=payload_sha256,
            reviewer_id="privacy_reviewer_01",
            reviewed_at=datetime.now(UTC),
            review_id="privacy_review_01",
        )


def _admit(
    store: SQLiteStore,
    label: ExpertAttentionLabel,
    snapshot: DecisionSnapshot,
    manifests: dict[str, ProbeManifest],
    authorizer: _Authorizer | None,
) -> TrainingExport:
    return prepare_training_export(
        splits={"train": (label,)},
        snapshot_ids={label.label_id: snapshot.snapshot_id},
        repository=DecisionSnapshotRepository(store),
        trusted_catalog=manifests,
        reviewer_authorizer=authorizer,
        export_authorizer=authorizer,
        privacy_reviewer=authorizer,
    )


def test_admits_only_frozen_laya_input_and_masks_unknown_candidates(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        authorizer = _Authorizer()
        export = _admit(store, label, snapshot, manifests, authorizer)

    example = export.examples[0]
    assert example.snapshot_id == snapshot.snapshot_id
    assert example.case_id == snapshot.case_id
    assert example.request_sha256 == snapshot.request_sha256
    assert example.input.state == snapshot.laya_state
    assert example.input.evidence == snapshot.laya_evidence
    assert example.input.candidates == snapshot.laya_candidates
    assert [(item.probe_id, item.utility, item.loss_mask) for item in example.targets] == [
        ("windows.eventlog", "useful", True),
        ("windows.proxy", "unknown", False),
    ]
    assert example.abstain_target is False
    assert example.input_visibility == "preworker_only"
    assert example.trainable is False
    assert export.training_admissible is False
    assert "execution_id" not in str(example.input.model_dump(mode="json"))
    assert authorizer.privacy_payloads == [example.model_dump_json()]
    assert (
        export.privacy_reviews[0].payload_sha256
        == sha256(example.model_dump_json().encode("utf-8")).hexdigest()
    )
    assert example.training_content_sha256 == authorizer.consent_content_digests[0]
    assert example.training_content_sha256 == training_content_sha256(example)
    assert example.training_content_sha256 != export.privacy_reviews[0].payload_sha256
    assert verified_export_payloads(export) == (example.model_dump_json(),)


def test_default_admission_denies_missing_independent_authorizers(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        with pytest.raises(PermissionError, match="reviewer authorization"):
            _admit(store, label, snapshot, manifests, None)


def test_legacy_snapshot_without_request_freeze_is_not_admitted(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store, freeze_missing=True)
        assert snapshot.request_frozen_at is None
        with pytest.raises(ValueError, match="request freeze time"):
            _admit(store, label, snapshot, manifests, _Authorizer())


def test_baseline_evidence_captured_between_freeze_and_snapshot_is_not_admitted(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store, late_baseline=True)
        assert snapshot.request_frozen_at is not None
        baseline = store.evidence(
            case_id=snapshot.case_id, evidence_id=str(label.snapshot.evidence_ids[0])
        )
        assert baseline is not None
        assert snapshot.request_frozen_at < datetime.fromisoformat(baseline.captured_at)
        assert datetime.fromisoformat(baseline.captured_at) < snapshot.captured_at
        with pytest.raises(ValueError, match="after request freeze"):
            _admit(store, label, snapshot, manifests, _Authorizer())


def test_rejects_unlinked_probe_outcome_even_if_persisted(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        unlinked_execution_id = ExecutionId.new()
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(unlinked_execution_id),
                case_id=str(label.split_keys.case_id),
                probe_id="windows.eventlog",
                probe_version=1,
                status="ok",
                parameters_json="{}",
                started_at=snapshot.captured_at.isoformat(),
                finished_at=snapshot.captured_at.isoformat(),
                state_version=3,
            )
        unlinked = label.model_copy(
            update={
                "outcomes": (
                    label.outcomes[0].model_copy(update={"execution_id": unlinked_execution_id}),
                )
            }
        )
        with pytest.raises(ValueError, match="linked execution"):
            _admit(store, unlinked, snapshot, manifests, _Authorizer())


def test_rejects_outcome_evidence_not_bound_to_execution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        store.connection.execute(
            "UPDATE evidence SET execution_id = NULL WHERE evidence_id = ?",
            (str(label.outcomes[0].evidence_ids[0]),),
        )
        with pytest.raises(ValueError, match="outcome evidence"):
            _admit(store, label, snapshot, manifests, _Authorizer())


def test_rejects_malformed_outcome_record_even_when_database_join_matches(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        store.connection.execute(
            "UPDATE evidence SET record_json = ? WHERE evidence_id = ?",
            ('{"kind":"fabricated"}', str(label.outcomes[0].evidence_ids[0])),
        )
        with pytest.raises(ValueError, match="typed outcome evidence"):
            _admit(store, label, snapshot, manifests, _Authorizer())


def test_rejects_typed_outcome_with_wrong_collector_provenance(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        evidence_id = str(label.outcomes[0].evidence_ids[0])
        row = store.evidence(case_id=str(label.split_keys.case_id), evidence_id=evidence_id)
        assert row is not None
        record = json.loads(row.record_json)
        record["collector"]["execution_id"] = str(ExecutionId.new())
        store.connection.execute(
            "UPDATE evidence SET record_json = ? WHERE evidence_id = ?",
            (json.dumps(record), evidence_id),
        )
        with pytest.raises(ValueError, match="collector provenance"):
            _admit(store, label, snapshot, manifests, _Authorizer())


def test_rejects_mismatched_frozen_snapshot_and_catalog(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        mismatched = label.model_copy(
            update={
                "snapshot": label.snapshot.model_copy(update={"candidate_context_sha256": "0" * 64})
            }
        )
        with pytest.raises(ValueError, match="candidate context"):
            _admit(store, mismatched, snapshot, manifests, _Authorizer())


def test_rejects_missing_export_consent(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        authorizer = _Authorizer()
        with pytest.raises(PermissionError, match="export authorization"):
            prepare_training_export(
                splits={"train": (label,)},
                snapshot_ids={label.label_id: snapshot.snapshot_id},
                repository=DecisionSnapshotRepository(store),
                trusted_catalog=manifests,
                reviewer_authorizer=authorizer,
            )
        assert authorizer.review_calls == 0


def test_rejects_missing_exact_plaintext_privacy_reviewer(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        authorizer = _Authorizer()
        with pytest.raises(PermissionError, match="privacy review"):
            prepare_training_export(
                splits={"train": (label,)},
                snapshot_ids={label.label_id: snapshot.snapshot_id},
                repository=DecisionSnapshotRepository(store),
                trusted_catalog=manifests,
                reviewer_authorizer=authorizer,
                export_authorizer=authorizer,
            )


def test_exact_privacy_review_receives_secret_path_and_may_deny(tmp_path: Path) -> None:
    class DenyPath(_Authorizer):
        def review_privacy(
            self, *, payload_json: str, payload_sha256: str
        ) -> PrivacyReviewReceipt | None:
            self.privacy_payloads.append(payload_json)
            assert (
                json.loads(payload_json)["input"]["state"]["symptom"]
                == "app opening C:\\Users\\brenn\\Private\\secret.txt is slow"
            )
            return None

    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(
            store, symptom="app opening C:\\Users\\brenn\\Private\\secret.txt is slow"
        )
        reviewer = DenyPath()
        with pytest.raises(PermissionError, match="privacy review"):
            _admit(store, label, snapshot, manifests, reviewer)
        assert reviewer.privacy_payloads


def test_rejects_privacy_review_receipt_for_different_plaintext(tmp_path: Path) -> None:
    class WrongPrivacy(_Authorizer):
        def review_privacy(
            self, *, payload_json: str, payload_sha256: str
        ) -> PrivacyReviewReceipt | None:
            return PrivacyReviewReceipt(
                payload_sha256="0" * 64,
                reviewer_id="privacy_reviewer_01",
                reviewed_at=datetime.now(UTC),
                review_id="wrong_payload",
            )

    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        with pytest.raises(PermissionError, match="privacy review"):
            _admit(store, label, snapshot, manifests, WrongPrivacy())


def test_rejects_cross_split_machine_leakage(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        other = label.model_copy(update={"label_id": "label_" + "2" * 32})
        with pytest.raises(ValueError, match=r"label ID|group crosses splits"):
            prepare_training_export(
                splits={"train": (label,), "heldout": (other,)},
                snapshot_ids={
                    label.label_id: snapshot.snapshot_id,
                    other.label_id: snapshot.snapshot_id,
                },
                repository=DecisionSnapshotRepository(store),
                trusted_catalog=manifests,
                reviewer_authorizer=_Authorizer(),
                export_authorizer=_Authorizer(),
                privacy_reviewer=_Authorizer(),
            )


def test_rejects_model_copy_forged_unobserved_negative(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        forged = label.model_copy(update={"negative_probe_ids": ("windows.proxy",)})
        with pytest.raises(ValueError, match=r"negative.*observed.*uninformative"):
            _admit(store, forged, snapshot, manifests, _Authorizer())


def test_rejects_model_copy_forged_catalog_digest(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        forged = label.model_copy(
            update={
                "snapshot": label.snapshot.model_copy(update={"candidate_catalog_sha256": "0" * 64})
            }
        )
        with pytest.raises(ValueError, match="candidate catalog digest"):
            _admit(store, forged, snapshot, manifests, _Authorizer())


def test_rejects_reviewer_receipt_for_another_label(tmp_path: Path) -> None:
    class WrongReview(_Authorizer):
        def verify_reviewer(
            self, *, label: ExpertAttentionLabel, label_sha256: str
        ) -> ReviewerAuthorization:
            return ReviewerAuthorization(
                label_id="label_" + "2" * 32,
                reviewer_id=label.reviewer_id,
                label_sha256=label_sha256,
                authorization_id="wrong_review",
            )

    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        with pytest.raises(PermissionError, match="reviewer authorization"):
            _admit(store, label, snapshot, manifests, WrongReview())


def test_rejects_consent_receipt_for_another_payload(tmp_path: Path) -> None:
    class WrongConsent(_Authorizer):
        def verify_export(
            self, *, case_id: str, snapshot_id: str, training_content_sha256: str
        ) -> ExportAuthorization:
            return ExportAuthorization(
                case_id=case_id,
                snapshot_id=snapshot_id,
                training_content_sha256="0" * 64,
                authorization_id="wrong_consent",
                purpose="local_model_training",
                retention_until=datetime.now(UTC) + timedelta(days=30),
            )

    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        with pytest.raises(PermissionError, match="export authorization"):
            _admit(store, label, snapshot, manifests, WrongConsent())


def test_rejects_copied_consent_receipt_for_other_purpose(tmp_path: Path) -> None:
    class WrongPurpose(_Authorizer):
        def verify_export(
            self, *, case_id: str, snapshot_id: str, training_content_sha256: str
        ) -> ExportAuthorization:
            valid = super().verify_export(
                case_id=case_id,
                snapshot_id=snapshot_id,
                training_content_sha256=training_content_sha256,
            )
            return valid.model_copy(update={"purpose": "remote_marketing"})

    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        with pytest.raises(PermissionError, match="export authorization"):
            _admit(store, label, snapshot, manifests, WrongPurpose())


def test_admits_reviewed_abstention_without_mislabelling_candidates(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        abstention = label.model_copy(
            update={
                "useful_probe_ids": (),
                "negative_probe_ids": (),
                "outcomes": (),
                "abstain": True,
            }
        )
        export = _admit(store, abstention, snapshot, manifests, _Authorizer())

    example = export.examples[0]
    assert example.abstain_target is True
    assert all(item.utility == "unknown" and not item.loss_mask for item in example.targets)


def test_payload_readback_rejects_mutation_after_privacy_review(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        export = _admit(store, label, snapshot, manifests, _Authorizer())

    changed = export.examples[0].model_copy(update={"reviewer_authorization_id": "spoofed"})
    altered_export = export.model_copy(update={"examples": (changed,)})
    with pytest.raises(ValueError, match="changed after privacy review"):
        verified_export_payloads(altered_export)


def test_readback_rejects_changed_content_even_if_privacy_hash_is_swapped(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        export = _admit(store, label, snapshot, manifests, _Authorizer())

    changed = export.examples[0].model_copy(update={"case_id": str(CaseId.new())})
    changed_digest = sha256(changed.model_dump_json().encode("utf-8")).hexdigest()
    altered_export = export.model_copy(
        update={
            "examples": (changed,),
            "privacy_reviews": (
                export.privacy_reviews[0].model_copy(update={"payload_sha256": changed_digest}),
            ),
        }
    )
    with pytest.raises(ValueError, match="training content changed after consent"):
        verified_export_payloads(altered_export)


def test_readback_rejects_swapped_system_state_even_if_privacy_hash_is_swapped(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        export = _admit(store, label, snapshot, manifests, _Authorizer())

    example = export.examples[0]
    changed_input = example.input.model_copy(
        update={"state": {**example.input.state, "symptom": "different fault"}}
    )
    changed = example.model_copy(update={"input": changed_input})
    changed_digest = sha256(changed.model_dump_json().encode("utf-8")).hexdigest()
    altered_export = export.model_copy(
        update={
            "examples": (changed,),
            "privacy_reviews": (
                export.privacy_reviews[0].model_copy(update={"payload_sha256": changed_digest}),
            ),
        }
    )
    with pytest.raises(ValueError, match="training content changed after consent"):
        verified_export_payloads(altered_export)


def test_privacy_review_must_follow_expert_review(tmp_path: Path) -> None:
    class PrematurePrivacy(_Authorizer):
        def review_privacy(
            self, *, payload_json: str, payload_sha256: str
        ) -> PrivacyReviewReceipt | None:
            return PrivacyReviewReceipt(
                payload_sha256=payload_sha256,
                reviewer_id="privacy_reviewer_01",
                reviewed_at=snapshot.captured_at,
                review_id="premature_privacy",
            )

    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        later_label = label.model_copy(
            update={"reviewed_at": snapshot.captured_at + timedelta(milliseconds=1)}
        )
        with pytest.raises(PermissionError, match="privacy review"):
            _admit(store, later_label, snapshot, manifests, PrematurePrivacy())


def test_readback_denies_plaintext_at_retention_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "data.db") as store:
        label, snapshot, manifests = _fixture(store)
        export = _admit(store, label, snapshot, manifests, _Authorizer())

    expiry = export.examples[0].retention_until

    class BeforeExpiry:
        @staticmethod
        def now(_timezone: object) -> datetime:
            return expiry - timedelta(microseconds=1)

    class AtExpiry:
        @staticmethod
        def now(_timezone: object) -> datetime:
            return expiry

    monkeypatch.setattr(training_admission, "datetime", BeforeExpiry)
    assert verified_export_payloads(export)
    monkeypatch.setattr(training_admission, "datetime", AtExpiry)
    with pytest.raises(PermissionError, match="retention expired"):
        verified_export_payloads(export)
