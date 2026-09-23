"""Fail-closed admission of reviewed, persisted next-probe supervision.

This is a local preparation boundary, not an automatic training-data generator.
Callers must supply independent, on-device reviewer authentication, plaintext
privacy review, and per-case training/export consent providers. A model draft,
selected probe, fixture, or digest alone cannot authorize an example. Only the
frozen preworker Laya projection is an input feature; later
execution results are consulted solely to validate masked expert supervision.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Literal, Protocol

from pydantic import Field, ValidationError

from systemsense.domain.coverage import CoverageRecord
from systemsense.domain.evidence import EvidenceRecord, FrozenModel
from systemsense.domain.probes import ProbeManifest
from systemsense.evaluation.attention_labels import (
    ExpertAttentionLabel,
    RegisteredProbe,
    validate_group_splits,
)
from systemsense.evaluation.attention_replay import (
    candidate_context_sha256,
    visible_evidence_sha256,
)
from systemsense.storage.decision_snapshots import (
    DecisionSnapshot,
    DecisionSnapshotRepository,
)
from systemsense.storage.sqlite_store import EvidenceRow

_MAX_LABELS = 500


class ReviewerAuthorization(FrozenModel):
    """Receipt from a trusted local reviewer registry for one exact label."""

    label_id: str = Field(pattern=r"^label_[0-9a-f]{32}$")
    reviewer_id: str = Field(min_length=1, max_length=120)
    label_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_id: str = Field(min_length=1, max_length=160)


class ExportAuthorization(FrozenModel):
    """Consent for canonical training content, before receipt metadata is added."""

    case_id: str = Field(pattern=r"^case_[0-9a-f]{32}$")
    snapshot_id: str = Field(pattern=r"^decision_snapshot_[0-9a-f]{32}$")
    training_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorization_id: str = Field(min_length=1, max_length=160)
    purpose: Literal["local_model_training"]
    retention_until: datetime


class PrivacyReviewReceipt(FrozenModel):
    """On-device screening of the exact serialized example, including plaintext."""

    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    reviewed_at: datetime
    review_id: str = Field(min_length=1, max_length=160)


class ReviewerAuthorizer(Protocol):
    def verify_reviewer(
        self, *, label: ExpertAttentionLabel, label_sha256: str
    ) -> ReviewerAuthorization | None: ...


class ExportAuthorizer(Protocol):
    def verify_export(
        self, *, case_id: str, snapshot_id: str, training_content_sha256: str
    ) -> ExportAuthorization | None: ...


class PrivacyReviewer(Protocol):
    def review_privacy(
        self, *, payload_json: str, payload_sha256: str
    ) -> PrivacyReviewReceipt | None: ...


class TrainingInput(FrozenModel):
    """Pre-action projection only; no selected action or outcome is a feature."""

    state: dict[str, object]
    evidence: tuple[dict[str, str], ...]
    candidates: tuple[dict[str, str], ...]


class CandidateTarget(FrozenModel):
    probe_id: str
    utility: Literal["useful", "negative", "unknown"]
    loss_mask: bool


class TrainingExample(FrozenModel):
    schema_version: Literal[1] = 1
    label_id: str
    case_id: str
    split: str
    snapshot_id: str
    request_sha256: str
    laya_projection_sha256: str
    input: TrainingInput
    input_visibility: Literal["preworker_only"] = "preworker_only"
    trainable: Literal[False] = False
    targets: tuple[CandidateTarget, ...]
    abstain_target: bool
    training_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer_authorization_id: str
    export_authorization_id: str
    retention_until: datetime


class TrainingExport(FrozenModel):
    schema_version: Literal[1] = 1
    training_admissible: Literal[False] = False
    examples: tuple[TrainingExample, ...]
    privacy_reviews: tuple[PrivacyReviewReceipt, ...]


def _sha256(payload: object) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _training_content(
    *,
    label_id: str,
    case_id: str,
    split: str,
    snapshot_id: str,
    request_sha256: str,
    laya_projection_sha256: str,
    model_input: TrainingInput,
    input_visibility: str,
    trainable: bool,
    targets: tuple[CandidateTarget, ...],
    abstain_target: bool,
) -> dict[str, object]:
    """Canonical consent scope, excluding reviewer/consent receipt metadata."""

    return {
        "schema_version": 1,
        "label_id": label_id,
        "case_id": case_id,
        "split": split,
        "snapshot_id": snapshot_id,
        "request_sha256": request_sha256,
        "laya_projection_sha256": laya_projection_sha256,
        "input": model_input.model_dump(mode="json"),
        "input_visibility": input_visibility,
        "trainable": trainable,
        "targets": [target.model_dump(mode="json") for target in targets],
        "abstain_target": abstain_target,
    }


def training_content_sha256(example: TrainingExample) -> str:
    """Recompute the pre-receipt consent digest from an exported example."""

    return _sha256(
        _training_content(
            label_id=example.label_id,
            case_id=example.case_id,
            split=example.split,
            snapshot_id=example.snapshot_id,
            request_sha256=example.request_sha256,
            laya_projection_sha256=example.laya_projection_sha256,
            model_input=example.input,
            input_visibility=example.input_visibility,
            trainable=example.trainable,
            targets=example.targets,
            abstain_target=example.abstain_target,
        )
    )


def _utc(value: str) -> datetime:
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None or instant.utcoffset() != UTC.utcoffset(None):
        raise ValueError("persisted timestamp must be UTC")
    return instant


def _validate_typed_evidence(
    row: EvidenceRow,
    *,
    repository: DecisionSnapshotRepository,
    probe_id: str | None = None,
    probe_version: int | None = None,
    require_observation: bool = False,
) -> None:
    """Verify typed payload and duplicated row fields, not source authenticity."""

    if row.time_basis in {"unknown", "legacy_case_opened"} or row.time_quality not in {
        "exact",
        "bounded_interval",
    }:
        raise ValueError("typed outcome evidence lacks reliable collection time provenance")
    try:
        record = EvidenceRecord.model_validate_json(row.record_json)
    except ValidationError:
        record = None
    if record is not None:
        source = repository.store.connection.execute(
            "SELECT source_id FROM evidence WHERE case_id = ? AND evidence_id = ?",
            (row.case_id, row.evidence_id),
        ).fetchone()
        if (
            source is None
            or str(source[0]) != record.source.source_id
            or str(record.evidence_id) != row.evidence_id
            or str(record.case_id) != row.case_id
            or record.observed_at != _utc(row.observed_at)
            or record.captured_at != _utc(row.captured_at)
        ):
            raise ValueError("typed outcome evidence row provenance does not match payload")
        if str(record.collector.execution_id) != row.execution_id:
            raise ValueError("typed outcome evidence collector provenance does not match execution")
        if probe_id is not None and (
            record.collector.id != probe_id or record.collector.version != probe_version
        ):
            raise ValueError("typed outcome evidence collector provenance does not match probe")
        return
    if require_observation:
        raise ValueError("typed outcome evidence record required for successful probe")
    try:
        coverage = CoverageRecord.model_validate_json(row.record_json)
    except ValidationError as exc:
        raise ValueError("typed outcome evidence record is invalid") from exc
    if (
        str(coverage.evidence_id) != row.evidence_id
        or str(coverage.case_id) != row.case_id
        or coverage.captured_at != _utc(row.captured_at)
        or (None if coverage.execution_id is None else str(coverage.execution_id))
        != row.execution_id
    ):
        raise ValueError("typed outcome evidence coverage provenance does not match row")


def _validate_frozen_binding(
    label: ExpertAttentionLabel,
    snapshot: DecisionSnapshot,
    manifests: Mapping[str, ProbeManifest],
    repository: DecisionSnapshotRepository,
) -> None:
    request = snapshot.request
    attention = label.snapshot
    if label.schema_version != 2 or label.synthetic or label.label_origin != "human_expert":
        raise ValueError("only version 2 non-synthetic human expert labels may be admitted")
    if (
        snapshot.case_id != str(label.split_keys.case_id)
        or snapshot.state_version != attention.state_version
        or snapshot.captured_at != attention.captured_at
        or request.case_id != label.split_keys.case_id
        or request.attention_only
    ):
        raise ValueError("label does not match persisted frozen decision snapshot")
    case = repository.store.case(snapshot.case_id)
    if case is None or _utc(case.created_at) != attention.case_opened_at:
        raise ValueError("label case-open time does not match persisted case")
    if snapshot.request_frozen_at is None:
        raise ValueError("persisted request freeze time is required for evidence provenance")
    if snapshot.request_frozen_at < attention.case_opened_at:
        raise ValueError("request freeze time predates case opening")
    if tuple(
        request.evidence_ids
    ) != attention.evidence_ids or attention.visible_evidence_sha256 != visible_evidence_sha256(
        request
    ):
        raise ValueError("label visible evidence does not match frozen request")
    if attention.candidate_context_sha256 != candidate_context_sha256(request):
        raise ValueError("label candidate context does not match frozen request")
    if tuple(candidate.probe_id for candidate in attention.candidate_probes) != (
        snapshot.candidate_probe_ids
    ):
        raise ValueError("label candidate order does not match frozen request")
    if tuple(
        (ref.probe_id, ref.manifest_version, ref.catalog_sha256)
        for ref in snapshot.probe_manifest_refs
    ) != tuple(
        (candidate.probe_id, candidate.manifest_version, candidate.catalog_sha256)
        for candidate in attention.candidate_probes
    ):
        raise ValueError("label candidate catalog does not match persisted manifest references")
    label.validate_against_catalog(manifests)
    for candidate in attention.candidate_probes:
        manifest = manifests[candidate.probe_id]
        if candidate != RegisteredProbe.from_manifest(manifest):
            raise ValueError("label candidate does not match trusted catalog")
        capability = next(
            item for item in request.available_probes if item.probe_id == candidate.probe_id
        )
        if capability.safety_class != manifest.safety.safety_class:
            raise ValueError("frozen candidate safety class does not match trusted catalog")
    for evidence_id in request.evidence_ids:
        row = repository.store.evidence(case_id=snapshot.case_id, evidence_id=str(evidence_id))
        if row is None:
            raise ValueError("frozen request references missing baseline evidence")
        if _utc(row.captured_at) > snapshot.request_frozen_at:
            raise ValueError("baseline evidence was captured after request freeze")
        _validate_typed_evidence(row, repository=repository)


def _validate_observed_outcomes(
    label: ExpertAttentionLabel,
    snapshot: DecisionSnapshot,
    repository: DecisionSnapshotRepository,
) -> None:
    links = {link.execution_id: link for link in repository.execution_links(snapshot.snapshot_id)}
    for outcome in label.outcomes:
        execution_id = str(outcome.execution_id)
        link = links.get(execution_id)
        if link is None or link.case_id != snapshot.case_id or link.probe_id != outcome.probe_id:
            raise ValueError("labeled outcome lacks an explicitly linked execution")
        run = repository.store.probe_execution(execution_id)
        if run is None or (
            run.case_id != snapshot.case_id
            or run.probe_id != outcome.probe_id
            or run.state_version <= snapshot.state_version
            or run.finished_at is None
            or _utc(run.started_at) != outcome.started_at
            or _utc(run.finished_at) != outcome.finished_at
        ):
            raise ValueError("labeled outcome does not match persisted probe execution")
        manifest_ref = next(
            item for item in snapshot.probe_manifest_refs if item.probe_id == outcome.probe_id
        )
        if run.probe_version != manifest_ref.manifest_version:
            raise ValueError("labeled outcome probe version does not match frozen catalog")
        if outcome.result in {"informative", "uninformative"} and run.status != "ok":
            raise ValueError("successful outcome label requires a successful probe execution")
        if outcome.result == "failed" and run.status == "ok":
            raise ValueError("failed outcome label contradicts a successful probe execution")
        for evidence_id in outcome.evidence_ids:
            row = repository.store.evidence(case_id=snapshot.case_id, evidence_id=str(evidence_id))
            if (
                row is None
                or row.execution_id != execution_id
                or not (outcome.started_at <= _utc(row.captured_at) <= outcome.finished_at)
            ):
                raise ValueError("outcome evidence is not bound to persisted linked execution")
            _validate_typed_evidence(
                row,
                repository=repository,
                probe_id=outcome.probe_id,
                probe_version=run.probe_version,
                require_observation=outcome.result in {"informative", "uninformative"},
            )


def prepare_training_export(
    *,
    splits: Mapping[str, Sequence[ExpertAttentionLabel]],
    snapshot_ids: Mapping[str, str],
    repository: DecisionSnapshotRepository,
    trusted_catalog: Mapping[str, ProbeManifest],
    reviewer_authorizer: ReviewerAuthorizer | None = None,
    export_authorizer: ExportAuthorizer | None = None,
    privacy_reviewer: PrivacyReviewer | None = None,
) -> TrainingExport:
    """Admit a bounded, split-safe set of records, or export nothing.

    The authorizers must independently authenticate the real reviewer and
    case owner's explicit local-training/export/retention consent. There is no
    built-in allow-all provider. This function never writes files or starts training.
    Preworker inputs are not the actual bounded Laya worker payload; this output
    is not trainable until a persisted, verified worker trace is bound to it.
    """

    labels = tuple((split, label) for split, group in splits.items() for label in group)
    if not labels or len(labels) > _MAX_LABELS:
        raise ValueError("training export requires between 1 and 500 labels")
    if reviewer_authorizer is None:
        raise PermissionError("independent reviewer authorization is required")
    if export_authorizer is None:
        raise PermissionError("explicit export authorization is required")
    if privacy_reviewer is None:
        raise PermissionError("exact plaintext privacy review is required")
    # Pydantic's model_copy(update=...) bypasses validation. Rebuild from plain
    # JSON here so copied or deserialized records cannot smuggle in unobserved
    # negatives, altered digests, or a forged synthetic/origin flag.
    for _, label in labels:
        ExpertAttentionLabel.model_validate(label.model_dump(mode="json"))
    validate_group_splits(splits, trusted_catalog)
    if set(snapshot_ids) != {label.label_id for _, label in labels}:
        raise ValueError("snapshot IDs must bind exactly one snapshot to every label")
    if len(set(snapshot_ids.values())) != len(snapshot_ids):
        raise ValueError("one frozen snapshot cannot be admitted more than once")

    # A single WAL read snapshot keeps case, decision, execution and evidence
    # checks consistent. External authorizers run after it closes.
    pending: list[
        tuple[
            str,
            ExpertAttentionLabel,
            DecisionSnapshot,
            TrainingInput,
            tuple[CandidateTarget, ...],
            str,
            str,
        ]
    ] = []
    snapshot_cache: dict[str, dict[str, DecisionSnapshot]] = {}
    with repository.store.read_snapshot():
        for split, label in labels:
            case_id = str(label.split_keys.case_id)
            if case_id not in snapshot_cache:
                snapshot_cache[case_id] = {
                    item.snapshot_id: item
                    for item in repository.snapshots(case_id=case_id, limit=_MAX_LABELS)
                }
            snapshot = snapshot_cache[case_id].get(snapshot_ids[label.label_id])
            if snapshot is None:
                raise ValueError("label snapshot is not persisted in its case")
            _validate_frozen_binding(label, snapshot, trusted_catalog, repository)
            _validate_observed_outcomes(label, snapshot, repository)
            visible_ids = tuple(item["probe_id"] for item in snapshot.laya_candidates)
            if len(visible_ids) != len(set(visible_ids)):
                raise ValueError("Laya candidate projection repeats probe IDs")
            if not set(label.useful_probe_ids + label.negative_probe_ids).issubset(visible_ids):
                raise ValueError("label targets a candidate not visible to Laya")
            useful = set(label.useful_probe_ids)
            negative = set(label.negative_probe_ids)
            targets = tuple(
                CandidateTarget(
                    probe_id=probe_id,
                    utility=(
                        "useful"
                        if probe_id in useful
                        else "negative"
                        if probe_id in negative
                        else "unknown"
                    ),
                    loss_mask=probe_id in useful or probe_id in negative,
                )
                for probe_id in visible_ids
            )
            model_input = TrainingInput(
                state=snapshot.laya_state,
                evidence=snapshot.laya_evidence,
                candidates=snapshot.laya_candidates,
            )
            label_digest = _sha256(label.model_dump(mode="json"))
            content_digest = _sha256(
                _training_content(
                    label_id=label.label_id,
                    case_id=snapshot.case_id,
                    split=split,
                    snapshot_id=snapshot.snapshot_id,
                    request_sha256=snapshot.request_sha256,
                    laya_projection_sha256=snapshot.laya_projection_sha256,
                    model_input=model_input,
                    input_visibility="preworker_only",
                    trainable=False,
                    targets=targets,
                    abstain_target=label.abstain,
                )
            )
            pending.append(
                (split, label, snapshot, model_input, targets, label_digest, content_digest)
            )

    examples: list[TrainingExample] = []
    privacy_reviews: list[PrivacyReviewReceipt] = []
    for split, label, snapshot, model_input, targets, label_digest, content_digest in pending:
        reviewer_receipt = reviewer_authorizer.verify_reviewer(
            label=label, label_sha256=label_digest
        )
        if reviewer_receipt is None:
            raise PermissionError("reviewer authorization is missing")
        try:
            ReviewerAuthorization.model_validate(reviewer_receipt.model_dump(mode="json"))
        except (ValidationError, ValueError, TypeError) as exc:
            raise PermissionError("reviewer authorization receipt is invalid") from exc
        if (
            reviewer_receipt.label_id != label.label_id
            or reviewer_receipt.reviewer_id != label.reviewer_id
            or reviewer_receipt.label_sha256 != label_digest
        ):
            raise PermissionError("reviewer authorization does not bind exact expert label")
        consent = export_authorizer.verify_export(
            case_id=snapshot.case_id,
            snapshot_id=snapshot.snapshot_id,
            training_content_sha256=content_digest,
        )
        if consent is None:
            raise PermissionError("export authorization is missing")
        try:
            ExportAuthorization.model_validate(consent.model_dump(mode="json"))
        except (ValidationError, ValueError, TypeError) as exc:
            raise PermissionError("export authorization receipt is invalid") from exc
        if (
            consent.case_id != snapshot.case_id
            or consent.snapshot_id != snapshot.snapshot_id
            or consent.training_content_sha256 != content_digest
            or consent.purpose != "local_model_training"
            or consent.retention_until.tzinfo is None
            or consent.retention_until.utcoffset() != UTC.utcoffset(None)
            or consent.retention_until <= datetime.now(UTC)
        ):
            raise PermissionError("export authorization or retention consent is invalid")
        example = TrainingExample(
            label_id=label.label_id,
            case_id=snapshot.case_id,
            split=split,
            snapshot_id=snapshot.snapshot_id,
            request_sha256=snapshot.request_sha256,
            laya_projection_sha256=snapshot.laya_projection_sha256,
            input=model_input,
            targets=targets,
            abstain_target=label.abstain,
            training_content_sha256=content_digest,
            reviewer_authorization_id=reviewer_receipt.authorization_id,
            export_authorization_id=consent.authorization_id,
            retention_until=consent.retention_until,
        )
        payload_json = example.model_dump_json()
        final_payload_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        privacy = privacy_reviewer.review_privacy(
            payload_json=payload_json, payload_sha256=final_payload_digest
        )
        if privacy is None:
            raise PermissionError("exact plaintext privacy review is missing")
        try:
            PrivacyReviewReceipt.model_validate(privacy.model_dump(mode="json"))
        except (ValidationError, ValueError, TypeError) as exc:
            raise PermissionError("exact plaintext privacy review receipt is invalid") from exc
        if (
            privacy.payload_sha256 != final_payload_digest
            or privacy.reviewed_at.tzinfo is None
            or privacy.reviewed_at.utcoffset() != UTC.utcoffset(None)
            or privacy.reviewed_at < label.reviewed_at
            or privacy.reviewed_at > datetime.now(UTC)
        ):
            raise PermissionError("exact plaintext privacy review is missing or unbound")
        examples.append(example)
        privacy_reviews.append(privacy)
    return TrainingExport(examples=tuple(examples), privacy_reviews=tuple(privacy_reviews))


def verified_export_payloads(export: TrainingExport) -> tuple[str, ...]:
    """Read unexpired exact-reviewed payloads; reject edits after privacy review.

    This checks digest consistency only. The trusted privacy reviewer remains
    responsible for authenticating the receipt; this is not a signature check.
    """

    # model_copy(update=...) bypasses Pydantic validation, including the literal
    # false admission gate on this intentionally non-trainable export format.
    try:
        TrainingExport.model_validate(export.model_dump(mode="json"))
    except (ValidationError, ValueError, TypeError) as exc:
        raise ValueError("training export envelope is invalid") from exc
    if not 1 <= len(export.examples) <= _MAX_LABELS:
        raise ValueError("training export envelope has invalid example count")
    if len(export.examples) != len(export.privacy_reviews):
        raise ValueError("privacy review count does not match export examples")

    def require_active_retention() -> None:
        instant = datetime.now(UTC)
        if any(
            example.retention_until.tzinfo is None
            or example.retention_until.utcoffset() != UTC.utcoffset(None)
            or example.retention_until <= instant
            for example in export.examples
        ):
            raise PermissionError("training export retention expired or invalid")

    require_active_retention()
    payloads: list[str] = []
    for example, review in zip(export.examples, export.privacy_reviews, strict=True):
        if training_content_sha256(example) != example.training_content_sha256:
            raise ValueError("training content changed after consent")
        payload_json = example.model_dump_json()
        if hashlib.sha256(payload_json.encode("utf-8")).hexdigest() != review.payload_sha256:
            raise ValueError("export payload changed after privacy review")
        payloads.append(payload_json)
    require_active_retention()
    return tuple(payloads)


def training_corpus_sha256(export: TrainingExport) -> str:
    """Identify an exact, still-consented export including its review receipts.

    This digest is a corpus identity check, not reviewer authentication, worker
    token parity, or permission to train. The export remains preworker-only.
    """

    verified_export_payloads(export)
    return _sha256(export.model_dump(mode="json"))


def verify_training_corpus_identity(export: TrainingExport, *, expected_sha256: str) -> None:
    """Fail if a verified export differs from an externally retained corpus digest."""

    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("expected corpus identity digest is invalid")
    if training_corpus_sha256(export) != expected_sha256:
        raise ValueError("training corpus identity does not match")
