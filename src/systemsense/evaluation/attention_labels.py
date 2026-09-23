"""Versioned human-reviewed labels for choosing the next registered probe.

Records contain evidence references and catalog capabilities, never raw case text.
They are collection contracts, not a training pipeline or measured model quality.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import ProbeManifest, SafetyClass
from systemsense.domain.time import UtcDateTime


class SplitKeys(FrozenModel):
    """Pseudonymous grouping keys; digest format is checked, origin is not authenticated."""

    case_id: CaseId
    machine_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    application_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    application_version: str | None = Field(
        default=None, min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$"
    )
    fault_family: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")

    @model_validator(mode="after")
    def version_requires_application(self) -> SplitKeys:
        if self.application_version is not None and self.application_key is None:
            raise ValueError("application version requires an application key")
        return self


class RegisteredProbe(FrozenModel):
    """Catalog reference without inline description, keywords, or target data."""

    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    manifest_version: int = Field(ge=1)
    catalog_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_manifest(cls, manifest: ProbeManifest) -> RegisteredProbe:
        if manifest.safety.safety_class not in {SafetyClass.R0, SafetyClass.R1}:
            raise ValueError("attention candidate must be a read-only catalog probe")
        canonical = json.dumps(
            manifest.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return cls(
            probe_id=manifest.probe_id,
            manifest_version=manifest.version,
            catalog_sha256=hashlib.sha256(canonical).hexdigest(),
        )


class AttentionSnapshot(FrozenModel):
    state_version: int = Field(ge=0)
    case_opened_at: UtcDateTime
    captured_at: UtcDateTime
    evidence_ids: tuple[EvidenceId, ...] = Field(max_length=256)
    candidate_probes: tuple[RegisteredProbe, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def unique_references(self) -> AttentionSnapshot:
        if self.case_opened_at > self.captured_at:
            raise ValueError("case-open time must precede snapshot")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("snapshot evidence IDs must be unique")
        probe_ids = [item.probe_id for item in self.candidate_probes]
        if len(probe_ids) != len(set(probe_ids)):
            raise ValueError("candidate probe IDs must be unique")
        return self


class RedactionAttestation(FrozenModel):
    """Explicit human check that source text was omitted and catalog text screened."""

    method: Literal["identifiers_only"]
    checked_by: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    checked_at: UtcDateTime


class ProbeOutcome(FrozenModel):
    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    execution_id: ExecutionId
    started_at: UtcDateTime
    finished_at: UtcDateTime
    evidence_ids: tuple[EvidenceId, ...] = Field(max_length=256)
    result: Literal["informative", "uninformative", "inconclusive", "failed"]
    limitation_codes: tuple[str, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def ordered_unique_result(self) -> ProbeOutcome:
        if self.finished_at < self.started_at:
            raise ValueError("probe outcome timestamps must be ordered")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("outcome evidence IDs must be unique")
        if self.result in {"failed", "inconclusive"} and not self.limitation_codes:
            raise ValueError("failed or inconclusive outcome requires a limitation code")
        if len(set(self.limitation_codes)) != len(self.limitation_codes) or any(
            re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", code) is None for code in self.limitation_codes
        ):
            raise ValueError("limitation codes must be unique safe identifiers")
        return self


class ExpertAttentionLabel(FrozenModel):
    """Hindsight expert utility labels at a frozen state with observed results."""

    schema_version: Literal[1] = 1
    label_id: str = Field(pattern=r"^label_[0-9a-f]{32}$")
    split_keys: SplitKeys
    snapshot: AttentionSnapshot
    useful_probe_ids: tuple[str, ...] = Field(max_length=128)
    negative_probe_ids: tuple[str, ...] = Field(max_length=128)
    abstain: bool
    outcomes: tuple[ProbeOutcome, ...] = Field(max_length=128)
    reviewer_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    reviewed_at: UtcDateTime
    label_origin: Literal["human_expert"]
    source_kind: Literal["live", "recorded"]
    synthetic: Literal[False]
    redaction: RedactionAttestation

    @model_validator(mode="after")
    def label_is_auditable(self) -> ExpertAttentionLabel:
        candidates = {item.probe_id for item in self.snapshot.candidate_probes}
        useful = set(self.useful_probe_ids)
        negative = set(self.negative_probe_ids)
        outcome_ids = [item.probe_id for item in self.outcomes]
        if len(useful) != len(self.useful_probe_ids) or len(negative) != len(
            self.negative_probe_ids
        ):
            raise ValueError("probe labels must be unique")
        if useful & negative:
            raise ValueError("probe cannot be both useful and negative")
        if not useful | negative <= candidates or not set(outcome_ids) <= candidates:
            raise ValueError("labels and outcomes must reference candidate registered probes")
        if len(outcome_ids) != len(set(outcome_ids)):
            raise ValueError("probe outcomes must be unique")
        if self.abstain and (useful or self.outcomes):
            raise ValueError("abstention cannot select or execute probes")
        if not self.abstain and not useful and not negative:
            raise ValueError("label requires a useful probe, negative probe, or abstention")
        if not useful <= set(outcome_ids):
            raise ValueError("selected useful probes require a post-probe outcome")
        observed_results = {item.probe_id: item.result for item in self.outcomes}
        if any(observed_results[probe_id] != "informative" for probe_id in useful):
            raise ValueError("useful probe label requires an informative outcome")
        if any(
            probe_id in observed_results and observed_results[probe_id] != "uninformative"
            for probe_id in negative
        ):
            raise ValueError("negative probe label conflicts with observed outcome")
        if self.redaction.checked_by != self.reviewer_id:
            raise ValueError("redaction check must identify the reviewer")
        if not self.snapshot.captured_at <= self.redaction.checked_at <= self.reviewed_at:
            raise ValueError("redaction and review timestamps must follow snapshot")
        for outcome in self.outcomes:
            if (
                not self.snapshot.captured_at
                <= outcome.started_at
                <= outcome.finished_at
                <= self.reviewed_at
            ):
                raise ValueError("probe outcome must follow snapshot and precede review")
            if outcome.finished_at > self.redaction.checked_at:
                raise ValueError("redaction check must follow every probe outcome")
            if outcome.result == "informative" and not (
                set(outcome.evidence_ids) - set(self.snapshot.evidence_ids)
            ):
                raise ValueError("informative outcome requires new evidence")
        return self

    def validate_against_catalog(self, manifests: Mapping[str, ProbeManifest]) -> None:
        """Bind candidate references to the trusted catalog at label admission."""

        for candidate in self.snapshot.candidate_probes:
            manifest = manifests.get(candidate.probe_id)
            if manifest is None or candidate != RegisteredProbe.from_manifest(manifest):
                raise ValueError(f"candidate does not match trusted catalog: {candidate.probe_id}")


def validate_group_splits(
    splits: Mapping[str, Sequence[ExpertAttentionLabel]],
    trusted_catalog: Mapping[str, ProbeManifest],
) -> None:
    """Admit catalog-bound labels with no cross-split group overlap."""

    owners: dict[tuple[str, str], str] = {}
    label_owners: dict[str, str] = {}
    for split, labels in splits.items():
        if not split:
            raise ValueError("split name must not be empty")
        for label in labels:
            label.validate_against_catalog(trusted_catalog)
            if label.label_id in label_owners:
                raise ValueError("label ID appears more than once in split assignment")
            label_owners[label.label_id] = split
            keys = label.split_keys
            group_keys = [
                ("case", str(keys.case_id)),
                ("machine", keys.machine_key),
                ("fault_family", keys.fault_family),
            ]
            if keys.application_key is not None:
                group_keys.append(("application", keys.application_key))
                if keys.application_version is not None:
                    group_keys.append(
                        (
                            "application_version",
                            f"{keys.application_key}:{keys.application_version}",
                        )
                    )
            for group_key in group_keys:
                previous_split = owners.setdefault(group_key, split)
                if previous_split != split:
                    raise ValueError(f"{group_key[0]} group crosses splits")
