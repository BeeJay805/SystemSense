"""Non-trainable pilot inventory for candidate-ID decision and dispatch custody.

Only hash-only preworker references and separately marked post-decision execution
metadata leave this boundary. A probe execution is not a useful-probe label.
The current API accepts unqualified fixture and owned-host rehearsal origins;
real, independently qualified Windows or validated-simulator admission needs a
separate authenticated source and outcome boundary.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from typing import Literal

from pydantic import Field, ValidationError

from systemsense.domain.evidence import FrozenModel
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import (
    CandidateDispatchAdmission,
    CandidateDispatchAdmissionRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore

_DIGEST = r"^[0-9a-f]{64}$"
_SNAPSHOT = r"^candidate_decision_snapshot_[0-9a-f]{32}$"
_MAX_EPISODES = 500
GroupKind = Literal["case", "machine", "application", "application_version", "fault_family"]


class PilotCaseRegistration(FrozenModel):
    """Caller-declared origin and split keys; none authenticate a source."""

    snapshot_id: str = Field(pattern=_SNAPSHOT)
    split: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")
    source_kind: Literal["fixture_contract", "controlled_host_rehearsal"]
    source_artifact_sha256: str = Field(pattern=_DIGEST)
    machine_key: str = Field(min_length=1, max_length=120)
    fault_family: str = Field(min_length=1, max_length=120)
    application_key: str | None = Field(default=None, min_length=1, max_length=120)
    application_version: str | None = Field(default=None, min_length=1, max_length=120)


class PilotCandidateRecord(FrozenModel):
    candidate_id: str = Field(pattern=r"^cand_v1_[0-9a-f]{32}$")
    probe_id: str
    manifest_sha256: str = Field(pattern=_DIGEST)
    invocation_sha256: str = Field(pattern=_DIGEST)
    description_sha256: str = Field(pattern=_DIGEST)
    dispatch_status: Literal["not_admitted", "unclaimed", "claimed_unlinked", "linked"]
    execution_id: str | None = None
    execution_status: str | None = None
    utility: Literal["unknown"] = "unknown"
    label_quality: Literal["unknown", "execution_recorded_unreviewed"] = "unknown"


class PilotSplitGroup(FrozenModel):
    kind: GroupKind
    value_sha256: str = Field(pattern=_DIGEST)
    split: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,39}$")


class PilotEpisodeRecord(FrozenModel):
    snapshot_id: str = Field(pattern=_SNAPSHOT)
    case_id: str
    epoch_state_version: int = Field(ge=0)
    split: str
    source_kind: Literal["fixture_contract", "controlled_host_rehearsal"]
    source_authenticity: Literal["not_verified"] = "not_verified"
    source_artifact_sha256: str = Field(pattern=_DIGEST)
    request_sha256: str = Field(pattern=_DIGEST)
    response_sha256: str = Field(pattern=_DIGEST)
    candidate_manifest_sha256: str = Field(pattern=_DIGEST)
    registry_manifest_sha256: str = Field(pattern=_DIGEST)
    model_input_visibility: Literal["hash_only_preworker_metadata"] = "hash_only_preworker_metadata"
    split_groups: tuple[PilotSplitGroup, ...] = Field(min_length=3, max_length=5)
    candidates: tuple[PilotCandidateRecord, ...] = Field(min_length=1, max_length=128)


class PilotCorpus(FrozenModel):
    schema_version: Literal[1] = 1
    classification: Literal["candidate_custody_pilot_only"] = "candidate_custody_pilot_only"
    training_admissible: Literal[False] = False
    diagnostic_performance_admissible: Literal[False] = False
    episodes: tuple[PilotEpisodeRecord, ...] = Field(min_length=1, max_length=_MAX_EPISODES)
    source_counts: dict[str, int]
    label_quality_counts: dict[str, int]
    split_counts: dict[str, int]
    split_groups: tuple[PilotSplitGroup, ...]
    split_manifest_sha256: str = Field(pattern=_DIGEST)
    manifest_sha256: str = Field(pattern=_DIGEST)


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _groups(registration: PilotCaseRegistration, case_id: str) -> tuple[tuple[GroupKind, str], ...]:
    groups: list[tuple[GroupKind, str]] = [
        ("case", case_id),
        ("machine", registration.machine_key),
        ("fault_family", registration.fault_family),
    ]
    if registration.application_key is not None:
        groups.append(("application", registration.application_key))
        if registration.application_version is not None:
            groups.append(
                (
                    "application_version",
                    f"{registration.application_key}:{registration.application_version}",
                )
            )
    elif registration.application_version is not None:
        raise ValueError("application version requires an application key")
    return tuple(groups)


def _split_digest(groups: tuple[PilotSplitGroup, ...]) -> str:
    rows = [(item.kind, item.value_sha256, item.split) for item in groups]
    return _digest({"schema_version": 1, "groups": rows})


def _manifest_content(corpus: PilotCorpus) -> dict[str, object]:
    return {
        "schema_version": corpus.schema_version,
        "classification": corpus.classification,
        "training_admissible": corpus.training_admissible,
        "diagnostic_performance_admissible": corpus.diagnostic_performance_admissible,
        "episodes": [item.model_dump(mode="json") for item in corpus.episodes],
        "source_counts": corpus.source_counts,
        "label_quality_counts": corpus.label_quality_counts,
        "split_counts": corpus.split_counts,
        "split_groups": [item.model_dump(mode="json") for item in corpus.split_groups],
        "split_manifest_sha256": corpus.split_manifest_sha256,
    }


def assemble_pilot_corpus(
    store: SQLiteStore,
    snapshots: CandidateDecisionSnapshotRepository,
    registrations: Sequence[PilotCaseRegistration],
) -> PilotCorpus:
    """Read one bounded, source-unverified shard from durable 019/020 custody.

    No future outcome, fault recipe, full request, or case text becomes a model
    feature here. Execution metadata is for inventory only and utility stays
    unknown even when a linked run succeeded.
    """

    if not 1 <= len(registrations) <= _MAX_EPISODES:
        raise ValueError("pilot shard requires between 1 and 500 registrations")
    if len({item.snapshot_id for item in registrations}) != len(registrations):
        raise ValueError("duplicate snapshot in pilot shard")
    dispatches = CandidateDispatchAdmissionRepository(store)
    episodes: list[PilotEpisodeRecord] = []
    assignments: dict[tuple[GroupKind, str], str] = {}
    with store.read_snapshot():
        for registration in registrations:
            PilotCaseRegistration.model_validate(registration.model_dump(mode="json"))
            snapshot = snapshots.readback(registration.snapshot_id)
            if not snapshot.request_frozen_at <= snapshot.captured_at:
                raise ValueError("decision request was not frozen before response")
            case_id = str(snapshot.case_id)
            episode_groups: list[PilotSplitGroup] = []
            for kind, value in _groups(registration, case_id):
                key = (kind, _digest([kind, value]))
                existing = assignments.get(key)
                if existing is not None and existing != registration.split:
                    raise ValueError(f"{kind} group crosses pilot split")
                assignments[key] = registration.split
                episode_groups.append(
                    PilotSplitGroup(kind=kind, value_sha256=key[1], split=registration.split)
                )
            rows = store.connection.execute(
                "SELECT admission_id FROM candidate_dispatch_admissions "
                "WHERE snapshot_id=? ORDER BY admission_id",
                (snapshot.snapshot_id,),
            ).fetchall()
            admitted: dict[str, CandidateDispatchAdmission] = {}
            for row in rows:
                record = dispatches.readback(str(row[0]))
                if record.snapshot_id != snapshot.snapshot_id:
                    raise ValueError("dispatch admission snapshot mismatch")
                if record.candidate_id in admitted:
                    raise ValueError("duplicate candidate dispatch admission")
                admitted[record.candidate_id] = record
            links = {
                item.candidate_id: item for item in snapshots.execution_links(snapshot.snapshot_id)
            }
            if not set(links).issubset(admitted):
                raise ValueError("execution link lacks one-shot dispatch admission")
            candidates: list[PilotCandidateRecord] = []
            for ref in snapshot.request.available_candidates:
                admission = admitted.get(ref.candidate_id)
                link = links.get(ref.candidate_id)
                if admission is not None and admission.execution_id != (
                    link.execution_id if link is not None else None
                ):
                    raise ValueError("dispatch admission and execution link differ")
                run = store.probe_execution(link.execution_id) if link is not None else None
                if link is not None and (
                    run is None
                    or run.case_id != case_id
                    or run.state_version != snapshot.epoch_state_version
                    or run.probe_id != ref.probe_id
                    or run.finished_at is None
                ):
                    raise ValueError("linked candidate execution is incomplete or mismatched")
                candidates.append(
                    PilotCandidateRecord(
                        candidate_id=ref.candidate_id,
                        probe_id=ref.probe_id,
                        manifest_sha256=ref.manifest_sha256,
                        invocation_sha256=ref.invocation_sha256,
                        description_sha256=_digest(ref.description),
                        dispatch_status=(
                            admission.outcome_status if admission is not None else "not_admitted"
                        ),
                        execution_id=link.execution_id if link is not None else None,
                        execution_status=run.status if run is not None else None,
                        label_quality=(
                            "execution_recorded_unreviewed" if run is not None else "unknown"
                        ),
                    )
                )
            if not set(admitted).issubset({item.candidate_id for item in candidates}):
                raise ValueError("dispatch admission references unadvertised candidate")
            episodes.append(
                PilotEpisodeRecord(
                    snapshot_id=snapshot.snapshot_id,
                    case_id=case_id,
                    epoch_state_version=snapshot.epoch_state_version,
                    split=registration.split,
                    source_kind=registration.source_kind,
                    source_artifact_sha256=registration.source_artifact_sha256,
                    request_sha256=snapshot.request_sha256,
                    response_sha256=snapshot.response_sha256,
                    candidate_manifest_sha256=snapshot.request.candidate_manifest_sha256,
                    registry_manifest_sha256=snapshot.registry_manifest_sha256,
                    split_groups=tuple(episode_groups),
                    candidates=tuple(candidates),
                )
            )
    sources = dict(sorted(Counter(item.source_kind for item in episodes).items()))
    qualities = dict(
        sorted(
            Counter(
                candidate.label_quality for item in episodes for candidate in item.candidates
            ).items()
        )
    )
    splits = dict(sorted(Counter(item.split for item in episodes).items()))
    split_groups = tuple(
        PilotSplitGroup(kind=kind, value_sha256=digest, split=split)
        for (kind, digest), split in sorted(assignments.items())
    )
    provisional = PilotCorpus(
        episodes=tuple(episodes),
        source_counts=sources,
        label_quality_counts=qualities,
        split_counts=splits,
        split_groups=split_groups,
        split_manifest_sha256=_split_digest(split_groups),
        manifest_sha256="0" * 64,
    )
    corpus = provisional.model_copy(
        update={"manifest_sha256": _digest(_manifest_content(provisional))}
    )
    verify_pilot_corpus(corpus)
    return corpus


def verify_pilot_corpus(corpus: PilotCorpus) -> str:
    """Reject in-memory `model_copy` bypasses and metadata mutation.

    This verifies structural integrity only. It does not authenticate declared
    source artifacts, reviewer identities, or the underlying SQLite file.
    """

    try:
        PilotCorpus.model_validate(corpus.model_dump(mode="json"))
    except (ValidationError, TypeError, ValueError) as error:
        raise ValueError("pilot corpus envelope is invalid") from error
    if len({item.snapshot_id for item in corpus.episodes}) != len(corpus.episodes):
        raise ValueError("pilot corpus repeats a snapshot")
    groups_by_key: dict[tuple[GroupKind, str], str] = {}
    for item in corpus.episodes:
        if len({group.kind for group in item.split_groups}) != len(item.split_groups):
            raise ValueError("pilot episode repeats a split group kind")
        for group in item.split_groups:
            if group.split != item.split:
                raise ValueError("pilot episode group split mismatch")
            key = (group.kind, group.value_sha256)
            prior = groups_by_key.get(key)
            if prior is not None and prior != group.split:
                raise ValueError("pilot group crosses split")
            groups_by_key[key] = group.split
    expected_groups = tuple(
        PilotSplitGroup(kind=kind, value_sha256=digest, split=split)
        for (kind, digest), split in sorted(groups_by_key.items())
    )
    if corpus.split_groups != expected_groups:
        raise ValueError("pilot group crosses split or manifest groups differ")
    if corpus.split_manifest_sha256 != _split_digest(expected_groups):
        raise ValueError("pilot split manifest digest mismatch")
    for item in corpus.episodes:
        if len({candidate.candidate_id for candidate in item.candidates}) != len(item.candidates):
            raise ValueError("pilot episode repeats a candidate")
        for candidate in item.candidates:
            if (candidate.execution_id is None) != (candidate.execution_status is None):
                raise ValueError("pilot candidate execution metadata is incomplete")
            if candidate.label_quality != (
                "execution_recorded_unreviewed" if candidate.execution_id else "unknown"
            ):
                raise ValueError("pilot label quality contradicts observed execution")
            if candidate.dispatch_status == "linked" and candidate.execution_id is None:
                raise ValueError("linked candidate lacks execution identity")
            if candidate.dispatch_status != "linked" and candidate.execution_id is not None:
                raise ValueError("unlinked candidate claims execution identity")
    if (
        corpus.source_counts
        != dict(sorted(Counter(item.source_kind for item in corpus.episodes).items()))
        or corpus.label_quality_counts
        != dict(
            sorted(
                Counter(
                    candidate.label_quality
                    for item in corpus.episodes
                    for candidate in item.candidates
                ).items()
            )
        )
        or corpus.split_counts
        != dict(sorted(Counter(item.split for item in corpus.episodes).items()))
    ):
        raise ValueError("pilot corpus counts do not match episodes")
    if _digest(_manifest_content(corpus)) != corpus.manifest_sha256:
        raise ValueError("pilot corpus manifest does not match content")
    return corpus.manifest_sha256
