"""Coordinator-owned provenance for accepted asynchronous deep probe advice."""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, Field

from systemsense.decision.contracts import ProbeProposal
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import ProbeManifest
from systemsense.storage.decision_snapshots import ProbeManifestRef


def canonical_model_sha256(value: BaseModel) -> str:
    encoded = json.dumps(
        value.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class DeepProposalOriginV1(FrozenModel):
    """A trusted checkpoint reference; never accepted from a model response."""

    schema_version: int = Field(default=1, ge=1, le=1)
    case_id: CaseId
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    proposal_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    probe_version: int = Field(ge=1)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    accepted_state_version: int = Field(ge=1)

    @classmethod
    def from_accepted(
        cls,
        *,
        case_id: CaseId,
        request_sha256: str,
        proposal: ProbeProposal,
        manifest: ProbeManifest,
        accepted_state_version: int,
    ) -> DeepProposalOriginV1:
        reference = ProbeManifestRef.from_manifest(proposal.probe_id, manifest)
        if reference.catalog_sha256 is None or reference.manifest_version is None:
            raise ValueError("accepted deep proposal lacks a registered manifest")
        return cls(
            case_id=case_id,
            request_sha256=request_sha256,
            proposal_sha256=canonical_model_sha256(proposal),
            probe_id=proposal.probe_id,
            probe_version=reference.manifest_version,
            manifest_sha256=reference.catalog_sha256,
            accepted_state_version=accepted_state_version,
        )
