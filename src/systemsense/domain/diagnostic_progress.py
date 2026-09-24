"""Bounded, cited diagnostic branch context for advisory model requests.

Only the deterministic owner may construct this from revalidated terminal custody.
These fields describe a scoped observation, not a cause or permission to act.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import Field, StrictBool, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.probes import MeasurementWindow


class DiagnosticProgressScopeV1(FrozenModel):
    """Case, interface handle and source-observation window of one question."""

    case_id: CaseId
    target_handle: str = Field(min_length=1, max_length=120)
    window: MeasurementWindow

    @model_validator(mode="after")
    def canonical_interface_guid(self) -> DiagnosticProgressScopeV1:
        try:
            canonical = str(UUID(self.target_handle))
        except ValueError as error:
            raise ValueError("progress scope target must be an interface GUID") from error
        if canonical != self.target_handle:
            raise ValueError("progress scope target must be a canonical interface GUID")
        return self


class DiagnosticProgressContextV1(FrozenModel):
    """One revalidated branch result supplied to an advisory provider."""

    schema_version: Literal[1] = 1
    question_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    branch_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    uncertainty_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    predicate_id: Literal["network.wifi_associated"] = "network.wifi_associated"
    scope: DiagnosticProgressScopeV1
    terminal_status: Literal["evaluated", "unknown", "failed", "interrupted"]
    observed: StrictBool | None
    reason: str = Field(min_length=1, max_length=240)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    matched_alternative_ids: tuple[str, ...] = Field(default=(), max_length=8)
    disfavored_alternative_ids: tuple[str, ...] = Field(default=(), max_length=8)
    unresolved_assumption_ids: tuple[str, ...] = Field(default=(), max_length=8)
    custody_status: Literal["verified", "missing", "invalid"]
    unknown: bool
    dead_end: bool
    branch_dead_end_count: int = Field(ge=0, le=120)

    @model_validator(mode="after")
    def consistent_result(self) -> DiagnosticProgressContextV1:
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("diagnostic progress repeats evidence IDs")
        for label, items in (
            ("matched alternatives", self.matched_alternative_ids),
            ("disfavored alternatives", self.disfavored_alternative_ids),
            ("unresolved assumptions", self.unresolved_assumption_ids),
        ):
            if len(set(items)) != len(items) or any(len(item) > 120 for item in items):
                raise ValueError(f"{label} must be unique and bounded")
        if set(self.matched_alternative_ids) & set(self.disfavored_alternative_ids):
            raise ValueError("an alternative cannot be both matched and disfavored")
        if not set((*self.matched_alternative_ids, *self.disfavored_alternative_ids)) <= {
            "wlan.associated",
            "wlan.disconnected",
        }:
            raise ValueError("progress references an unregistered alternative")
        if self.unknown != (self.observed is None):
            raise ValueError("unknown must match absent observation")
        if self.observed is None:
            if self.matched_alternative_ids or self.disfavored_alternative_ids or not self.dead_end:
                raise ValueError("unknown result cannot discriminate alternatives")
        elif (
            self.terminal_status != "evaluated"
            or self.custody_status != "verified"
            or not self.evidence_ids
            or not self.matched_alternative_ids
            or not self.disfavored_alternative_ids
            or self.dead_end
        ):
            raise ValueError("observed result requires verified cited discrimination")
        if self.observed is not None:
            expected_match = "wlan.associated" if self.observed else "wlan.disconnected"
            expected_disfavored = "wlan.disconnected" if self.observed else "wlan.associated"
            if self.matched_alternative_ids != (expected_match,) or (
                self.disfavored_alternative_ids != (expected_disfavored,)
            ):
                raise ValueError("progress alternatives disagree with observed WLAN state")
        if self.custody_status != "verified" and self.observed is not None:
            raise ValueError("lost custody cannot present a Boolean result")
        return self
