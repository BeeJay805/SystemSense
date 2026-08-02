"""Strict, hashable contracts for proof-grade A/B runs."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from benchmarks.models import BenchmarkFamily


class ExperimentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExperimentArm(StrEnum):
    BASELINE = "baseline"
    SYSTEMSENSE = "systemsense"


class ModelRunner(StrEnum):
    RESPONSES_API = "responses_api"
    CODEX_CLI = "codex_cli"


FINGERPRINT_STATE_KEYS = frozenset(
    {
        "os",
        "powershell",
        "python_packages",
        "installed_software",
        "drivers",
        "policies",
        "services",
        "scenario_files",
        "fault_state",
        "systemsense",
    }
)


class ScenarioScripts(ExperimentModel):
    inject: str
    verify_broken: str
    verify_fixed: str
    repair_reference: str


class ScenarioManifest(ExperimentModel):
    schema_version: Literal[1] = 1
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    family: BenchmarkFamily
    human_prompt: str = Field(min_length=20, max_length=2000)
    expected_signals: tuple[str, ...] = Field(min_length=1)
    expected_evidence_terms: tuple[str, ...] = Field(min_length=1)
    expected_coverage_categories: tuple[str, ...] = Field(min_length=1)
    scripts: ScenarioScripts
    assets: tuple[str, ...] = ()
    qualification_repetitions: int = Field(default=3, ge=3, le=10)


class MachineFingerprint(ExperimentModel):
    schema_version: Literal[1, 2] = 2
    arm: ExperimentArm
    clone_id: str = Field(min_length=1, max_length=200)
    parent_snapshot_id: str = Field(min_length=1, max_length=500)
    state: dict[str, str] = Field(min_length=1)
    inventory: dict[str, tuple[str, ...]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def required_state_categories(self) -> MachineFingerprint:
        missing = FINGERPRINT_STATE_KEYS - set(self.state)
        if missing:
            raise ValueError("fingerprint state is missing: " + ", ".join(sorted(missing)))
        inventory_missing = FINGERPRINT_STATE_KEYS - set(self.inventory)
        if self.inventory and inventory_missing:
            raise ValueError(
                "fingerprint inventory is missing: " + ", ".join(sorted(inventory_missing))
            )
        return self

    def comparison_hash(self) -> str:
        return canonical_sha256(
            {
                "parent_snapshot_id": self.parent_snapshot_id,
                "state": self.state,
            }
        )


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
