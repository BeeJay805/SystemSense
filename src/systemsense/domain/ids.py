"""Opaque identifiers and deterministic source identities."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import ClassVar
from uuid import uuid4

from pydantic import ConfigDict, RootModel, model_validator

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


class OpaqueId(RootModel[str]):
    """Immutable prefixed identifier with Pydantic validation."""

    model_config = ConfigDict(frozen=True)

    prefix: ClassVar[str]

    @model_validator(mode="after")
    def validate_format(self) -> OpaqueId:
        pattern = rf"{re.escape(self.prefix)}_[0-9a-f]{{32}}"
        if re.fullmatch(pattern, self.root) is None:
            raise ValueError(f"invalid {self.prefix} identifier")
        return self

    @classmethod
    def new(cls) -> OpaqueId:
        return cls(root=f"{cls.prefix}_{uuid4().hex}")

    def __str__(self) -> str:
        return self.root


class CaseId(OpaqueId):
    prefix = "case"


class TargetId(OpaqueId):
    prefix = "target"


class EvidenceId(OpaqueId):
    prefix = "ev"


class ArtifactId(OpaqueId):
    prefix = "artifact"


class ExecutionId(OpaqueId):
    prefix = "exec"


class EntityId(OpaqueId):
    prefix = "entity"


def stable_source_id(source_type: str, fields: Mapping[str, JsonValue]) -> str:
    """Return a stable identity for one record in an external evidence source."""

    canonical = json.dumps(
        {"source_type": source_type, "fields": dict(fields)},
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return f"src_{hashlib.sha256(canonical).hexdigest()}"
