"""Typed contracts for curated, offline diagnostic reference knowledge."""

from collections.abc import Iterable
from datetime import date
from enum import StrEnum
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import AliasChoices, Field, field_validator, model_validator

from systemsense.domain.evidence import FrozenModel


class KnowledgeNodeKind(StrEnum):
    SUBSYSTEM = "subsystem"
    CONDITION = "condition"
    MECHANISM = "mechanism"
    SYMPTOM = "symptom"
    OBSERVATION = "observation"


class KnowledgeRelationKind(StrEnum):
    CAN_CONTRIBUTE_TO = "can_contribute_to"
    CAN_PRESENT_AS = "can_present_as"
    DEPENDS_ON = "depends_on"
    INTERACTS_WITH = "interacts_with"
    DISTINGUISHED_BY = "distinguished_by"


class KnowledgeDirection(StrEnum):
    OUTGOING = "outgoing"
    INCOMING = "incoming"
    BOTH = "both"


class KnowledgeSource(FrozenModel):
    source_id: str = Field(pattern=r"^ks_[a-z0-9][a-z0-9_.-]{2,79}$")
    title: str = Field(min_length=1, max_length=240)
    publisher: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=10, max_length=500, pattern=r"^https://")
    usage_note: str = Field(min_length=1, max_length=500)


class KnowledgeNode(FrozenModel):
    node_id: str = Field(
        validation_alias=AliasChoices("node_id", "id"),
        pattern=r"^kn_[a-z0-9][a-z0-9_.-]{2,119}$",
    )
    label: str = Field(min_length=1, max_length=160)
    category: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    kind: KnowledgeNodeKind
    aliases: tuple[str, ...] = Field(default=(), max_length=16)


class KnowledgeCitation(FrozenModel):
    """Pinned source material reviewed for one reference relation."""

    source_id: str = Field(pattern=r"^ks_[a-z0-9][a-z0-9_.-]{2,79}$")
    revision: str = Field(
        pattern=(
            r"^(?:[0-9a-f]{40}(?:[0-9a-f]{24})?"
            r"|v?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?)$"
        )
    )
    section: str = Field(min_length=1, max_length=240)
    license_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,79}$")
    license_url: str = Field(min_length=10, max_length=500, pattern=r"^https://")
    pinned_url: str = Field(min_length=10, max_length=500, pattern=r"^https://")
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_pinned_locator(self) -> "KnowledgeCitation":
        parsed = urlsplit(self.pinned_url)
        if not parsed.hostname or parsed.username is not None or parsed.fragment:
            raise ValueError("pinned URL must identify an HTTPS source artifact without a fragment")
        location = unquote(parsed.path + "?" + parsed.query)
        if self.revision not in location:
            raise ValueError("pinned URL path or query must contain the cited revision")
        return self

    @field_validator("section")
    @classmethod
    def reject_blank_section(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            raise ValueError("citation section must be nonblank and trimmed")
        return value


class KnowledgeRelation(FrozenModel):
    """A sourced diagnostic reference, never a case fact or proof of cause."""

    relation_id: str = Field(
        validation_alias=AliasChoices("relation_id", "id"),
        pattern=r"^kr_[a-z0-9][a-z0-9_.-]{2,119}$",
    )
    source_node_id: str = Field(
        validation_alias=AliasChoices("source_node_id", "from"),
        pattern=r"^kn_[a-z0-9][a-z0-9_.-]{2,119}$",
    )
    target_node_id: str = Field(
        validation_alias=AliasChoices("target_node_id", "to"),
        pattern=r"^kn_[a-z0-9][a-z0-9_.-]{2,119}$",
    )
    relationship: KnowledgeRelationKind = Field(
        validation_alias=AliasChoices("relationship", "kind")
    )
    mechanism: str = Field(min_length=12, max_length=1000)
    conditions: tuple[str, ...] = Field(
        validation_alias=AliasChoices("conditions", "when"), min_length=1, max_length=8
    )
    symptoms: tuple[str, ...] = Field(default=(), max_length=8)
    distinguishing_probe_ids: tuple[str, ...] = Field(
        validation_alias=AliasChoices("distinguishing_probe_ids", "probes"),
        min_length=1,
        max_length=8,
    )
    counterevidence: tuple[str, ...] = Field(
        validation_alias=AliasChoices("counterevidence", "counter"),
        min_length=1,
        max_length=8,
    )
    limitations: tuple[str, ...] = Field(
        validation_alias=AliasChoices("limitations", "limits"), min_length=1, max_length=8
    )
    applicability: tuple[str, ...] = Field(
        validation_alias=AliasChoices("applicability", "applies"),
        min_length=1,
        max_length=8,
    )
    source_ids: tuple[str, ...] = Field(
        validation_alias=AliasChoices("source_ids", "sources"), min_length=1, max_length=8
    )
    reviewed_at: str | None = Field(
        default=None, pattern=r"^\d{4}-\d{2}-\d{2}$", exclude_if=lambda value: value is None
    )
    citations: tuple[KnowledgeCitation, ...] = Field(
        default=(), max_length=8, exclude_if=lambda value: not value
    )

    @field_validator("reviewed_at")
    @classmethod
    def validate_reviewed_date(cls, value: str | None) -> str | None:
        if value is not None:
            date.fromisoformat(value)
        return value

    @field_validator("distinguishing_probe_ids")
    @classmethod
    def validate_probe_names(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        import re

        if any(re.fullmatch(r"[a-z][a-z0-9_.-]*", value) is None for value in values):
            raise ValueError("distinguishing probe IDs must be typed names")
        return values


class ReferencePack(FrozenModel):
    schema_version: Literal[1, 2] = 1
    pack_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    version: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=200)
    reviewed_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    disclaimer: str = Field(min_length=20, max_length=1000)
    sources: tuple[KnowledgeSource, ...] = Field(min_length=1, max_length=128)
    nodes: tuple[KnowledgeNode, ...] = Field(min_length=1, max_length=512)
    relations: tuple[KnowledgeRelation, ...] = Field(min_length=1, max_length=2048)

    @field_validator("reviewed_at")
    @classmethod
    def validate_pack_review_date(cls, value: str) -> str:
        date.fromisoformat(value)
        return value

    @model_validator(mode="after")
    def validate_unique_ids(self) -> "ReferencePack":
        _require_unique((item.source_id for item in self.sources), "source")
        _require_unique((item.node_id for item in self.nodes), "node")
        _require_unique((item.relation_id for item in self.relations), "relation")
        for relation in self.relations:
            if self.schema_version == 1:
                if {"reviewed_at", "citations"}.intersection(relation.model_fields_set):
                    raise ValueError("schema v1 relations cannot contain pinned provenance")
                continue
            if relation.reviewed_at is None or not relation.citations:
                raise ValueError(f"relation {relation.relation_id} lacks v2 provenance")
            source_ids = set(relation.source_ids)
            citation_ids = [citation.source_id for citation in relation.citations]
            if len(source_ids) != len(relation.source_ids) or set(citation_ids) != source_ids:
                raise ValueError(f"relation {relation.relation_id} citations must match sources")
            _require_unique(citation_ids, "citation source")
        return self


class KnowledgeQuery(FrozenModel):
    keywords: tuple[str, ...] = Field(default=(), max_length=8)
    categories: tuple[str, ...] = Field(default=(), max_length=16)
    node_ids: tuple[str, ...] = Field(default=(), max_length=32)
    relationship_kinds: tuple[KnowledgeRelationKind, ...] = Field(default=(), max_length=8)
    probe_ids: tuple[str, ...] = Field(default=(), max_length=16)
    max_relations: int = Field(default=24, ge=1, le=64)
    max_chars: int = Field(default=32_000, ge=1024, le=100_000)

    @field_validator("keywords")
    @classmethod
    def normalize_keywords(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(" ".join(value.casefold().split()) for value in values)
        if any(not value or len(value) > 80 for value in normalized):
            raise ValueError("keywords must contain 1 to 80 nonblank characters")
        return normalized


class KnowledgePacket(FrozenModel):
    pack_id: str
    pack_version: int
    nodes: tuple[KnowledgeNode, ...]
    relations: tuple[KnowledgeRelation, ...]
    sources: tuple[KnowledgeSource, ...]
    truncated: bool
    omitted_relation_count: int = Field(ge=0)
    limitations: tuple[str, ...]
    disclaimer: str


def _require_unique(values: Iterable[str], label: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise ValueError(f"duplicate {label} ID: {value}")
        seen.add(value)
