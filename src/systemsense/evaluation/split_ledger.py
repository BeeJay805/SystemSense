"""Versioned, metadata-only split custody across many review shards.

This checks grouping consistency, not label authenticity, consent, privacy,
worker-token parity, or training admission. No case text is stored.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.probes import ProbeManifest
from systemsense.evaluation.attention_labels import (
    ExpertAttentionLabel,
    validate_group_splits,
)

_SCHEMA_VERSION = 1
_MAX_SHARD_LABELS = 500


class SplitLedgerManifest(FrozenModel):
    schema_version: Literal[1] = 1
    corpus_id: str
    total_labels: int = Field(ge=0)
    split_counts: dict[str, int]
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    training_admissible: Literal[False] = False


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _groups(label: ExpertAttentionLabel) -> tuple[tuple[str, str], ...]:
    keys = label.split_keys
    result = [
        ("case", str(keys.case_id)),
        ("machine", keys.machine_key),
        ("fault_family", keys.fault_family),
    ]
    if keys.application_key is not None:
        result.append(("application", keys.application_key))
        if keys.application_version is not None:
            result.append(
                ("application_version", f"{keys.application_key}:{keys.application_version}")
            )
    return tuple(result)


class SplitGroupLedger:
    """Atomic, reopenable global split assignments for bounded label shards."""

    def __init__(self, path: Path, *, corpus_id: str) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{0,119}", corpus_id) is None:
            raise ValueError("corpus ID is invalid")
        self._connection = sqlite3.connect(path, timeout=5)
        try:
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in {0, _SCHEMA_VERSION}:
                raise ValueError("split ledger schema is unsupported")
            if (
                version == 0
                and self._connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name LIKE 'split_ledger_%' LIMIT 1"
                ).fetchone()
            ):
                raise ValueError("unversioned split ledger is unsupported")
            self._connection.execute("PRAGMA journal_mode=WAL")
            with self._connection:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS split_ledger_metadata ("
                    "corpus_id TEXT NOT NULL PRIMARY KEY)"
                )
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS split_ledger_labels ("
                    "label_id TEXT NOT NULL PRIMARY KEY, split TEXT NOT NULL, "
                    "label_sha256 TEXT NOT NULL)"
                )
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS split_ledger_groups ("
                    "kind TEXT NOT NULL, value_sha256 TEXT NOT NULL, split TEXT NOT NULL, "
                    "PRIMARY KEY(kind, value_sha256))"
                )
                existing = self._connection.execute(
                    "SELECT corpus_id FROM split_ledger_metadata"
                ).fetchall()
                if existing and existing != [(corpus_id,)]:
                    raise ValueError("split ledger belongs to another corpus")
                if not existing:
                    self._connection.execute(
                        "INSERT INTO split_ledger_metadata(corpus_id) VALUES (?)", (corpus_id,)
                    )
                self._connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            self._corpus_id = corpus_id
        except BaseException:
            self._connection.close()
            raise

    def __enter__(self) -> SplitGroupLedger:
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def admit(
        self,
        splits: Mapping[str, Sequence[ExpertAttentionLabel]],
        *,
        trusted_catalog: Mapping[str, ProbeManifest],
    ) -> SplitLedgerManifest:
        """Admit one shard atomically; an unchanged replay is idempotent."""

        flattened = tuple((split, label) for split, labels in splits.items() for label in labels)
        if not 1 <= len(flattened) <= _MAX_SHARD_LABELS:
            raise ValueError("split shard requires between 1 and 500 labels")
        validate_group_splits(splits, trusted_catalog)
        for split, label in flattened:
            if re.fullmatch(r"[a-z][a-z0-9_-]{0,39}", split) is None:
                raise ValueError("split name is invalid")
            ExpertAttentionLabel.model_validate(label.model_dump(mode="json"))
            if label.schema_version != 2 or label.synthetic or label.label_origin != "human_expert":
                raise ValueError("split ledger requires version 2 non-synthetic expert metadata")

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            for split, label in flattened:
                label_hash = _digest(label.model_dump(mode="json"))
                row = self._connection.execute(
                    "SELECT split, label_sha256 FROM split_ledger_labels WHERE label_id = ?",
                    (label.label_id,),
                ).fetchone()
                if row is not None and row != (split, label_hash):
                    raise ValueError("existing label changed or crossed splits")
                if row is None:
                    self._connection.execute(
                        "INSERT INTO split_ledger_labels(label_id, split, label_sha256) "
                        "VALUES (?, ?, ?)",
                        (label.label_id, split, label_hash),
                    )
                for kind, value in _groups(label):
                    value_hash = _digest([kind, value])
                    group = self._connection.execute(
                        "SELECT split FROM split_ledger_groups WHERE kind = ? AND value_sha256 = ?",
                        (kind, value_hash),
                    ).fetchone()
                    if group is not None and group[0] != split:
                        raise ValueError(f"{kind} group crosses split shards")
                    if group is None:
                        self._connection.execute(
                            "INSERT INTO split_ledger_groups(kind, value_sha256, split) "
                            "VALUES (?, ?, ?)",
                            (kind, value_hash, split),
                        )
            result = self._manifest()
            self._connection.commit()
            return result
        except BaseException:
            self._connection.rollback()
            raise

    def manifest(self) -> SplitLedgerManifest:
        """Recompute the full identity from durable metadata after reopening."""

        self._connection.execute("BEGIN")
        try:
            result = self._manifest()
            self._connection.commit()
            return result
        except BaseException:
            self._connection.rollback()
            raise

    def verify_manifest(self, *, expected_sha256: str) -> None:
        """Compare against an externally retained identity, not an authentication proof."""

        if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
            raise ValueError("expected manifest digest is invalid")
        if self.manifest().manifest_sha256 != expected_sha256:
            raise ValueError("split manifest identity does not match")

    def _manifest(self) -> SplitLedgerManifest:
        labels = self._connection.execute(
            "SELECT label_id, split, label_sha256 FROM split_ledger_labels ORDER BY label_id"
        ).fetchall()
        groups = self._connection.execute(
            "SELECT kind, value_sha256, split FROM split_ledger_groups ORDER BY kind, value_sha256"
        ).fetchall()
        counts: dict[str, int] = {}
        for _, split, _ in labels:
            counts[split] = counts.get(split, 0) + 1
        return SplitLedgerManifest(
            corpus_id=self._corpus_id,
            total_labels=len(labels),
            split_counts=counts,
            manifest_sha256=_digest(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "corpus_id": self._corpus_id,
                    "labels": labels,
                    "groups": groups,
                }
            ),
        )
