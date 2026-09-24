"""Global, metadata-only split custody for candidate-ID pilot shards.

This ledger prevents declared group overlap across shards. The pilot's source
keys and artifact hashes are caller claims, not authenticated machine or fault
identities; no row here is a training label or admission decision.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Literal

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.evaluation.pilot_corpus import PilotCorpus, PilotSplitGroup, verify_pilot_corpus

_SCHEMA_VERSION = 1
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TABLES = {
    "pilot_split_metadata",
    "pilot_split_shards",
    "pilot_split_episodes",
    "pilot_split_groups",
}


class PilotSplitLedgerManifest(FrozenModel):
    schema_version: Literal[1] = 1
    corpus_id: str
    shard_count: int = Field(ge=0)
    total_episodes: int = Field(ge=0)
    split_counts: dict[str, int]
    source_counts: dict[str, int]
    split_group_count: int = Field(ge=0)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_authenticity: Literal["not_verified"] = "not_verified"
    training_admissible: Literal[False] = False
    diagnostic_performance_admissible: Literal[False] = False


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class PilotSplitLedger:
    """Persist complete candidate-ID pilot shards and reject cross-shard leaks."""

    def __init__(self, path: Path, *, corpus_id: str) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_.-]{0,119}", corpus_id) is None:
            raise ValueError("pilot split corpus ID is invalid")
        self._connection = sqlite3.connect(path, timeout=5)
        try:
            version = int(self._connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, _SCHEMA_VERSION):
                raise ValueError("pilot split ledger schema is unsupported")
            tables = {
                str(row[0])
                for row in self._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                ).fetchall()
            }
            if (version == 0 and tables) or (version == _SCHEMA_VERSION and tables != _TABLES):
                raise ValueError("pilot split ledger requires a dedicated versioned database")
            self._connection.execute("PRAGMA journal_mode=WAL")
            with self._connection:
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS pilot_split_metadata ("
                    "corpus_id TEXT NOT NULL PRIMARY KEY)"
                )
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS pilot_split_shards ("
                    "shard_sha256 TEXT NOT NULL PRIMARY KEY, "
                    "split_manifest_sha256 TEXT NOT NULL, episode_count INTEGER NOT NULL)"
                )
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS pilot_split_episodes ("
                    "snapshot_id TEXT NOT NULL PRIMARY KEY, "
                    "case_id TEXT NOT NULL, shard_sha256 TEXT NOT NULL, "
                    "episode_sha256 TEXT NOT NULL, "
                    "split TEXT NOT NULL, source_kind TEXT NOT NULL, "
                    "groups_json TEXT NOT NULL, "
                    "FOREIGN KEY(shard_sha256) REFERENCES pilot_split_shards(shard_sha256))"
                )
                self._connection.execute(
                    "CREATE TABLE IF NOT EXISTS pilot_split_groups ("
                    "kind TEXT NOT NULL, value_sha256 TEXT NOT NULL, split TEXT NOT NULL, "
                    "PRIMARY KEY(kind, value_sha256))"
                )
                owner = self._connection.execute(
                    "SELECT corpus_id FROM pilot_split_metadata"
                ).fetchall()
                if owner and owner != [(corpus_id,)]:
                    raise ValueError("pilot split ledger belongs to another corpus")
                if not owner:
                    self._connection.execute(
                        "INSERT INTO pilot_split_metadata(corpus_id) VALUES (?)", (corpus_id,)
                    )
                self._connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            self._corpus_id = corpus_id
        except BaseException:
            self._connection.close()
            raise

    def __enter__(self) -> PilotSplitLedger:
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def admit(self, corpus: PilotCorpus) -> PilotSplitLedgerManifest:
        """Atomically admit one structurally valid shard; exact replay is idempotent."""

        # Copy before validation so caller-owned nested dicts cannot change during
        # the transaction. The pilot verifier checks counts and all self-hashes.
        frozen = PilotCorpus.model_validate_json(corpus.model_dump_json())
        shard_sha = verify_pilot_corpus(frozen)
        for episode in frozen.episodes:
            groups = {group.kind: group.value_sha256 for group in episode.split_groups}
            if not {"case", "machine", "fault_family"} <= groups.keys() or (
                "application_version" in groups and "application" not in groups
            ):
                raise ValueError("pilot episode required split groups are missing")
            if groups["case"] != _digest(["case", episode.case_id]):
                raise ValueError("pilot case group is not bound to case ID")
        rows = tuple(
            (
                episode.snapshot_id,
                episode.case_id,
                shard_sha,
                _digest(episode.model_dump(mode="json")),
                episode.split,
                episode.source_kind,
                _canonical([group.model_dump(mode="json") for group in episode.split_groups]),
            )
            for episode in frozen.episodes
        )
        group_rows = tuple(
            (group.kind, group.value_sha256, group.split) for group in frozen.split_groups
        )
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing_shard = self._connection.execute(
                "SELECT split_manifest_sha256, episode_count FROM pilot_split_shards "
                "WHERE shard_sha256=?",
                (shard_sha,),
            ).fetchone()
            if existing_shard is not None:
                if existing_shard != (frozen.split_manifest_sha256, len(rows)):
                    raise ValueError("pilot split shard identity changed")
                existing_rows = self._connection.execute(
                    "SELECT snapshot_id, case_id, shard_sha256, episode_sha256, "
                    "split, source_kind, "
                    "groups_json FROM pilot_split_episodes WHERE shard_sha256=? "
                    "ORDER BY snapshot_id",
                    (shard_sha,),
                ).fetchall()
                if existing_rows != sorted(rows):
                    raise ValueError("pilot split shard replay differs from stored episodes")
            else:
                for snapshot_id, *_ in rows:
                    if self._connection.execute(
                        "SELECT 1 FROM pilot_split_episodes WHERE snapshot_id=?", (snapshot_id,)
                    ).fetchone():
                        raise ValueError("pilot snapshot changed or belongs to a different shard")
                for kind, value_sha, split in group_rows:
                    previous = self._connection.execute(
                        "SELECT split FROM pilot_split_groups WHERE kind=? AND value_sha256=?",
                        (kind, value_sha),
                    ).fetchone()
                    if previous is not None and previous[0] != split:
                        raise ValueError(f"{kind} group crosses split shards")
                self._connection.execute(
                    "INSERT INTO pilot_split_shards(shard_sha256, split_manifest_sha256, "
                    "episode_count) VALUES (?, ?, ?)",
                    (shard_sha, frozen.split_manifest_sha256, len(rows)),
                )
                self._connection.executemany(
                    "INSERT INTO pilot_split_episodes(snapshot_id, case_id, shard_sha256, "
                    "episode_sha256, split, source_kind, groups_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
                self._connection.executemany(
                    "INSERT OR IGNORE INTO pilot_split_groups(kind, value_sha256, split) "
                    "VALUES (?, ?, ?)",
                    group_rows,
                )
            result = self._manifest()
            self._connection.commit()
            return result
        except BaseException:
            self._connection.rollback()
            raise

    def manifest(self) -> PilotSplitLedgerManifest:
        self._connection.execute("BEGIN")
        try:
            result = self._manifest()
            self._connection.commit()
            return result
        except BaseException:
            self._connection.rollback()
            raise

    def verify_manifest(self, *, expected_sha256: str) -> None:
        """Compare durable metadata to a separately retained exact identity."""

        if _DIGEST.fullmatch(expected_sha256) is None:
            raise ValueError("pilot split manifest expected identity is invalid")
        if self.manifest().manifest_sha256 != expected_sha256:
            raise ValueError("pilot split manifest identity differs")

    def _manifest(self) -> PilotSplitLedgerManifest:
        shards = self._connection.execute(
            "SELECT shard_sha256, split_manifest_sha256, episode_count "
            "FROM pilot_split_shards ORDER BY shard_sha256"
        ).fetchall()
        episodes = self._connection.execute(
            "SELECT snapshot_id, case_id, shard_sha256, episode_sha256, split, source_kind, "
            "groups_json FROM pilot_split_episodes ORDER BY snapshot_id"
        ).fetchall()
        groups = self._connection.execute(
            "SELECT kind, value_sha256, split FROM pilot_split_groups ORDER BY kind, value_sha256"
        ).fetchall()
        shard_counts = {str(row[0]): int(row[2]) for row in shards}
        seen_by_shard = {key: 0 for key in shard_counts}
        derived_groups: dict[tuple[str, str], str] = {}
        split_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}
        for (
            snapshot_id,
            case_id,
            shard_sha,
            episode_sha,
            split,
            source_kind,
            groups_json,
        ) in episodes:
            if (
                not isinstance(snapshot_id, str)
                or not isinstance(case_id, str)
                or not isinstance(shard_sha, str)
                or not isinstance(episode_sha, str)
                or shard_sha not in seen_by_shard
            ):
                raise ValueError("pilot split episode custody is invalid")
            seen_by_shard[shard_sha] += 1
            split_counts[split] = split_counts.get(split, 0) + 1
            source_counts[source_kind] = source_counts.get(source_kind, 0) + 1
            try:
                raw_groups = json.loads(groups_json)
                bound_groups = tuple(PilotSplitGroup.model_validate(item) for item in raw_groups)
            except (TypeError, ValueError) as error:
                raise ValueError("pilot split episode group custody is invalid") from error
            if not 3 <= len(bound_groups) <= 5 or len({item.kind for item in bound_groups}) != len(
                bound_groups
            ):
                raise ValueError("pilot split episode groups are incomplete")
            kinds = {item.kind for item in bound_groups}
            if not {"case", "machine", "fault_family"} <= kinds or (
                "application_version" in kinds and "application" not in kinds
            ):
                raise ValueError("pilot episode required split groups are missing")
            case_group = next(item for item in bound_groups if item.kind == "case")
            if case_group.value_sha256 != _digest(["case", case_id]):
                raise ValueError("pilot case group is not bound to case ID")
            for group in bound_groups:
                if group.split != split:
                    raise ValueError("pilot split episode group changed split")
                key = (group.kind, group.value_sha256)
                previous = derived_groups.setdefault(key, split)
                if previous != split:
                    raise ValueError("pilot split group crosses stored splits")
        if seen_by_shard != shard_counts:
            raise ValueError("pilot split shard episode count differs")
        if groups != [
            (kind, value_sha, split) for (kind, value_sha), split in sorted(derived_groups.items())
        ]:
            raise ValueError("pilot split group index differs from episode custody")
        return PilotSplitLedgerManifest(
            corpus_id=self._corpus_id,
            shard_count=len(shards),
            total_episodes=len(episodes),
            split_counts=dict(sorted(split_counts.items())),
            source_counts=dict(sorted(source_counts.items())),
            split_group_count=len(groups),
            manifest_sha256=_digest(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "corpus_id": self._corpus_id,
                    "shards": shards,
                    "episodes": episodes,
                    "groups": groups,
                }
            ),
        )
