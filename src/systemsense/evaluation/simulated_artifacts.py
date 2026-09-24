"""Bounded, reproducible local artifacts for toy contract episodes only.

Hashes detect accidental changes and support replay; they do not authenticate a
real-world source or make these episodes training or performance evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.evaluation.simulated_pilot import (
    SimulatedEpisode,
    generate_simulated_episode,
    scenario_ids,
    validate_simulated_splits,
    verify_simulated_episode,
)

_DIGEST = r"^[0-9a-f]{64}$"
_MAX_ARTIFACT_BYTES = 1_000_000


class _Record(FrozenModel):
    scenario_id: str
    selected_probe_ids: tuple[str, ...]
    source_kind: Literal["deterministic_toy_simulator"] = "deterministic_toy_simulator"
    label_quality: Literal["simulated_oracle_contract_only"] = "simulated_oracle_contract_only"
    episode: SimulatedEpisode
    record_sha256: str = Field(pattern=_DIGEST)


class _Corpus(FrozenModel):
    schema_version: Literal[1] = 1
    classification: Literal["simulated_contract_only"] = "simulated_contract_only"
    source_kind: Literal["deterministic_toy_simulator"] = "deterministic_toy_simulator"
    training_admissible: Literal[False] = False
    diagnostic_performance_admissible: Literal[False] = False
    scenario_ids: tuple[str, ...]
    records: tuple[_Record, ...]


class _SplitGroup(FrozenModel):
    kind: str
    value_sha256: str = Field(pattern=_DIGEST)
    split: str


class _LabelCounts(FrozenModel):
    observed_useful: int = Field(ge=0)
    observed_negative: int = Field(ge=0)
    unavailable_unknown: int = Field(ge=0)
    unrun_unknown: int = Field(ge=0)
    total_unknown: int = Field(ge=0)


class _Manifest(FrozenModel):
    schema_version: Literal[1] = 1
    classification: Literal["simulated_contract_only"] = "simulated_contract_only"
    source_kind: Literal["deterministic_toy_simulator"] = "deterministic_toy_simulator"
    training_admissible: Literal[False] = False
    diagnostic_performance_admissible: Literal[False] = False
    scenario_ids: tuple[str, ...]
    record_count: int = Field(ge=1, le=32)
    candidate_count: int = Field(ge=1, le=512)
    label_quality_counts: _LabelCounts
    split_group_manifest: tuple[_SplitGroup, ...]
    record_sha256: tuple[str, ...]
    corpus_sha256: str = Field(pattern=_DIGEST)
    manifest_sha256: str = Field(pattern=_DIGEST)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _build(
    selections: Mapping[str, tuple[str, ...]], splits: Mapping[str, str]
) -> tuple[_Corpus, _Manifest]:
    ids = scenario_ids()
    unknown = (set(selections) | set(splits)) - set(ids)
    if unknown:
        raise ValueError("unknown simulated scenario")
    episodes = tuple(
        generate_simulated_episode(
            scenario_id,
            split=splits.get(scenario_id, "fixture"),
            executed_probe_ids=selections.get(scenario_id, ()),
        )
        for scenario_id in ids
    )
    validate_simulated_splits(episodes)
    records = tuple(
        _Record(
            scenario_id=episode.scenario_id,
            selected_probe_ids=selections.get(episode.scenario_id, ()),
            episode=episode,
            record_sha256=_digest(
                {
                    "scenario_id": episode.scenario_id,
                    "selected_probe_ids": selections.get(episode.scenario_id, ()),
                    "source_kind": "deterministic_toy_simulator",
                    "label_quality": "simulated_oracle_contract_only",
                    "episode": episode.model_dump(mode="json"),
                }
            ),
        )
        for episode in episodes
    )
    corpus = _Corpus(scenario_ids=ids, records=records)
    labels = tuple(item for episode in episodes for item in episode.adjudications)
    counts = _LabelCounts(
        observed_useful=sum(
            item.status == "observed" and item.utility == "useful" for item in labels
        ),
        observed_negative=sum(
            item.status == "observed" and item.utility == "negative" for item in labels
        ),
        unavailable_unknown=sum(item.status == "unavailable" for item in labels),
        unrun_unknown=sum(item.status == "unrun" for item in labels),
        total_unknown=sum(item.utility == "unknown" for item in labels),
    )
    groups = tuple(
        _SplitGroup(kind=kind, value_sha256=digest, split=split)
        for kind, digest, split in sorted(
            {
                (key.kind, key.value_sha256, episode.split)
                for episode in episodes
                for key in episode.split_keys
            }
        )
    )
    manifest_body: dict[str, object] = {
        "schema_version": 1,
        "classification": "simulated_contract_only",
        "source_kind": "deterministic_toy_simulator",
        "training_admissible": False,
        "diagnostic_performance_admissible": False,
        "scenario_ids": ids,
        "record_count": len(records),
        "candidate_count": len(labels),
        "label_quality_counts": counts.model_dump(mode="json"),
        "split_group_manifest": [item.model_dump(mode="json") for item in groups],
        "record_sha256": tuple(item.record_sha256 for item in records),
        "corpus_sha256": _digest(corpus.model_dump(mode="json")),
    }
    manifest = _Manifest.model_validate(
        {**manifest_body, "manifest_sha256": _digest(manifest_body)}
    )
    return corpus, manifest


def write_simulated_artifacts(
    output_dir: Path,
    *,
    selections: Mapping[str, tuple[str, ...]] | None = None,
    splits: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Create two local files in one new directory; never overwrite an artifact."""
    corpus, manifest = _build(selections or {}, splits or {})
    corpus_payload = _canonical_bytes(corpus.model_dump(mode="json")) + b"\n"
    manifest_payload = _canonical_bytes(manifest.model_dump(mode="json")) + b"\n"
    if len(corpus_payload) > _MAX_ARTIFACT_BYTES or len(manifest_payload) > _MAX_ARTIFACT_BYTES:
        raise ValueError("simulated artifact exceeds size bound")
    target = output_dir.resolve(strict=False)
    if not target.parent.is_dir():
        raise ValueError("simulated artifact parent directory does not exist")
    target.mkdir(parents=False, exist_ok=False)
    with (target / "corpus.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(corpus_payload.decode("utf-8"))
    with (target / "run_manifest.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(manifest_payload.decode("utf-8"))
    return manifest.model_dump(mode="json")


def verify_simulated_artifacts(output_dir: Path) -> dict[str, Any]:
    """Check bounded local readback, exact toy replay, counts, and all hashes."""
    try:
        target = output_dir.resolve(strict=True)
        with (target / "corpus.json").open("rb") as stream:
            corpus_bytes = stream.read(_MAX_ARTIFACT_BYTES + 1)
        with (target / "run_manifest.json").open("rb") as stream:
            manifest_bytes = stream.read(_MAX_ARTIFACT_BYTES + 1)
        if len(corpus_bytes) > _MAX_ARTIFACT_BYTES or len(manifest_bytes) > _MAX_ARTIFACT_BYTES:
            raise ValueError("simulated artifact exceeds size bound")
        corpus = _Corpus.model_validate_json(corpus_bytes)
        manifest = _Manifest.model_validate_json(manifest_bytes)
        if corpus.scenario_ids != scenario_ids() or len(corpus.records) != len(corpus.scenario_ids):
            raise ValueError("simulated scenario catalog differs")
        for record in corpus.records:
            verify_simulated_episode(record.episode)
        expected_corpus, expected_manifest = _build(
            {record.scenario_id: record.selected_probe_ids for record in corpus.records},
            {record.scenario_id: record.episode.split for record in corpus.records},
        )
        if corpus != expected_corpus or manifest != expected_manifest:
            raise ValueError("simulated artifact differs from deterministic replay")
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("simulated artifact verification failed") from error
    return manifest.model_dump(mode="json")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Write non-trainable deterministic toy episodes")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--select", action="append", default=[], metavar="SCENARIO:PROBE")
    args = parser.parse_args(argv)
    chosen: dict[str, list[str]] = {}
    for entry in args.select:
        scenario_id, separator, probe_id = entry.partition(":")
        if not separator or not scenario_id or not probe_id:
            parser.error("--select must be SCENARIO:PROBE")
        chosen.setdefault(scenario_id, []).append(probe_id)
    manifest = write_simulated_artifacts(
        args.output_dir, selections={key: tuple(value) for key, value in chosen.items()}
    )
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
