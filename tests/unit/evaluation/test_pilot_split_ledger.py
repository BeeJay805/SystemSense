"""Global split custody for candidate-ID pilot shards, without training admission."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from systemsense.evaluation.pilot_corpus import (
    GroupKind,
    PilotCandidateRecord,
    PilotCorpus,
    PilotEpisodeRecord,
    PilotSplitGroup,
    _digest,  # pyright: ignore[reportPrivateUsage]
    _manifest_content,  # pyright: ignore[reportPrivateUsage]
    _split_digest,  # pyright: ignore[reportPrivateUsage]
    verify_pilot_corpus,
)
from systemsense.evaluation.pilot_fixture import write_fixture_corpus
from systemsense.evaluation.pilot_split_ledger import PilotSplitLedger
from systemsense.evaluation.split_ledger import SplitGroupLedger


def _corpus(
    ordinal: int,
    *,
    split: str = "train",
    machine: str = "machine-a",
    family: str = "wifi",
    application: str = "browser",
    source_kind: str = "fixture_contract",
) -> PilotCorpus:
    case_id = f"case_{ordinal:032x}"
    groups = tuple(
        PilotSplitGroup(
            kind=cast(GroupKind, kind), value_sha256=_digest([kind, value]), split=split
        )
        for kind, value in sorted(
            (
                ("case", case_id),
                ("machine", machine),
                ("fault_family", family),
                ("application", application),
                ("application_version", f"{application}:1"),
            )
        )
    )
    episode = PilotEpisodeRecord(
        snapshot_id=f"candidate_decision_snapshot_{ordinal:032x}",
        case_id=case_id,
        epoch_state_version=1,
        split=split,
        source_kind=source_kind,  # type: ignore[arg-type]
        source_artifact_sha256=_digest(["artifact", ordinal]),
        request_sha256=_digest(["request", ordinal]),
        response_sha256=_digest(["response", ordinal]),
        candidate_manifest_sha256=_digest(["manifest", ordinal]),
        registry_manifest_sha256=_digest(["registry", ordinal]),
        split_groups=groups,
        candidates=(
            PilotCandidateRecord(
                candidate_id=f"cand_v1_{ordinal:032x}",
                probe_id="network.connectivity",
                manifest_sha256=_digest("manifest"),
                invocation_sha256=_digest(["invocation", ordinal]),
                description_sha256=_digest("description"),
                dispatch_status="not_admitted",
            ),
        ),
    )
    provisional = PilotCorpus(
        episodes=(episode,),
        source_counts={source_kind: 1},
        label_quality_counts={"unknown": 1},
        split_counts={split: 1},
        split_groups=groups,
        split_manifest_sha256=_split_digest(groups),
        manifest_sha256="0" * 64,
    )
    corpus = provisional.model_copy(
        update={"manifest_sha256": _digest(_manifest_content(provisional))}
    )
    verify_pilot_corpus(corpus)
    return corpus


def test_admits_distinct_shards_and_replays_exact_shard_after_reopen(tmp_path: Path) -> None:
    path = tmp_path / "pilot_splits.db"
    train = _corpus(1)
    heldout = _corpus(2, split="test", machine="machine-b", family="pdf", application="reader")
    with PilotSplitLedger(path, corpus_id="pilot_v1") as ledger:
        first = ledger.admit(train)
        second = ledger.admit(heldout)
        assert second.total_episodes == 2
        assert second.shard_count == 2
        assert second.split_counts == {"test": 1, "train": 1}
        assert second.source_counts == {"fixture_contract": 2}
        assert second.training_admissible is False
        assert second.source_authenticity == "not_verified"
        assert first.manifest_sha256 != second.manifest_sha256
    with PilotSplitLedger(path, corpus_id="pilot_v1") as ledger:
        assert ledger.admit(train) == second
        ledger.verify_manifest(expected_sha256=second.manifest_sha256)


def test_real_fixture_pipeline_admits_only_nontrainable_metadata(tmp_path: Path) -> None:
    output_dir = tmp_path / "fixture"
    write_fixture_corpus(output_dir)
    corpus = PilotCorpus.model_validate_json((output_dir / "corpus.json").read_text("utf-8"))
    with PilotSplitLedger(tmp_path / "fixture_splits.db", corpus_id="fixture_pilot") as ledger:
        manifest = ledger.admit(corpus)
        assert manifest.total_episodes == 1
        assert manifest.source_counts == {"fixture_contract": 1}
        assert manifest.split_counts == {"fixture": 1}
        assert manifest.training_admissible is False
        ledger.verify_manifest(expected_sha256=manifest.manifest_sha256)


@pytest.mark.parametrize(
    "shared", ["machine", "fault_family", "application", "application_version"]
)
def test_rejects_cross_shard_group_leakage_atomically(tmp_path: Path, shared: str) -> None:
    first = _corpus(1)
    kwargs = {"machine": "machine-b", "family": "pdf", "application": "reader"}
    if shared == "machine":
        kwargs["machine"] = "machine-a"
    elif shared == "fault_family":
        kwargs["family"] = "wifi"
    elif shared == "application":
        kwargs["application"] = "browser"
    else:
        # A shared version group necessarily has the same application group.
        kwargs["application"] = "browser"
    second = _corpus(2, split="test", **kwargs)
    path = tmp_path / "pilot_splits.db"
    with PilotSplitLedger(path, corpus_id="pilot_v1") as ledger:
        baseline = ledger.admit(first)
    with PilotSplitLedger(path, corpus_id="pilot_v1") as ledger:
        with pytest.raises(ValueError, match="group crosses split"):
            ledger.admit(second)
        assert ledger.manifest() == baseline


def test_same_snapshot_with_changed_shard_is_rejected(tmp_path: Path) -> None:
    first = _corpus(1)
    changed = _corpus(1, machine="machine-changed")
    with PilotSplitLedger(tmp_path / "pilot_splits.db", corpus_id="pilot_v1") as ledger:
        baseline = ledger.admit(first)
        with pytest.raises(ValueError, match=r"snapshot.*changed|snapshot.*different shard"):
            ledger.admit(changed)
        assert ledger.manifest() == baseline


def test_rejects_mutated_manifest_and_wrong_external_identity(tmp_path: Path) -> None:
    corpus = _corpus(1)
    with PilotSplitLedger(tmp_path / "pilot_splits.db", corpus_id="pilot_v1") as ledger:
        with pytest.raises(ValueError, match="manifest"):
            ledger.admit(corpus.model_copy(update={"manifest_sha256": "a" * 64}))
        manifest = ledger.admit(corpus)
        with pytest.raises(ValueError, match="identity"):
            ledger.verify_manifest(expected_sha256="b" * 64)
        ledger.verify_manifest(expected_sha256=manifest.manifest_sha256)


def test_rejects_wrong_corpus_owner(tmp_path: Path) -> None:
    path = tmp_path / "pilot_splits.db"
    with PilotSplitLedger(path, corpus_id="pilot_v1") as ledger:
        ledger.admit(_corpus(1))
    with pytest.raises(ValueError, match="another corpus"):
        PilotSplitLedger(path, corpus_id="other")


def test_rejects_another_schema_one_ledger_database(tmp_path: Path) -> None:
    path = tmp_path / "historical_probe_splits.db"
    with SplitGroupLedger(path, corpus_id="historical"):
        pass
    with pytest.raises(ValueError, match=r"dedicated.*database"):
        PilotSplitLedger(path, corpus_id="pilot_v1")


def test_rejects_structurally_valid_shard_without_fault_family_group(tmp_path: Path) -> None:
    corpus = _corpus(1)
    groups = tuple(item for item in corpus.split_groups if item.kind != "fault_family")
    episode = corpus.episodes[0].model_copy(update={"split_groups": groups})
    provisional = corpus.model_copy(
        update={
            "episodes": (episode,),
            "split_groups": groups,
            "split_manifest_sha256": _split_digest(groups),
        }
    )
    altered = provisional.model_copy(
        update={"manifest_sha256": _digest(_manifest_content(provisional))}
    )
    verify_pilot_corpus(altered)
    with PilotSplitLedger(tmp_path / "pilot_splits.db", corpus_id="pilot_v1") as ledger:
        with pytest.raises(ValueError, match=r"required.*groups"):
            ledger.admit(altered)


def test_rejects_case_group_digest_not_bound_to_case_id(tmp_path: Path) -> None:
    corpus = _corpus(1)
    groups = tuple(
        item.model_copy(update={"value_sha256": "f" * 64}) if item.kind == "case" else item
        for item in corpus.split_groups
    )
    episode = corpus.episodes[0].model_copy(update={"split_groups": groups})
    provisional = corpus.model_copy(
        update={
            "episodes": (episode,),
            "split_groups": groups,
            "split_manifest_sha256": _split_digest(groups),
        }
    )
    altered = provisional.model_copy(
        update={"manifest_sha256": _digest(_manifest_content(provisional))}
    )
    verify_pilot_corpus(altered)
    with PilotSplitLedger(tmp_path / "pilot_splits.db", corpus_id="pilot_v1") as ledger:
        with pytest.raises(ValueError, match=r"case group.*case ID"):
            ledger.admit(altered)
