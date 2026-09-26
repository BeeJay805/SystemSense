"""Reproduce a no-update Laya head rehearsal from two local research captures.

This command assigns deliberately synthetic opposite signs to two same-menu
measurements. It verifies mechanics, not diagnostic utility or training admission.
Never use its fixture signs as labels for a weight update.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from benchmarks.laya_exact_batch_parity import (
    _local_qualification,  # pyright: ignore[reportPrivateUsage]
    verify_weight_digest,
)
from benchmarks.laya_training_loader import (
    ExactFixtureBatch,
    SyntheticRehearsalPair,
    rehearse_exact_head_fixture,
)
from systemsense.inference.laya_runtime import LayaRuntimeConfig
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore


class ReadOnlySnapshotStore(SQLiteStore):
    """Use existing repository readback and validation without opening a writer."""

    def initialize(self) -> None:
        if self._connection is not None:  # pyright: ignore[reportPrivateUsage]
            return
        path = self.path.resolve(strict=True)
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        connection.execute("PRAGMA query_only=ON")
        self._connection = connection  # pyright: ignore[reportPrivateUsage]


@dataclass(frozen=True)
class FixtureCapture:
    batch: ExactFixtureBatch
    pair: SyntheticRehearsalPair
    source: dict[str, object]


def _object_dict(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} invalid")
    raw = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise ValueError(f"{name} invalid")
    return cast(dict[str, object], value)


def select_synthetic_pair_ids(
    request: dict[str, object], call: dict[str, object], *, observable: str
) -> tuple[str, str]:
    """Find two distinct target-bound measurements in one captured comparison.

    These identities only select a gradient-mechanics fixture. Their arbitrary
    positive/negative signs are explicitly not outcome labels.
    """

    raw_items = request.get("items")
    raw_semantics = request.get("item_semantics")
    raw_questions = call.get("questions")
    if (
        not isinstance(raw_items, list)
        or not isinstance(raw_semantics, list)
        or not isinstance(raw_questions, list)
    ):
        raise ValueError("captured request or comparison missing")
    items: dict[object, dict[str, object]] = {}
    for value in cast(list[object], raw_items):
        item = _object_dict(value, "item")
        items[item.get("item_id")] = item
    semantics: dict[object, dict[str, object]] = {}
    for value in cast(list[object], raw_semantics):
        semantic = _object_dict(value, "semantic")
        semantics[semantic.get("item_id")] = semantic
    if len(items) != len(cast(list[object], raw_items)) or len(semantics) != len(
        cast(list[object], raw_semantics)
    ):
        raise ValueError("captured item identity ambiguous")
    question_ids: list[str] = []
    for raw in cast(list[object], raw_questions):
        row = _object_dict(raw, "question row")
        if not isinstance(row.get("item_id"), str):
            raise ValueError("captured comparison identity invalid")
        question = _object_dict(row.get("question"), "question")
        if question.get("type") != "noul":
            raise ValueError("same complete comparison required")
        question_ids.append(cast(str, row["item_id"]))
    if len(set(question_ids)) != len(question_ids):
        raise ValueError("same complete comparison required")
    chosen: list[tuple[str, str]] = []
    for item_id in question_ids:
        item, semantic = items.get(item_id), semantics.get(item_id)
        if item is None or semantic is None:
            raise ValueError("same complete comparison required")
        reference, measurement = item.get("reference"), semantic.get("measurement")
        if not isinstance(reference, dict) or not isinstance(measurement, dict):
            continue
        typed_reference = _object_dict(cast(object, reference), "reference")
        typed_measurement = _object_dict(cast(object, measurement), "measurement")
        if (
            typed_reference.get("kind") != "measure"
            or typed_measurement.get("probe_id") != observable
        ):
            continue
        digest = typed_measurement.get("invocation_sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("measurement invocation identity invalid")
        chosen.append((item_id, digest))
    if len(chosen) < 2:
        raise ValueError("same complete comparison requires two measurements")
    if chosen[0][1] == chosen[1][1]:
        raise ValueError("distinct target or parameters required")
    return chosen[0][0], chosen[1][0]


def ordered_invocation_digests(
    request: dict[str, object], pair_ids: tuple[str, str]
) -> tuple[str, str]:
    raw = request.get("item_semantics")
    if not isinstance(raw, list):
        raise ValueError("measurement semantics missing")
    by_id = {
        row.get("item_id"): row
        for value in cast(list[object], raw)
        if (row := _object_dict(value, "measurement semantic"))
    }
    result: list[str] = []
    for item_id in pair_ids:
        row = by_id.get(item_id)
        if row is None:
            raise ValueError("measurement semantic missing")
        measurement = _object_dict(row.get("measurement"), "measurement")
        digest = measurement.get("invocation_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("measurement invocation identity invalid")
        result.append(digest)
    return result[0], result[1]


def load_capture_fixture(
    database: Path,
    snapshot_id: str,
    *,
    observable: str,
    split: Literal["train", "development"],
) -> FixtureCapture:
    """Read and revalidate one exact, unreviewed worker draft without writing DB."""

    if not database.is_file():
        raise FileNotFoundError("research capture database unavailable")
    with ReadOnlySnapshotStore(database) as store:
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(snapshot_id)
        draft = repository.readback_frontier_worker_draft(snapshot_id)
        trace = snapshot.response.presentation_trace
        if trace is None:
            raise ValueError("exact worker presentation unavailable")
        comparisons = [
            batch
            for batch in trace.microbatches
            if batch.phase == "compare" and batch.batch_index == 0
        ]
        if len(comparisons) != 1 or comparisons[0].worker_presentation is None:
            raise ValueError("same complete comparison unavailable")
        comparison = comparisons[0]
        presentation = comparison.worker_presentation
        if presentation is None:
            raise ValueError("comparison presentation unavailable")
        if comparison.cache_hit_ids or comparison.inference_ids != comparison.candidate_ids:
            raise ValueError("comparison was not fully captured")
        call = draft.captured_calls.get(("compare", 0))
        if call is None:
            raise ValueError("exact comparison worker input unavailable")
        request = snapshot.request.model_dump(mode="json")
        pair_ids = select_synthetic_pair_ids(request, call, observable=observable)
        pair = synthetic_marker_pair(
            snapshot_id=snapshot_id,
            candidate_ids=pair_ids,
            split=split,
            source_group_id=str(snapshot.case_id),
        )
        proof = presentation.model_dump(mode="json")
        return FixtureCapture(
            batch=ExactFixtureBatch(snapshot_id, "compare", 0, call, proof),
            pair=pair,
            source={
                "snapshot_id": snapshot_id,
                "case_id_sha256": hashlib.sha256(str(snapshot.case_id).encode()).hexdigest(),
                "capture_sha256": draft.capture_sha256,
                "comparison_question_count": len(cast(list[object], call["questions"])),
                "synthetic_pair_invocation_sha256": ordered_invocation_digests(request, pair_ids),
                "privacy_review_status": draft.privacy_review_status,
                "training_admissible": draft.training_admissible,
            },
        )


def _synthetic_marker(snapshot_id: str, candidate_id: str, role: str) -> str:
    return hashlib.sha256(
        json.dumps(
            ["systemsense-fixture-sign-only-v1", snapshot_id, candidate_id, role],
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def synthetic_marker_pair(
    *,
    snapshot_id: str,
    candidate_ids: tuple[str, str],
    split: Literal["train", "development"],
    source_group_id: str,
) -> SyntheticRehearsalPair:
    if candidate_ids[0] == candidate_ids[1] or not source_group_id:
        raise ValueError("distinct synthetic fixture pair and episode required")
    return SyntheticRehearsalPair(
        snapshot_id=snapshot_id,
        phase="compare",
        batch_index=0,
        useful_candidate_id=candidate_ids[0],
        uninformative_candidate_id=candidate_ids[1],
        positive_fixture_sha256=_synthetic_marker(
            snapshot_id, candidate_ids[0], "arbitrary-positive"
        ),
        negative_fixture_sha256=_synthetic_marker(
            snapshot_id, candidate_ids[1], "arbitrary-negative"
        ),
        split=split,
        source_group_id=source_group_id,
    )


def verify_synthetic_marker_pair(pair: SyntheticRehearsalPair) -> bool:
    return (
        pair.phase == "compare"
        and pair.batch_index == 0
        and pair.positive_fixture_sha256
        == _synthetic_marker(pair.snapshot_id, pair.useful_candidate_id, "arbitrary-positive")
        and pair.negative_fixture_sha256
        == _synthetic_marker(
            pair.snapshot_id, pair.uninformative_candidate_id, "arbitrary-negative"
        )
    )


def ensure_private_report_path(path: Path) -> Path:
    resolved = path.resolve()
    checkout = Path(__file__).resolve().parents[1]
    if resolved.is_relative_to(checkout):
        raise ValueError("rehearsal report must stay outside the checkout")
    if not resolved.parent.is_dir():
        raise ValueError("rehearsal report parent must already exist")
    return resolved


def fixture_admission_report(
    *,
    train_pair: SyntheticRehearsalPair,
    development_pair: SyntheticRehearsalPair,
    rehearsal_result: dict[str, object],
) -> dict[str, object]:
    if (
        train_pair.split != "train"
        or development_pair.split != "development"
        or train_pair.source_group_id == development_pair.source_group_id
        or not verify_synthetic_marker_pair(train_pair)
        or not verify_synthetic_marker_pair(development_pair)
        or rehearsal_result.get("status") != "fixture_only"
    ):
        raise ValueError("synthetic fixture rehearsal incomplete")
    before = rehearsal_result.get("parameters_sha256_before")
    after = rehearsal_result.get("parameters_sha256_after")
    if (
        rehearsal_result.get("trainable") is not False
        or rehearsal_result.get("weight_updates_performed") is not False
        or rehearsal_result.get("train_pairs") != 1
        or rehearsal_result.get("development_pairs") != 1
        or not isinstance(before, str)
        or re.fullmatch(r"[0-9a-f]{64}", before) is None
        or before != after
    ):
        raise ValueError("fixture rehearsal requires unchanged parameters and no update")
    return {
        "schema_version": 1,
        "status": "fixture_only",
        "trainable": False,
        "training_admission": "rejected_no_observed_outcomes",
        "synthetic_signs_are_outcome_labels": False,
        "weight_updates_performed": False,
        "split_basis": "distinct_simulator_episodes_same_fault_family",
        "held_out_performance_claim": False,
        "rehearsal": rehearsal_result,
    }


def run_fixture_rehearsal(
    *,
    model_path: Path,
    train_db: Path,
    train_snapshot: str,
    development_db: Path,
    development_snapshot: str,
    observable: str,
) -> dict[str, object]:
    """No optimizer or writer is constructed; all source labels are fake signs."""

    if train_db.resolve() == development_db.resolve() or train_snapshot == development_snapshot:
        raise ValueError("distinct research episodes required")
    train = load_capture_fixture(train_db, train_snapshot, observable=observable, split="train")
    development = load_capture_fixture(
        development_db, development_snapshot, observable=observable, split="development"
    )
    if train.pair.source_group_id == development.pair.source_group_id:
        raise ValueError("research episode split collision")
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    config = LayaRuntimeConfig(
        interpreter_path=Path(sys.executable).resolve(),
        model_path=model_path.resolve(strict=True),
        device="cpu",
    )
    install = config.validate_install()
    weight_path = config.model_path / "model.safetensors"
    verify_weight_digest(
        weight_path, expected_sha256=install.weight_sha256, expected_bytes=install.weight_bytes
    )
    with open(os.devnull, "w", encoding="utf-8") as sink:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            tokenizer, cfg, qualification = _local_qualification(config.model_path)
            qualification["model_weight_sha256"] = install.weight_sha256
            qualification["package_wheel_sha256"] = install.package_wheel_sha256
            worker = importlib.import_module("systemsense.inference.laya_worker")
            load_agent = worker._load_agent  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType, reportPrivateUsage]
            agent, _release = load_agent(config.model_path, 2, "cpu", 1536, "float32")
            model = agent.model
            first = rehearse_exact_head_fixture(
                (train.batch, development.batch),
                (train.pair, development.pair),
                tokenizer=tokenizer,
                cfg=cfg,
                qualification=qualification,
                model=model,
                verify_fixture_proof=verify_synthetic_marker_pair,
                seed=17,
                model_proof_mode="pinned_laya",
                max_batches=1,
            )
            final = rehearse_exact_head_fixture(
                (train.batch, development.batch),
                (train.pair, development.pair),
                tokenizer=tokenizer,
                cfg=cfg,
                qualification=qualification,
                model=model,
                verify_fixture_proof=verify_synthetic_marker_pair,
                seed=17,
                model_proof_mode="pinned_laya",
                resume=_object_dict(first["checkpoint"], "fixture checkpoint"),
            )
    verify_weight_digest(
        weight_path, expected_sha256=install.weight_sha256, expected_bytes=install.weight_bytes
    )
    report = fixture_admission_report(
        train_pair=train.pair,
        development_pair=development.pair,
        rehearsal_result=final,
    )
    report["model"] = {
        "package_version": qualification["package_version"],
        "model_revision": qualification["model_revision"],
        "weight_sha256": install.weight_sha256,
        "tokenizer_sha256": qualification["tokenizer_sha256"],
        "worker_sha256": qualification["worker_sha256"],
        "device": "cpu",
    }
    report["sources"] = [train.source, development.source]
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--train-db", type=Path, required=True)
    parser.add_argument("--train-snapshot", required=True)
    parser.add_argument("--development-db", type=Path, required=True)
    parser.add_argument("--development-snapshot", required=True)
    parser.add_argument("--observable", default="application.target_pressure")
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        destination = ensure_private_report_path(args.report_dir / "fixture-rehearsal.json")
        report = run_fixture_rehearsal(
            model_path=args.model_path,
            train_db=args.train_db,
            train_snapshot=args.train_snapshot,
            development_db=args.development_db,
            development_snapshot=args.development_snapshot,
            observable=args.observable,
        )
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            prefix="systemsense-no-update-fixture-",
            suffix=".json",
            dir=destination.parent,
            delete=False,
        ) as output:
            json.dump(report, output, sort_keys=True, separators=(",", ":"), allow_nan=False)
            output.flush()
            report_path = Path(output.name)
        print(
            json.dumps(
                {"status": "fixture_only", "trainable": False, "report_path": str(report_path)},
                separators=(",", ":"),
            )
        )
        return 0
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.DatabaseError) as error:
        print(
            json.dumps(
                {"status": "error", "trainable": False, "error_type": type(error).__name__},
                separators=(",", ":"),
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
