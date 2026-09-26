"""Offline, frozen-menu synthetic comparison. Never a Windows accuracy score."""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter
from collections.abc import Sequence
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.synthetic_pilot_oracle import (
    PILOT_SCENARIOS,
    SyntheticScenario,
    compare_visible_reference,
)


def score_frozen_case(
    store: SQLiteStore,
    case_id: str,
    scenario: SyntheticScenario,
    *,
    binding_path: Path,
) -> dict[str, object]:
    """Compare observed Laya choices with a visible-input reference on saved menus.

    This is one-step synthetic counterfactual replay, not a rerun of an
    adaptive policy or a Windows diagnosis benchmark. The hidden recipe is
    consumed only by the independent selected-action oracle after selection.
    """

    rows = store.connection.execute(
        "SELECT s.snapshot_id,d.snapshot_id IS NOT NULL "
        "FROM candidate_decision_snapshots AS s "
        "LEFT JOIN frontier_worker_capture_drafts AS d ON d.snapshot_id=s.snapshot_id "
        "WHERE s.case_id=? AND s.schema_version=2 "
        "ORDER BY s.request_frozen_at,s.snapshot_id",
        (case_id,),
    ).fetchall()
    if not rows:
        raise ValueError("case has no frozen mixed-frontier snapshots")
    unscored = [
        {"snapshot_id": str(snapshot_id), "reason": "capture_missing"}
        for snapshot_id, has_capture in rows
        if not has_capture
    ]
    if len(unscored) == len(rows):
        raise ValueError("case has no exact Laya capture to compare")
    comparisons = tuple(
        compare_visible_reference(store, str(snapshot_id), scenario, binding_path=binding_path)
        for snapshot_id, has_capture in rows
        if has_capture
    )
    actual = Counter(item.actual_status for item in comparisons)
    reference = Counter(item.reference_status for item in comparisons)
    known = {"useful", "uninformative"}
    return {
        "scope": "frozen_menu_one_step_only",
        "case_id": case_id,
        "snapshot_count": len(rows),
        "compared_count": len(comparisons),
        "unscored": unscored,
        "actual_outcomes": dict(sorted(actual.items())),
        "reference_outcomes": dict(sorted(reference.items())),
        "known_pair_count": sum(
            item.actual_status in known and item.reference_status in known for item in comparisons
        ),
        "learning_candidate_count": sum(item.learning_candidate for item in comparisons),
        "choices": [
            {
                "snapshot_id": item.snapshot_id,
                "actual_item_id": item.actual_item_id,
                "actual_status": item.actual_status,
                "reference_item_id": item.reference_item_id,
                "reference_status": item.reference_status,
                "reference_evaluation": item.reference_evaluation,
                "learning_candidate": item.learning_candidate,
            }
            for item in comparisons
        ],
        "unavailable_arms": ["deep_only", "scout_off", "scout_on"],
        "training_admissible": False,
        "diagnostic_performance_admissible": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Score one named synthetic case without opening its source DB for writes."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument(
        "--scenario", choices=tuple(item.kind for item in PILOT_SCENARIOS), required=True
    )
    parser.add_argument("--binding", type=Path, required=True)
    args = parser.parse_args(argv)
    database = Path(args.database)
    binding = Path(args.binding)
    if not database.is_file() or not binding.is_file():
        parser.error("database and hidden-recipe binding must be existing files")
    scenario = next(item for item in PILOT_SCENARIOS if item.kind == args.scenario)
    with TemporaryDirectory(prefix="systemsense-frozen-comparison-") as scratch_dir:
        scratch_database = Path(scratch_dir) / "comparison.db"
        with (
            closing(sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)) as source,
            closing(sqlite3.connect(scratch_database)) as copied,
        ):
            source.backup(copied)
        with SQLiteStore(scratch_database) as store:
            report = score_frozen_case(store, str(args.case_id), scenario, binding_path=binding)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
