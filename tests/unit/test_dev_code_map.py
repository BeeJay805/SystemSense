"""Developer navigation must not silently omit a known critical module."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from pytest import CaptureFixture

from scripts.code_map import build, find, internal_imports


def test_relative_imports_resolve_only_known_modules() -> None:
    tree = ast.parse(
        "from ..domain import evidence\nfrom . import policy\n"
        "from .policy import Decision\nimport systemsense.missing\n"
    )
    known = {
        "systemsense.application.worker",
        "systemsense.application.policy",
        "systemsense.domain.evidence",
    }
    assert internal_imports(tree, "systemsense.application.worker", False, known) == [
        "systemsense.application.policy",
        "systemsense.domain.evidence",
    ]


def test_repo_map_covers_frontier_defs_and_reverse_imports(
    tmp_path: Path, capsys: CaptureFixture[str]
) -> None:
    repo = Path(__file__).resolve().parents[2]
    output = tmp_path / "map.json"
    build(repo, output)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["head"]
    assert payload["parse_errors"] == {}
    ranker = payload["modules"]["systemsense.decision.frontier_ranker"]
    assert "systemsense.inference.laya_runtime" in ranker["imports"]
    assert "systemsense.application.frontier_policy" in ranker["imported_by"]
    candidate = next(d for d in ranker["definitions"] if d["name"] == "_candidate_description")
    find(output, "_candidate_description")
    assert (
        f"src/systemsense/decision/frontier_ranker.py:{candidate['line']}"
        in capsys.readouterr().out
    )
