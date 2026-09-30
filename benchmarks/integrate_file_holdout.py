"""Score the explicitly selected completed file-holdout artifact set offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, cast

from benchmarks.private_alpha_scorecard import score


def combine_reviews(evidence: Path, output: Path) -> Path:
    if output.exists():
        raise FileExistsError(output)
    names = (
        "file-semantic-review-basic-01.json",
        "file-semantic-review-basic-02.json",
        "file-semantic-review-first-pass.json",
        "file-semantic-review-second-pass.json",
    )
    documents: list[dict[str, Any]] = []
    for name in names:
        value = json.loads((evidence / name).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise TypeError(f"review export must be an object: {name}")
        documents.append(cast(dict[str, Any], value))
    protocol_hashes = {document.get("protocol_sha256") for document in documents}
    if len(protocol_hashes) != 1:
        raise ValueError("selected review exports do not share one frozen protocol hash")
    reviews: list[dict[str, Any]] = []
    for document in documents:
        value = document.get("reviews")
        if not isinstance(value, list):
            raise TypeError("each selected review export must contain reviews")
        for row in cast(list[object], value):
            if not isinstance(row, dict):
                raise TypeError("every selected review must be an object")
            reviews.append(cast(dict[str, Any], row))
    output.write_text(
        json.dumps(
            {"protocol_sha256": next(iter(protocol_hashes)), "reviews": reviews},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    manifest_value = json.loads(args.manifest.read_text(encoding="utf-8"))
    if not isinstance(manifest_value, dict):
        raise TypeError("manifest must be a JSON object")
    manifest = cast(dict[str, Any], manifest_value)
    reviews_path = combine_reviews(args.evidence, args.output.with_suffix(".reviews.json"))
    report = score(manifest, [reviews_path])
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
