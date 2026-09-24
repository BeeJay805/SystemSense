"""Bounded offline admission of candidate-ID pilot shards to split custody.

The output is a metadata-only receipt, not authenticated origin, useful-test
supervision, diagnostic performance, or permission to train a model.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from pydantic import ValidationError

from systemsense.evaluation.pilot_corpus import PilotCorpus, verify_pilot_corpus
from systemsense.evaluation.pilot_split_ledger import PilotSplitLedger, PilotSplitLedgerManifest

_MAX_CORPUS_BYTES = 32 * 1024 * 1024
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _external_target(path: Path, *, label: str) -> Path:
    target = path.resolve(strict=False)
    if target.is_relative_to(_REPOSITORY_ROOT):
        raise ValueError(f"{label} must be outside repository")
    if not target.parent.is_dir():
        raise ValueError(f"{label} parent directory does not exist")
    return target


def _read_corpus(path: Path) -> PilotCorpus:
    with path.open("rb") as stream:
        payload = stream.read(_MAX_CORPUS_BYTES + 1)
    if not payload or len(payload) > _MAX_CORPUS_BYTES:
        raise ValueError("pilot corpus is empty or exceeds the local size bound")
    try:
        corpus = PilotCorpus.model_validate_json(payload)
        verify_pilot_corpus(corpus)
    except (ValidationError, ValueError) as error:
        raise ValueError("pilot corpus is invalid") from error
    return corpus


def admit_pilot_corpus_file(
    *,
    corpus_path: Path,
    ledger_path: Path,
    corpus_id: str,
    output_path: Path,
) -> PilotSplitLedgerManifest:
    """Admit one existing bounded corpus and exclusively write its safe receipt.

    If the receipt write fails after admission, replay the same corpus at a new
    output path. Ledger admission is idempotent; an uncertain write never
    authorizes training or replaces an existing output.
    """

    target = _external_target(output_path, label="manifest")
    database = _external_target(ledger_path, label="ledger database")
    source = corpus_path.resolve(strict=False)
    if len({target, database, source}) != 3:
        raise ValueError("pilot paths must be distinct")
    if target.exists() or target.is_symlink():
        raise FileExistsError("pilot manifest already exists")
    if database.is_dir():
        raise ValueError("ledger database path is a directory")
    corpus = _read_corpus(corpus_path)
    with PilotSplitLedger(database, corpus_id=corpus_id) as ledger:
        admitted = ledger.admit(corpus)
        readback = ledger.manifest()
        if readback != admitted:
            raise ValueError("pilot split manifest changed after admission")
        ledger.verify_manifest(expected_sha256=admitted.manifest_sha256)
    payload = (
        json.dumps(
            admitted.model_dump(mode="json"),
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    with target.open("xb") as stream:
        stream.write(payload)
        stream.flush()
    with target.open("rb") as stream:
        readback_payload = stream.read(len(payload) + 1)
    if (
        readback_payload != payload
        or PilotSplitLedgerManifest.model_validate_json(readback_payload) != admitted
    ):
        raise ValueError("pilot split manifest output readback failed")
    return admitted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Admit a non-trainable candidate-ID pilot corpus to global split custody"
    )
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--ledger-db", required=True, type=Path)
    parser.add_argument("--corpus-id", required=True)
    parser.add_argument("--output-manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = admit_pilot_corpus_file(
            corpus_path=args.corpus,
            ledger_path=args.ledger_db,
            corpus_id=args.corpus_id,
            output_path=args.output_manifest,
        )
    except (OSError, sqlite3.Error, ValidationError, ValueError):
        # No exception text: malformed source JSON can contain private strings.
        print('{"status":"error","reason":"pilot_split_rejected"}', file=sys.stderr)
        return 2
    print(json.dumps({"status": "ok", "manifest_sha256": manifest.manifest_sha256}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
