"""Deterministic JSON Schema export for public domain contracts."""

import json
from pathlib import Path

from pydantic import BaseModel

from systemsense.domain.cases import DiagnosticCase
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.inventory import InventoryFact

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "case.v1.schema.json": DiagnosticCase,
    "evidence.v1.schema.json": EvidenceRecord,
    "inventory.v1.schema.json": InventoryFact,
}


def rendered_schemas() -> dict[str, str]:
    return {
        filename: json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"
        for filename, model in SCHEMA_MODELS.items()
    }


def main() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    schema_directory = repository_root / "schemas"
    schema_directory.mkdir(exist_ok=True)
    for filename, rendered in rendered_schemas().items():
        (schema_directory / filename).write_text(rendered, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
