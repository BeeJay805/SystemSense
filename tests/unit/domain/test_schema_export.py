from pathlib import Path

from systemsense.domain.schema_export import rendered_schemas


def test_checked_in_schemas_match_pydantic_models() -> None:
    repository_root = Path(__file__).resolve().parents[3]

    for filename, rendered in rendered_schemas().items():
        checked_in = (repository_root / "schemas" / filename).read_text(encoding="utf-8")
        assert checked_in == rendered
