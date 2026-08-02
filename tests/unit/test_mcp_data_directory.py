from pathlib import Path

import pytest

from systemsense.mcp_server import default_database_path


def test_mcp_default_database_honors_documented_data_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEMSENSE_DATA_DIR", str(tmp_path))

    assert default_database_path() == tmp_path / "systemsense.db"
