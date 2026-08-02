from pathlib import Path

import pytest

from systemsense.mcp_server import default_database_path


def test_mcp_default_database_honors_documented_data_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SYSTEMSENSE_DATA_DIR", str(tmp_path))

    assert default_database_path() == tmp_path / "systemsense.db"


def test_mcp_exact_database_path_takes_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact = tmp_path / "isolated-arm.db"
    monkeypatch.setenv("SYSTEMSENSE_DATA_DIR", str(tmp_path / "ignored"))
    monkeypatch.setenv("SYSTEMSENSE_DATABASE_PATH", str(exact))

    assert default_database_path() == exact
