"""Keep Windows default runtime ledgers out of the real user profile."""

import sys
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_local_app_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData"))
