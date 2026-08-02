import tomllib
from pathlib import Path

from systemsense import __version__


def test_package_exposes_version() -> None:
    assert __version__ == "0.1.0"


def test_release_wheel_excludes_benchmark_controller_and_repair_scripts() -> None:
    repository = Path(__file__).resolve().parents[1]
    configuration = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))

    assert configuration["tool"]["hatch"]["build"]["targets"]["wheel"]["packages"] == [
        "src/systemsense"
    ]
    assert "systemsense-ab" not in configuration["project"]["scripts"]
