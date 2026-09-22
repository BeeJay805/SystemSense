import os
import subprocess
import sys
from textwrap import dedent


def test_cli_imports_without_optional_mcp_dependency() -> None:
    source = "import systemsense.cli; print('mcp' in sys.modules)"
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(sys.path[0]), os.path.abspath("src")])
    result = subprocess.run(
        [sys.executable, "-c", "import sys; " + source],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_cli_imports_when_optional_mcp_runtime_is_absent() -> None:
    source = dedent(
        """
        import builtins
        original = builtins.__import__
        def blocked(name, *args, **kwargs):
            if (
                name == "anyio"
                or name.startswith("anyio.")
                or name == "mcp"
                or name.startswith("mcp.")
            ):
                raise ModuleNotFoundError(f"blocked optional dependency: {name}")
            return original(name, *args, **kwargs)
        builtins.__import__ = blocked
        import systemsense.cli
        print("core-cli-imported")
        """
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(sys.path[0]), os.path.abspath("src")])
    result = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "core-cli-imported"


def test_core_bootstrap_and_workspace_do_not_import_mcp() -> None:
    source = (
        "import sys; from systemsense.application.bootstrap import default_planner; "
        "from systemsense.application.workspace import EvidenceWorkspace; "
        "default_planner(); print('mcp' in sys.modules)"
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(sys.path[0]), os.path.abspath("src")])
    result = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_mcp_check_reports_optional_extra_when_mcp_is_unavailable() -> None:
    source = dedent(
        """
        import builtins
        original = builtins.__import__
        def blocked(name, *args, **kwargs):
            if name == "mcp" or name.startswith("mcp."):
                raise ModuleNotFoundError("blocked mcp")
            return original(name, *args, **kwargs)
        builtins.__import__ = blocked
        from typer.testing import CliRunner
        from systemsense.cli import app
        result = CliRunner().invoke(app, ["mcp-check"])
        print(result.exit_code)
        print(result.output)
        """
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(sys.path[0]), os.path.abspath("src")])
    result = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "MCP support is unavailable" in result.stdout
    assert "optional 'mcp' extra" in result.stdout


def test_mcp_entrypoint_exits_cleanly_when_optional_extra_is_unavailable() -> None:
    source = dedent(
        """
        import builtins
        original = builtins.__import__
        def blocked(name, *args, **kwargs):
            if name == "mcp" or name.startswith("mcp."):
                raise ModuleNotFoundError("blocked mcp", name="mcp")
            return original(name, *args, **kwargs)
        builtins.__import__ = blocked
        from systemsense.cli import mcp_main
        mcp_main()
        """
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(sys.path[0]), os.path.abspath("src")])
    result = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 2
    assert "MCP support is unavailable" in result.stderr
    assert "optional 'mcp' extra" in result.stderr
    assert "Traceback" not in result.stderr
