import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from benchmarks.ab.contracts import (
    FINGERPRINT_STATE_KEYS,
    ExperimentArm,
    MachineFingerprint,
)
from benchmarks.ab.fingerprint import capture_fingerprint, fingerprint_detail_differences
from benchmarks.ab.scenario import REQUIRED_SCRIPTS, load_scenario

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CANARY = _REPO_ROOT / "benchmarks" / "ab" / "scenarios" / "port_conflict"


def test_port_conflict_scenario_has_human_prompt_and_complete_script_contract() -> None:
    loaded = load_scenario(_CANARY)

    assert loaded.manifest.scenario_id == "application.port_conflict"
    assert "port 8000" not in loaded.manifest.human_prompt.lower()
    assert set(loaded.script_paths) == set(REQUIRED_SCRIPTS)
    assert all(path.is_file() for path in loaded.script_paths.values())
    assert loaded.content_hash == load_scenario(_CANARY / "manifest.json").content_hash


def test_port_conflict_injector_does_not_inherit_controller_process_handles() -> None:
    script = (_CANARY / "inject.ps1").read_text(encoding="utf-8")

    assert "Invoke-CimMethod" in script
    assert "Win32_Process" in script
    assert "Start-Process" not in script


def test_scenario_loader_rejects_script_escape(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        """
        {
          "schema_version": 1,
          "scenario_id": "application.escape",
          "family": "application",
          "human_prompt": "The application will not start.",
          "expected_signals": ["port owner"],
          "expected_evidence_terms": ["8000"],
          "expected_coverage_categories": ["application"],
          "scripts": {
            "inject": "../inject.ps1",
            "verify_broken": "verify-broken.ps1",
            "verify_fixed": "verify-fixed.ps1",
            "repair_reference": "repair-reference.ps1"
          }
        }
        """,
        encoding="utf-8",
    )
    for filename in ("verify-broken.ps1", "verify-fixed.ps1", "repair-reference.ps1"):
        (tmp_path / filename).write_text("exit 0\n", encoding="utf-8")

    with pytest.raises(ValueError, match="inside the scenario directory"):
        load_scenario(tmp_path)


def test_clone_fingerprint_hash_excludes_arm_identity_but_includes_fault_state() -> None:
    state = {key: f"sha256:{key}" for key in FINGERPRINT_STATE_KEYS}
    baseline = MachineFingerprint(
        arm=ExperimentArm.BASELINE,
        clone_id="clone-a",
        parent_snapshot_id="checkpoint-42",
        state=state,
    )
    treatment = MachineFingerprint(
        arm=ExperimentArm.SYSTEMSENSE,
        clone_id="clone-b",
        parent_snapshot_id="checkpoint-42",
        state=state,
    )

    assert baseline.comparison_hash() == treatment.comparison_hash()
    changed = treatment.model_copy(
        update={"state": {**treatment.state, "fault_state": "sha256:different"}}
    )
    assert baseline.comparison_hash() != changed.comparison_hash()


def test_fingerprint_difference_explains_changed_inventory_rows() -> None:
    state = {key: f"sha256:{key}" for key in FINGERPRINT_STATE_KEYS}
    inventory = {key: () for key in FINGERPRINT_STATE_KEYS}
    baseline = MachineFingerprint(
        arm=ExperimentArm.BASELINE,
        clone_id="clone-a",
        parent_snapshot_id="checkpoint-42",
        state=state,
        inventory={**inventory, "services": ("Example|Auto|example.exe",)},
    )
    treatment = MachineFingerprint(
        arm=ExperimentArm.SYSTEMSENSE,
        clone_id="clone-b",
        parent_snapshot_id="checkpoint-42",
        state={**state, "services": "sha256:changed"},
        inventory={**inventory, "services": ("Example|Manual|example.exe",)},
    )

    differences = fingerprint_detail_differences(baseline, treatment)

    assert differences[0].category == "services"
    assert differences[0].left_only == ("Example|Auto|example.exe",)
    assert differences[0].right_only == ("Example|Manual|example.exe",)


def test_clone_fingerprint_requires_every_parity_category() -> None:
    with pytest.raises(ValidationError, match="drivers"):
        MachineFingerprint(
            arm=ExperimentArm.BASELINE,
            clone_id="clone-a",
            parent_snapshot_id="snapshot-1",
            state={"os": "abc"},
        )


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell fingerprint is Windows-only")
def test_fingerprint_capture_does_not_require_pip(tmp_path: Path) -> None:
    python_without_pip = tmp_path / "python-without-pip.cmd"
    python_without_pip.write_text(
        "@echo off\r\n"
        'if "%~1"=="-m" if "%~2"=="pip" (\r\n'
        "  >&2 echo No module named pip\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        f'"{sys.executable}" %*\r\n',
        encoding="utf-8",
    )

    fingerprint = capture_fingerprint(
        script_path=_REPO_ROOT / "benchmarks" / "ab" / "capture-fingerprint.ps1",
        arm=ExperimentArm.BASELINE,
        clone_id="pipless-python",
        parent_snapshot_id="test-parent",
        scenario_root=_CANARY,
        python_executable=python_without_pip,
    )

    assert set(fingerprint.state) == FINGERPRINT_STATE_KEYS
    assert set(fingerprint.inventory) == FINGERPRINT_STATE_KEYS


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell fingerprint is Windows-only")
def test_fingerprint_capture_supports_native_python_executable() -> None:
    fingerprint = capture_fingerprint(
        script_path=_REPO_ROOT / "benchmarks" / "ab" / "capture-fingerprint.ps1",
        arm=ExperimentArm.BASELINE,
        clone_id="native-python",
        parent_snapshot_id="test-parent",
        scenario_root=_CANARY,
        python_executable=Path(sys.executable),
    )

    assert set(fingerprint.state) == FINGERPRINT_STATE_KEYS
    assert set(fingerprint.inventory) == FINGERPRINT_STATE_KEYS


def test_service_fingerprint_excludes_volatile_runtime_state() -> None:
    script = (_REPO_ROOT / "benchmarks" / "ab" / "capture-fingerprint.ps1").read_text(
        encoding="utf-8"
    )
    service_inventory = script.split("$serviceLines =", 1)[1].split("$scenarioLines =", 1)[0]

    assert "Get-CimInstance Win32_Service" in service_inventory
    assert '"$serviceName|$($_.StartMode)|$($_.PathName)"' in service_inventory
    assert "$($_.State)" not in service_inventory


def test_service_fingerprint_normalizes_only_per_user_instance_suffixes() -> None:
    script = (_REPO_ROOT / "benchmarks" / "ab" / "capture-fingerprint.ps1").read_text(
        encoding="utf-8"
    )
    service_inventory = script.split("$serviceLines =", 1)[1].split("$scenarioLines =", 1)[0]

    assert "$template.Type -band 0x40" in script
    assert '"^(?<base>.+)_[0-9a-fA-F]{5}$"' in script
    assert "Get-CanonicalServiceName $_.Name" in service_inventory
    assert '"$serviceName|$($_.StartMode)|$($_.PathName)"' in service_inventory
