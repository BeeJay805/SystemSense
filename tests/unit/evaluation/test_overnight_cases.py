"""Regression checks for synthetic registered-probe custody and blind cases."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from benchmarks import overnight_cases
from benchmarks.overnight_cases import case_contract, load_cases, synthetic_probe_runner
from systemsense.application.candidate_catalog import general_pressure_candidate_catalog
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import PersistedProbeResult
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue, stable_source_id
from systemsense.orchestration.probes import ProbeRunStatus
from systemsense.packs.runtime import default_probe_definitions
from systemsense.storage.case_candidates import CandidateRecord, CandidateResolution
from systemsense.storage.sqlite_store import SQLiteStore

_FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "fixtures"


def test_current_catalog_drift_cannot_run_as_frozen_overnight_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drift = overnight_cases.current_catalog_drift()
    assert any("application.target_pressure: frozen=(1," in item for item in drift)
    assert "unexpected current probe: network.loopback_replay" in drift
    assert "unexpected current probe: network.listener_owner_pressure" in drift

    def unexpected_episode(*_args: object, **_kwargs: object) -> None:
        pytest.fail("incompatible historical suite must stop before constructing an episode")

    monkeypatch.setattr(overnight_cases, "build_investigator", unexpected_episode)
    case_id = next(iter(load_cases()))
    visible = SimpleNamespace(case_id=case_id, **case_contract(case_id), budget_ms=90_000)
    with pytest.raises(ValueError, match="current probe catalog is incompatible"):
        overnight_cases.run_case(visible, "deterministic", tmp_path)
    assert not tuple(tmp_path.iterdir())


def test_historical_contract_does_not_read_mutable_live_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case_id = next(iter(load_cases()))
    before = case_contract(case_id)

    def unavailable_live_catalog() -> None:
        pytest.fail("historical fingerprints must not depend on the live registry")

    monkeypatch.setattr(overnight_cases, "default_probe_definitions", unavailable_live_catalog)
    assert case_contract(case_id) == before


def test_twelve_blind_cases_have_balanced_within_family_splits_and_frozen_contracts() -> None:
    recipes = load_cases()
    suite = json.loads((_FIXTURES / "overnight_suite.json").read_text(encoding="utf-8"))
    oracle = json.loads((_FIXTURES / "overnight_oracle.json").read_text(encoding="utf-8"))
    assert (
        oracle["suite_sha256"]
        == hashlib.sha256((_FIXTURES / "overnight_suite.json").read_bytes()).hexdigest()
    )

    assert len(recipes) == len(suite["cases"]) == len(oracle["cases"]) == 12
    assert set(recipes) == set(oracle["cases"]) == {row["case_id"] for row in suite["cases"]}
    assert Counter((row["family_group"], row["split"]) for row in suite["cases"]) == {
        (family, split): 2
        for family in ("network", "application", "performance")
        for split in ("development", "holdout")
    }
    for row in suite["cases"]:
        assert row["source"] == "synthetic"
        assert row["budget_ms"] == recipes[row["case_id"]]["budget_ms"]
        assert all(row[key] == value for key, value in case_contract(row["case_id"]).items())
        assert "split" not in recipes[row["case_id"]]
        assert "family" not in recipes[row["case_id"]]
        assert "hidden_simulated_cause" not in recipes[row["case_id"]]
        assert "verification" not in recipes[row["case_id"]].get("reported_task", {})
        assert oracle["cases"][row["case_id"]]["leak_markers"]


@pytest.mark.parametrize("case_id", tuple(load_cases()))
def test_all_registered_probes_are_replaced_without_changing_manifests(case_id: str) -> None:
    recipe = load_cases()[case_id]
    runner = synthetic_probe_runner(recipe)
    defaults = {item.manifest.probe_id: item for item in default_probe_definitions()}

    assert runner.probe_ids == frozenset(defaults)
    assert not runner.isolated_probe_ids
    for probe_id, definition in defaults.items():
        assert runner.manifest(probe_id) == definition.manifest
    for probe_id in ("core.system", "network.snapshot", "incident.events", "power.snapshot"):
        result = runner.run(probe_id, {})
        assert result.status is ProbeRunStatus.OK
        assert result.observation is not None
        assert "Synthetic fixture" in result.observation.limitations[0]


def test_network_proxy_state_is_local_configuration_not_reachability() -> None:
    runner = synthetic_probe_runner(load_cases()["case-7c2b80de4573"])
    connectivity = runner.run("network.connectivity", {}).observation
    configuration = runner.run("network.configuration", {}).observation
    assert connectivity is not None and configuration is not None
    connectivity_facts = cast(dict[str, Any], connectivity.facts)
    configuration_facts = cast(dict[str, Any], configuration.facts)
    assert connectivity_facts["connectivity"]["proxy"]["manual_enabled"] is True
    assert configuration_facts["proxy"]["enabled"] is True
    assert "reachability" in " ".join(connectivity.limitations)
    assert "reachability" not in connectivity.facts


def test_application_event_retains_other_target_and_source_time() -> None:
    runner = synthetic_probe_runner(load_cases()["case-a934ed27f3c1"])
    observation = runner.run("incident.events", {}).observation
    assert observation is not None
    event = cast(dict[str, Any], observation.facts)["events"][0]
    assert event["event_data"]["AppName"] == "OtherTool.exe"
    assert (
        datetime.fromisoformat(observation.captured_at.isoformat())
        - datetime.fromisoformat(event["observed_at"])
    ).total_seconds() >= 52 * 60


def test_initial_cpu_spike_and_later_sample_disagree_without_erasing_either() -> None:
    runner = synthetic_probe_runner(load_cases()["case-6db492a1c735"])
    first = runner.run("core.resources", {}).observation
    later = runner.run("pressure.sample", {}).observation
    assert first is not None and later is not None
    assert cast(dict[str, Any], first.facts)["resources"]["cpu_percent"] == 97
    assert [
        item["system_cpu_percent"]
        for item in cast(dict[str, Any], later.facts)["pressure"]["samples"]
    ] == [3] * 3


def test_denied_and_unsupported_stay_explicit_unknowns() -> None:
    network = synthetic_probe_runner(load_cases()["case-509ed3c4b780"])
    connectivity = network.run("network.connectivity", {}).observation
    assert connectivity is not None
    assert connectivity.facts["collection_status"] == "permission_denied"
    assert cast(dict[str, Any], connectivity.facts)["connectivity"]["proxy"] is None

    performance = synthetic_probe_runner(load_cases()["case-b3e7814a209c"])
    sample = performance.run("gpu.telemetry.sample", {}).observation
    assert sample is not None
    series = cast(dict[str, Any], sample.facts)["gpu_telemetry_sample"]
    assert series["status"] == "unsupported"
    assert all(not frame["gpus"] for frame in series["samples"])


def test_explicit_live_window_contains_all_synthetic_sample_times() -> None:
    runner = synthetic_probe_runner(load_cases()["case-6db492a1c735"])
    start = datetime.now(UTC)
    parameters: dict[str, JsonValue] = {
        "window_start": start.isoformat(),
        "window_end": (start + timedelta(seconds=10)).isoformat(),
    }
    for probe_id in ("pressure.sample", "gpu.telemetry.sample"):
        result = runner.run(probe_id, parameters)
        assert result.status is ProbeRunStatus.OK
        assert result.observation is not None
        facts = cast(dict[str, Any], result.observation.facts)
        series = (
            facts["pressure"] if probe_id == "pressure.sample" else facts["gpu_telemetry_sample"]
        )
        assert result.started_at <= datetime.fromisoformat(series["window_started_at"])
        assert start <= datetime.fromisoformat(series["window_started_at"])
        assert datetime.fromisoformat(series["window_ended_at"]) <= start + timedelta(seconds=10)
        assert datetime.fromisoformat(series["window_ended_at"]) <= result.observation.captured_at
        assert (
            datetime.fromisoformat(series["window_ended_at"])
            - datetime.fromisoformat(series["window_started_at"])
        ).total_seconds() < 10


def test_registered_live_candidate_uses_actual_synthetic_sample_interval(tmp_path: Path) -> None:
    """A catalog-issued window's exact parameters fit the substituted collector."""

    runner = synthetic_probe_runner(load_cases()["case-6db492a1c735"])
    baseline = runner.run("core.resources", {})
    assert baseline.status is ProbeRunStatus.OK and baseline.observation is not None
    manifest = runner.manifest("core.resources")
    assert manifest is not None
    observed_at = baseline.observation.observed_at
    captured_at = max(baseline.finished_at, baseline.observation.captured_at)
    case_id, evidence_id = CaseId.new(), EvidenceId.new()
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "core.resources", "probe_version": manifest.version}
    )
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=observed_at,
        captured_at=captured_at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "core.resources"},
        ),
        collector=CollectorReference(
            id="core.resources", version=manifest.version, execution_id=baseline.execution_id
        ),
        summary=baseline.observation.summary,
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    epoch = 2
    with SQLiteStore(tmp_path / "candidate.db") as store:
        store.create_case(
            case_id=str(case_id),
            kind="general",
            symptom="Synthetic renderer slowdown",
            created_at=observed_at.isoformat(),
            status="collecting",
            state_version=epoch,
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
            (
                str(case_id),
                json.dumps(
                    {
                        "case_id": str(case_id),
                        "state_version": epoch,
                        "status": "running",
                        "deadline_at": (observed_at + timedelta(seconds=60)).isoformat(),
                        "budget_ms": 60_000,
                        "spent_cost_ms": 0,
                        "max_probes": 3,
                        "completed_probe_ids": [],
                        "pending_probe_ids": [],
                        "interrupted_probe_ids": [],
                        "unrecorded_attempt_count": 0,
                    }
                ),
            ),
        )
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(baseline.execution_id),
                case_id=str(case_id),
                probe_id="core.resources",
                probe_version=manifest.version,
                status="ok",
                parameters_json="{}",
                started_at=baseline.started_at.isoformat(),
                finished_at=baseline.finished_at.isoformat(),
                state_version=epoch,
            )
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=source_id,
                record_json=record.model_dump_json(),
                observed_at=observed_at.isoformat(),
                captured_at=captured_at.isoformat(),
                execution_id=str(baseline.execution_id),
                dedupe_key=f"execution:{baseline.execution_id}",
                time_basis="collector_observed",
                time_quality="exact",
            )
        parent = PersistedProbeResult(
            task_id="baseline-core-resources",
            case_id=str(case_id),
            epoch_state_version=epoch,
            probe_id="core.resources",
            execution_id=baseline.execution_id,
            evidence_generation=0,
            trigger_evidence_sha256="a" * 64,
        )
        window = Investigator._streaming_parent_window(  # pyright: ignore[reportPrivateUsage]
            case_id, observed_at + timedelta(seconds=60), parent, store
        )
        assert window is not None
        assert (window.end - window.start).total_seconds() == 12
        registry, needs = general_pressure_candidate_catalog(
            store, runner, case_id, observation_window=window
        )
        assert len(needs) == 1
        candidate = registry.issue(case_id, epoch, needs[0])
        assert isinstance(candidate, CandidateRecord)
        resolved = registry.resolve(case_id, epoch, candidate.candidate_id)
        assert isinstance(resolved, CandidateResolution)
        # This isolates fixture behavior. The product dispatch path has a
        # separate typed-window validation issue tracked by the integration owner.
        result = runner.run(resolved.invocation.probe_id, resolved.invocation.parameters)
        assert result.status is ProbeRunStatus.OK and result.observation is not None
        pressure = cast(dict[str, Any], result.observation.facts)["pressure"]
        assert result.started_at <= datetime.fromisoformat(pressure["window_started_at"])
        assert window.start <= datetime.fromisoformat(pressure["window_started_at"])
        assert datetime.fromisoformat(pressure["window_ended_at"]) <= window.end
        assert datetime.fromisoformat(pressure["window_ended_at"]) <= result.observation.captured_at


def test_none_window_defaults_are_equivalent_to_no_window() -> None:
    runner = synthetic_probe_runner(load_cases()["case-6db492a1c735"])
    for probe_id in ("pressure.sample", "gpu.telemetry.sample"):
        result = runner.run(probe_id, {"window_start": None, "window_end": None})
        assert result.status is ProbeRunStatus.OK


def test_expired_live_window_fails_closed() -> None:
    runner = synthetic_probe_runner(load_cases()["case-6db492a1c735"])
    now = datetime.now(UTC)
    result = runner.run(
        "pressure.sample",
        {
            "window_start": (now - timedelta(seconds=10)).isoformat(),
            "window_end": (now - timedelta(seconds=5)).isoformat(),
        },
    )
    assert result.status is ProbeRunStatus.FAILED
    assert result.observation is None
    assert result.error is not None and "window is unavailable" in result.error
