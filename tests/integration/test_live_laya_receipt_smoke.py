"""Opt-in pinned-Laya smoke for source-bound PDF process measurement routing."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from systemsense.cli import _managed_laya_admission  # pyright: ignore[reportPrivateUsage]
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import utc_now
from systemsense.inference.factory import AdvisoryProviders, load_advisory_providers
from systemsense.inference.host_telemetry import read_host_telemetry
from systemsense.inference.profile import (
    LocalInferenceProfile,
    ManagedGpuResources,
    load_inference_profile,
    propose_managed_v3_payload,
)
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.packs.runtime import TargetPressureParametersV1, default_probe_runner
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_investigator_pdf_target import (
    _precollected_pdf_investigator,  # pyright: ignore[reportPrivateUsage]
)


def _managed_pinned_laya_providers() -> AdvisoryProviders:
    """Admit the pinned GPU worker through the CLI's same-user ledger."""

    installed = load_inference_profile()
    assert installed.laya.enabled and installed.laya.device == "cuda"
    if installed.schema_version == 3:
        assert installed.decision_provider == "laya"
        profile = installed
    else:
        assert installed.inference.enabled
        observed = read_host_telemetry(gpu_device_index=installed.laya.cuda_device_index)
        resources = ManagedGpuResources(
            gpu_device_index=observed.gpu_device_index,
            gpu_uuid=observed.gpu_uuid,
        )
        profile = LocalInferenceProfile.model_validate(
            propose_managed_v3_payload(
                installed,
                decision_provider="laya",
                managed_resources=resources,
            )
        )
    policy = profile.resolved_execution_policy()
    admission = _managed_laya_admission(policy)
    assert admission is not None
    return load_advisory_providers(
        profile.inference,
        laya_config=profile.laya.runtime_config(),
        laya_timeout_seconds=profile.laya.timeout_seconds,
        execution_policy=policy,
        managed_admission=admission,
    )


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_LAYA_RECEIPT") != "1",
    reason="explicit opt-in managed CUDA Laya receipt/measurement smoke",
)
def test_real_laya_routes_source_bound_pdf_measurement(tmp_path: Path) -> None:
    providers = _managed_pinned_laya_providers()
    try:
        providers.prewarm_laya(timeout_seconds=90)
        assert providers.frontier_ranker is not None
        with SQLiteStore(tmp_path / "live-laya-receipt.db") as store:
            store.initialize()
            app, case_id = _precollected_pdf_investigator(store)
            state = app.repository.load(str(case_id))
            app.repository.save(
                state.model_copy(update={"max_probes": 2}),
                expected_version=state.state_version,
                event="test_budget",
                detail="one live frontier candidate run",
            )
            app.frontier_ranker = providers.frontier_ranker
            app.knowledge = ReferenceKnowledgeGraph.load_default()
            manifest = default_probe_runner().manifest("application.target_pressure")
            assert manifest is not None
            observed: list[dict[str, JsonValue]] = []

            def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
                observed.append(parameters)
                stamp = utc_now()
                return ProbeObservation(
                    summary="Synthetic selected process pressure",
                    facts={"pid": parameters["pid"]},
                    observed_at=stamp,
                    captured_at=stamp,
                )

            app.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
                definitions=(
                    ProbeDefinition(
                        manifest=manifest,
                        parameter_model=TargetPressureParametersV1,
                        handler=observe,
                        isolated=False,
                    ),
                )
            )
            finished = app.run(str(case_id))
            assert observed and observed[0]["pid"] == 4242
            assert finished.completed_probe_ids.count("application.target_pressure") == 1
            assert any(
                call.role == "fast_decision"
                and call.detail == "frontier_laya"
                and not call.degraded
                for call in finished.provider_calls
            )
            row = store.connection.execute(
                "SELECT b.receipt_id,s.request_json "
                "FROM frontier_packet_snapshot_bindings AS b "
                "JOIN candidate_decision_snapshots AS s ON s.snapshot_id=b.snapshot_id "
                "WHERE s.case_id=?",
                (str(case_id),),
            ).fetchone()
            assert row is not None
            assert FrontierPacketReceiptRepository(store).readback(str(row[0])).packets
            assert '"evidence_packets":[]' not in str(row[1])
    finally:
        providers.close()
