"""Registered output menus stay bounded without losing the core reasoning request."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import CaseId, JsonValue
from systemsense.domain.probes import (
    ProbeOutputFieldV1,
    ProbePredictionOutputV1,
    ProbeToolMetadataV1,
    SelfWrite,
)
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation
from systemsense.reasoning.contracts import ReasoningRequest
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator, probe_definition


def _registered(category: str, field_count: int, values_per_field: int) -> ProbeDefinition:
    base = probe_definition(category)
    outputs = tuple(
        ProbePredictionOutputV1(name=f"fact_{index}", allowed_values=tuple(range(values_per_field)))
        for index in range(field_count)
    )

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        now = datetime.now(UTC)
        return ProbeObservation(
            summary="Synthetic registered output observation",
            facts={output.name: output.allowed_values[0] for output in outputs},
            observed_at=now,
            captured_at=now,
        )

    return replace(
        base,
        handler=collect,
        discovery=ProbeToolMetadataV1(
            probe_id=base.manifest.probe_id,
            probe_version=base.manifest.version,
            observable_ids=(base.manifest.probe_id,),
            parameter_fields=(),
            supports_window=False,
            outputs=tuple(ProbeOutputFieldV1(name=item.name) for item in outputs),
            estimated_cost_ms=25,
            resource_class="cpu",
            sensitivity=Sensitivity.SYSTEM_METADATA,
            network_effect="none",
            io_intensity="light",
            target_state_effect="none",
            self_writes=(SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
            purpose="Observe bounded synthetic categorical outputs",
        ),
        prediction_outputs=outputs,
    )


@pytest.mark.parametrize(
    ("contracts", "retained"),
    [
        (
            (("core", 8, 2), ("network", 8, 2), ("devices", 1, 2)),
            (8, 8, 0),
        ),
        ((("core", 4, 16), ("network", 1, 2)), (4, 0)),
    ],
)
def test_registered_prediction_menu_omits_excess_whole_contracts(
    tmp_path: Path,
    contracts: tuple[tuple[str, int, int], ...],
    retained: tuple[int, ...],
) -> None:
    definitions = tuple(_registered(*item) for item in contracts)
    with SQLiteStore(tmp_path / "bounded-menu.db") as store:
        app = investigator(store, definitions=definitions)
        projected = app._prediction_capabilities(app.capabilities)  # pyright: ignore[reportPrivateUsage]

    assert tuple(len(item.prediction_outputs) for item in projected) == retained
    assert tuple(item.probe_version for item in projected) == tuple(
        1 if count else None for count in retained
    )
    assert sum(len(item.prediction_outputs) for item in projected) <= 16
    assert (
        sum(len(output.allowed_values) for item in projected for output in item.prediction_outputs)
        <= 64
    )
    request = ReasoningRequest(
        schema_version=6,
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="bounded_output_menu",
        deadline_at=datetime.now(UTC) + timedelta(minutes=1),
        objective="Check a synthetic symptom",
        available_probes=projected,
        budget_ms=1000,
        max_probes=1,
    )
    assert len(request.available_probes) == len(contracts)
