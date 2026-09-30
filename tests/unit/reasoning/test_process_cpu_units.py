"""Synthetic evidence projection; not Windows or model qualification."""

from datetime import UTC, datetime, timedelta

import pytest

from systemsense.application.bootstrap import default_capabilities
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import ReasoningRequest
from systemsense.reasoning.process import assess_named_process

NOW = datetime(2026, 9, 30, tzinfo=UTC)


@pytest.mark.parametrize("cores", [1.0, None, 10.0])
def test_basic_labels_cpu_denominator_and_only_uses_consistent_core_measurement(
    cores: float | None,
) -> None:
    inventory = EvidenceContext(
        evidence_id=EvidenceId(root="ev_" + "1" * 32),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="application.snapshot",
        summary="Exact saved process",
        case_scope="current_case",
        status=EvidenceContextStatus.OBSERVED,
        facts={
            "target_process_search": [
                {
                    "name": "sample.exe",
                    "status": "matching_process_observed",
                    "matched_row_count": 1,
                }
            ],
            "processes.0": {"name": "sample.exe", "pid": 42, "creation_time": NOW.isoformat()},
        },
    )
    sample: dict[str, JsonValue] = {
        "name": "sample.exe",
        "delta_status": "measured",
        "status": "available",
        "cpu_percent": 4.167,
        "cpu_logical_cores": cores,
    }
    pressure = EvidenceContext(
        evidence_id=EvidenceId(root="ev_" + "2" * 32),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="application.target_pressure",
        summary="Exact saved CPU sample",
        case_scope="current_case",
        status=EvidenceContextStatus.OBSERVED,
        facts={
            "target_pressure": {
                "target_pid": 42,
                "target_creation_time": NOW.isoformat(),
                "status": "available",
                "logical_cpu_count": 24,
                "samples": [sample],
                "window_ended_at": NOW.isoformat(),
            }
        },
    )
    request = ReasoningRequest(
        case_id=CaseId(root="case_" + "a" * 32),
        state_version=0,
        correlation_id="cpu-units",
        deadline_at=NOW + timedelta(seconds=30),
        objective="Is sample.exe using a core?",
        evidence_ids=(inventory.evidence_id, pressure.evidence_id),
        evidence_context=(inventory, pressure),
        available_probes=default_capabilities(),
        budget_ms=30000,
        max_probes=2,
    )
    result = assess_named_process(request)
    assert result is not None
    assert "4.2% of total logical-processor CPU capacity" in result[0]
    if cores == 1.0:
        assert "1.00 logical cores" in result[0]
    else:
        assert "logical-core usage was not recorded" in result[0]
        assert "equivalent to" not in result[0]
    assert "cause of the reported slowness remain unknown" in result[0]
