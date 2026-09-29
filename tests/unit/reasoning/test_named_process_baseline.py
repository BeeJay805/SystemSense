"""Basic route reports exact process observations without inventing a cause."""

from datetime import UTC, datetime, timedelta

from systemsense.decision.contracts import ProbeCapability, ResourceClass
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import ReasoningRequest
from systemsense.reasoning.deterministic import DeterministicReasoningProvider

NOW = datetime.now(UTC)
NAME = "example-target.exe"
CREATED = "2026-09-29T04:00:00Z"


def _context(probe_id: str, facts: dict[str, JsonValue]) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW,
        probe_id=probe_id,
        summary="Saved exact target observation",
        facts=facts,
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
    )


def _inventory(status: str, *, omitted: int = 0, name: str = NAME) -> EvidenceContext:
    facts: dict[str, JsonValue] = {
        "target_process_search": [
            {
                "name": name,
                "status": status,
                "matched_row_count": 1 if status == "matching_process_observed" else 0,
                "omitted_process_count": omitted,
            }
        ],
        "collection_status": "available",
        "omitted_counts": {"processes": omitted},
        "collection_completed_at": NOW.isoformat(),
    }
    if status == "matching_process_observed":
        facts["processes.42"] = {
            "name": name,
            "pid": 4242,
            "creation_time": CREATED,
        }
    return _context("application.snapshot", facts)


def _pressure(*, pid: int = 4242, cpu: tuple[float, float] = (4.1, 3.9)) -> EvidenceContext:
    return _context(
        "application.target_pressure",
        {
            "target_pressure": {
                "status": "available",
                "target_pid": pid,
                "target_creation_time": CREATED,
                "window_ended_at": NOW.isoformat(),
                "samples": [
                    {"name": NAME, "delta_status": "baseline", "cpu_percent": None},
                    *(
                        {
                            "name": NAME,
                            "delta_status": "measured",
                            "cpu_percent": value,
                            "status": "available",
                        }
                        for value in cpu
                    ),
                ],
            }
        },
    )


def _request(*contexts: EvidenceContext, objective: str | None = None) -> ReasoningRequest:
    return ReasoningRequest(
        case_id=CaseId.new(),
        state_version=1,
        correlation_id="named_process_basic",
        deadline_at=NOW + timedelta(minutes=1),
        objective=objective or f"Is {NAME} using CPU now?",
        evidence_ids=tuple(item.evidence_id for item in contexts),
        evidence_context=contexts,
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="Saved process inventory",
                cost_ms=1000,
                resource_class=ResourceClass.PROCESS,
            ),
        ),
        budget_ms=5000,
        max_probes=1,
    )


def test_basic_reports_identity_bound_cpu_values_and_limits() -> None:
    inventory = _inventory("matching_process_observed")
    pressure = _pressure()
    response = DeterministicReasoningProvider().investigate(_request(inventory, pressure))

    assert "4.1%" in response.summary and "3.9%" in response.summary
    assert "during" in response.summary and "cause" in response.summary
    assert {str(item) for item in response.considered_evidence_ids} == {
        str(inventory.evidence_id),
        str(pressure.evidence_id),
    }


def test_basic_distinguishes_complete_absence_from_incomplete_inventory() -> None:
    absent = _inventory("no_matching_process_in_saved_complete_table")
    incomplete = _inventory("incomplete_process_inventory", omitted=10)

    absent_response = DeterministicReasoningProvider().investigate(_request(absent))
    incomplete_response = DeterministicReasoningProvider().investigate(_request(incomplete))

    assert "not observed running" in absent_response.summary
    assert "at the saved snapshot time" in absent_response.summary
    assert "cause" in absent_response.summary
    assert "not observed running" not in incomplete_response.summary


def test_basic_ignores_wrong_identity_and_does_not_call_idle_a_failure() -> None:
    inventory = _inventory("matching_process_observed")
    mismatched = DeterministicReasoningProvider().investigate(
        _request(inventory, _pressure(pid=9000))
    )
    idle = DeterministicReasoningProvider().investigate(
        _request(inventory, _pressure(cpu=(0.0, 0.0)))
    )

    assert "4.1%" not in mismatched.summary
    assert "0.0%" in idle.summary
    assert "No measurable CPU use was observed in those intervals" in idle.summary
    assert "failed" not in idle.summary.casefold()


def test_basic_keeps_generic_gap_without_exact_executable() -> None:
    response = DeterministicReasoningProvider().investigate(
        _request(_inventory("matching_process_observed"), objective="My app feels slow")
    )

    assert (
        response.summary
        == "The cause remains unknown; only reviewed observation rules were applied."
    )
