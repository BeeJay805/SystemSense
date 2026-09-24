"""Progress requires usable new observations, not merely new probe failures."""

from datetime import UTC, datetime, timedelta
from typing import Literal

from systemsense.application.investigator import Investigator
from systemsense.domain.ids import EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus

NOW = datetime(2026, 9, 23, 6, 30, tzinfo=UTC)


def _context(
    probe_id: str,
    status: EvidenceContextStatus,
    *,
    value: int = 0,
    observed_after_capture: bool = False,
    case_scope: Literal["current_case", "historical", "unspecified"] = "current_case",
    incident_relevant: bool = True,
) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=EvidenceId.new(),
        probe_id=probe_id,
        observed_at=NOW + (timedelta(seconds=1) if observed_after_capture else timedelta()),
        captured_at=NOW,
        summary=f"{probe_id} returned {status.value}",
        facts={"value": value},
        status=status,
        case_scope=case_scope,
        incident_relevant=incident_relevant,
    )


def test_distinct_failed_or_unavailable_probes_do_not_reset_progress() -> None:
    first = _context("network.one", EvidenceContextStatus.FAILED)
    second = _context("network.two", EvidenceContextStatus.UNAVAILABLE)
    third = _context("network.three", EvidenceContextStatus.DENIED)

    assert Investigator._fingerprint(()) == Investigator._fingerprint((first,))  # pyright: ignore[reportPrivateUsage]
    assert Investigator._fingerprint((first,)) == Investigator._fingerprint(  # pyright: ignore[reportPrivateUsage]
        (first, second, third)
    )


def test_coverage_receipt_without_observation_is_not_progress() -> None:
    receipt = _context("network.coverage", EvidenceContextStatus.OBSERVED).model_copy(
        update={"facts": {}}
    )
    partial_without_facts = _context("network.partial", EvidenceContextStatus.PARTIAL)
    partial_without_facts = partial_without_facts.model_copy(update={"facts": {}})

    assert Investigator._fingerprint(()) == Investigator._fingerprint(  # pyright: ignore[reportPrivateUsage]
        (receipt, partial_without_facts)
    )


def test_new_valid_observations_change_progress_but_clock_inconsistent_does_not() -> None:
    first = _context("network.one", EvidenceContextStatus.OBSERVED, value=1)
    second = _context("network.two", EvidenceContextStatus.PARTIAL, value=2)
    impossible = _context(
        "network.three", EvidenceContextStatus.OBSERVED, observed_after_capture=True
    )

    assert Investigator._fingerprint((first,)) != Investigator._fingerprint(  # pyright: ignore[reportPrivateUsage]
        (first, second)
    )
    assert Investigator._fingerprint((first,)) == Investigator._fingerprint(  # pyright: ignore[reportPrivateUsage]
        (first, impossible)
    )


def test_historical_and_out_of_incident_observations_do_not_reset_progress() -> None:
    current = _context("network.current", EvidenceContextStatus.OBSERVED)
    historical = _context(
        "network.historical", EvidenceContextStatus.OBSERVED, case_scope="historical"
    )
    out_of_window = _context(
        "network.late", EvidenceContextStatus.OBSERVED, incident_relevant=False
    )

    assert Investigator._fingerprint((current,)) == Investigator._fingerprint(  # pyright: ignore[reportPrivateUsage]
        (current, historical, out_of_window)
    )


def test_equivalent_facts_with_new_record_ids_do_not_change_novelty() -> None:
    first = _context("network.one", EvidenceContextStatus.OBSERVED, value=1)
    repeated = first.model_copy(
        update={"evidence_id": EvidenceId.new(), "summary": "Same facts, new presentation"}
    )

    assert Investigator._fingerprint((first,)) == Investigator._fingerprint(  # pyright: ignore[reportPrivateUsage]
        (first, repeated)
    )
