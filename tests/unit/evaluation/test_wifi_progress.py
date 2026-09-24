"""Only explicit, scoped WLAN observations may discriminate association state."""

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.probes import MeasurementWindow
from systemsense.evaluation import progress
from systemsense.packs.runtime import default_probe_definitions
from systemsense.platform.windows.connectivity import ConnectivitySnapshot, WifiInterface
from systemsense.platform.windows.deep_collectors import ComponentStatus

NOW = datetime(2026, 9, 24, tzinfo=UTC)
GUID = "00000000-0000-0000-0000-000000000001"
CASE = CaseId.new()


def _record(state: str = "connected", *, case_id: CaseId = CASE) -> EvidenceRecord:
    snapshot = ConnectivitySnapshot(
        source_id="src_" + "a" * 64,
        captured_at=NOW,
        wifi_observed_at=NOW,
        wifi_status=ComponentStatus.AVAILABLE,
        wifi_interfaces=(
            WifiInterface(interface_guid=GUID, description="Wi-Fi", association_state=state),
        ),
        omitted_wifi_count=0,
        addresses_observed_at=NOW,
        addresses_status=ComponentStatus.UNSUPPORTED,
        adapters=(),
        omitted_adapter_count=0,
        routes_observed_at=NOW,
        routes_status=ComponentStatus.UNSUPPORTED,
        default_routes=(),
        omitted_route_count=0,
        proxy_observed_at=NOW,
        proxy_status=ComponentStatus.UNSUPPORTED,
        proxy=None,
        wlan_events_observed_at=NOW,
        wlan_events_status=ComponentStatus.UNSUPPORTED,
        recent_failures=(),
        omitted_failure_count=0,
        status=ComponentStatus.PARTIAL,
    )
    return EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW,
        captured_at=NOW,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=stable_source_id(
                "systemsense.probe", {"probe_id": "network.connectivity", "probe_version": 3}
            ),
            locator={"probe_id": "network.connectivity"},
        ),
        collector=CollectorReference(
            id="network.connectivity", version=3, execution_id=ExecutionId.new()
        ),
        summary="WLAN snapshot",
        facts=(
            EvidenceFact(
                name="connectivity_detail", value=cast(JsonValue, snapshot.model_dump(mode="json"))
            ),
        ),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )


def test_registered_evidence_evaluator_exists() -> None:
    assert hasattr(progress, "evaluate_wifi_association")
    current = next(
        item.manifest
        for item in default_probe_definitions()
        if item.manifest.probe_id == "network.connectivity"
    )
    assert _record().collector.version == current.version


def test_old_baseline_does_not_obscure_an_in_window_followup() -> None:
    scope = progress.PredicateScope(
        case_id=CASE,
        target_handle=GUID,
        window=MeasurementWindow(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=1)),
    )
    old = _record("disconnected")
    raw = cast(dict[str, JsonValue], old.facts[0].value).copy()
    raw["wifi_observed_at"] = (NOW - timedelta(minutes=10)).isoformat()
    old = old.model_copy(update={"facts": (EvidenceFact(name="connectivity_detail", value=raw),)})
    current = _record()
    result = progress.evaluate_wifi_association(scope=scope, evidence=(old, current))
    assert result.observed is True
    assert result.evidence_ids == (current.evidence_id,)


def test_scoped_progress_is_computed_from_records_and_unknown_is_retained() -> None:
    assert hasattr(progress, "record_test_progress")
    scope = progress.PredicateScope(
        case_id=CASE,
        target_handle=GUID,
        window=MeasurementWindow(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=1)),
    )
    intent = progress.TestIntent(
        intent_id="test.association",
        branch_id="branch.network",
        probe_id="network.connectivity",
        uncertainty_id="uncertainty.association",
        scope=scope,
        predictions=(
            progress.PredictedOutcome(
                hypothesis_id="hyp.associated",
                predicate_id="network.wifi_associated",
                expected=True,
            ),
            progress.PredictedOutcome(
                hypothesis_id="hyp.disconnected",
                predicate_id="network.wifi_associated",
                expected=False,
            ),
        ),
    )
    record = _record()
    ledger = progress.record_test_progress(
        progress.ProgressLedger(), intent=intent, evidence=(record,)
    )
    assert ledger.events[-1].diagnostic_progress
    assert ledger.events[-1].scope == scope
    assert ledger.events[-1].evaluation is not None
    assert ledger.events[-1].prediction_matched_hypothesis_ids == ("hyp.associated",)
    ledger = progress.record_test_progress(ledger, intent=intent, evidence=(record,))
    assert not ledger.events[-1].diagnostic_progress
    unknown = _record("authenticating")
    ledger = progress.record_test_progress(ledger, intent=intent, evidence=(unknown,))
    assert not ledger.events[-1].diagnostic_progress
    assert ledger.events[-1].evidence_ids == (unknown.evidence_id,)
    assert ledger.events[-1].evaluation is not None
    assert ledger.events[-1].evaluation.observed is None
    other_scope = scope.model_copy(update={"case_id": CaseId.new()})
    other_intent = intent.model_copy(update={"scope": other_scope})
    ledger = progress.record_test_progress(
        ledger, intent=other_intent, evidence=(_record(case_id=other_scope.case_id),)
    )
    assert ledger.events[-1].diagnostic_progress


def test_scoped_intent_rejects_unbound_boolean_observation() -> None:
    assert "scope" in progress.TestIntent.model_fields
    scope = progress.PredicateScope(
        case_id=CASE,
        target_handle=GUID,
        window=MeasurementWindow(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=1)),
    )
    intent = progress.TestIntent(
        intent_id="test.association",
        branch_id="branch.network",
        probe_id="network.connectivity",
        uncertainty_id="uncertainty.association",
        scope=scope,
        predictions=(
            progress.PredictedOutcome(
                hypothesis_id="hyp.associated",
                predicate_id="network.wifi_associated",
                expected=True,
            ),
            progress.PredictedOutcome(
                hypothesis_id="hyp.disconnected",
                predicate_id="network.wifi_associated",
                expected=False,
            ),
        ),
    )
    with pytest.raises(ValueError, match="scope"):
        progress.record_progress(
            progress.ProgressLedger(),
            intent=intent,
            observation=progress.VerifiedPredicateObservation(
                predicate_id="network.wifi_associated",
                observed=True,
                evidence_ids=(EvidenceId.new(),),
            ),
        )


@pytest.mark.parametrize(("state", "expected"), [("connected", True), ("disconnected", False)])
def test_explicit_state_has_exact_scope_and_citation(state: str, expected: bool) -> None:
    scope = progress.PredicateScope(
        case_id=CASE,
        target_handle=GUID,
        window=MeasurementWindow(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=1)),
    )
    record = _record(state)
    result = progress.evaluate_wifi_association(scope=scope, evidence=(record,))
    assert result.observed is expected
    assert result.scope == scope
    assert result.evidence_ids == (record.evidence_id,)
    assert result.observed_at == (NOW,)


@pytest.mark.parametrize(
    "failure",
    [
        "missing",
        "wrong_case",
        "wrong_target",
        "old",
        "transition",
        "partial",
        "malformed",
        "conflict",
        "duplicate_fact",
        "future",
        "forged_source",
        "wrong_parser",
        "old_probe_version",
    ],
)
def test_incomplete_or_ambiguous_evidence_stays_unknown(failure: str) -> None:
    scope = progress.PredicateScope(
        case_id=CASE,
        target_handle=GUID,
        window=MeasurementWindow(start=NOW - timedelta(seconds=1), end=NOW + timedelta(seconds=1)),
    )
    record = _record("authenticating" if failure == "transition" else "connected")
    evidence = (record,)
    if failure == "missing":
        evidence = ()
    elif failure == "wrong_case":
        evidence = (_record(case_id=CaseId.new()),)
    elif failure == "wrong_target":
        scope = scope.model_copy(update={"target_handle": "00000000-0000-0000-0000-000000000002"})
    elif failure == "old":
        scope = scope.model_copy(
            update={
                "window": MeasurementWindow(
                    start=NOW + timedelta(seconds=1), end=NOW + timedelta(seconds=2)
                )
            }
        )
    elif failure == "conflict":
        evidence = (record, _record("disconnected"))
    elif failure == "duplicate_fact":
        evidence = (record.model_copy(update={"facts": record.facts * 2}),)
    elif failure == "future":
        evidence = (record.model_copy(update={"captured_at": NOW - timedelta(seconds=1)}),)
    elif failure == "forged_source":
        evidence = (
            record.model_copy(
                update={"source": record.source.model_copy(update={"source_id": "src_" + "b" * 64})}
            ),
        )
    elif failure == "wrong_parser":
        evidence = (
            record.model_copy(
                update={"extraction": record.extraction.model_copy(update={"parser": "other"})}
            ),
        )
    elif failure == "old_probe_version":
        evidence = (
            record.model_copy(
                update={"collector": record.collector.model_copy(update={"version": 1})}
            ),
        )
    elif failure in {"partial", "malformed"}:
        raw = cast(dict[str, JsonValue], record.facts[0].value).copy()
        raw["wifi_status"] = "partial" if failure == "partial" else "bogus"
        evidence = (
            record.model_copy(
                update={"facts": (EvidenceFact(name="connectivity_detail", value=raw),)}
            ),
        )
    result = progress.evaluate_wifi_association(scope=scope, evidence=evidence)
    assert result.observed is None
    assert result.reason
