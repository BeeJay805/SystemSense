"""The first deep turn must retain trusted task and focus-delivery custody."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import pytest

from benchmarks.source_task_relation_red import run_balanced_relation_probe
from systemsense.application.investigator import Investigator
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.deterministic import DeterministicReasoningProvider


@pytest.mark.parametrize(
    ("time_quality", "expect_relation"),
    [("exact", True), ("unknown", False)],
)
def test_first_selected_source_reaches_deep_with_trusted_time_quality(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    time_quality: Literal["exact", "unknown"],
    expect_relation: bool,
) -> None:
    requests: list[ReasoningRequest] = []
    original = DeterministicReasoningProvider.investigate

    def capture(
        provider: DeterministicReasoningProvider, request: ReasoningRequest
    ) -> ReasoningResponse:
        requests.append(request)
        return original(provider, request)

    monkeypatch.setattr(DeterministicReasoningProvider, "investigate", capture)
    tampered = [False]
    original_deep = Investigator._reason  # pyright: ignore[reportPrivateUsage]

    def tamper_after_delivery(app: Investigator, state: Any, *args: Any, **kwargs: Any) -> Any:
        if (
            time_quality == "unknown"
            and not tampered[0]
            and state.fast_catalog_selected_ids
            and str(state.fast_catalog_selected_ids[0]) == f"ev_{49:032x}"
        ):
            with app.store.transaction():
                app.store.connection.execute(
                    "UPDATE evidence SET time_quality='unknown' WHERE case_id=? AND evidence_id=?",
                    (str(state.case_id), f"ev_{49:032x}"),
                )
            tampered[0] = True
        return original_deep(app, state, *args, **kwargs)

    monkeypatch.setattr(Investigator, "_reason", tamper_after_delivery)
    cells = run_balanced_relation_probe(
        tmp_path / "first-selection",
        domain_filter="network_browser",
        matched_indices=(49,),
        chosen_indices=(49,),
    )
    assert len(cells) == 1
    cell = cells[0]
    chosen_id = cell["chosen_evidence_id"]
    task_id = cell["task_observation"]["evidence_id"]
    first_postselection = next(
        request
        for request in requests
        if chosen_id in {str(item) for item in request.priority_evidence_ids}
        and chosen_id in {str(item.evidence_id) for item in request.evidence_context}
    )
    assert first_postselection.schema_version == 6
    assert first_postselection.task_observation is not None
    assert str(first_postselection.task_observation.evidence_id) == task_id
    assert str(first_postselection.task_observation.evidence_id) in {
        str(item.evidence_id) for item in first_postselection.evidence_context
    }
    selected = first_postselection.selected_sources
    if expect_relation:
        assert not tampered[0]
        chosen = [item for item in selected if str(item.evidence_id) == chosen_id]
        assert len(chosen) == 1
        assert chosen[0].source_task_relation is not None
        assert chosen[0].source_task_relation.status == "same_target_full_window"
        assert chosen[0].source_task_relation.task_record_sha256 == (
            first_postselection.task_observation.record_sha256
        )
    else:
        assert tampered[0]
        assert chosen_id not in {str(item.evidence_id) for item in selected}
        assert "Selected fixture coverage omitted: persisted time quality invalid." in (
            first_postselection.observer_context
        )
