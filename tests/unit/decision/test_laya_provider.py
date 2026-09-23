from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from systemsense.decision.contracts import DecisionRequest, ProbeCapability, ResourceClass
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaCachedOrigin,
    LayaRuntimeError,
)

NOW = datetime.now(UTC)


def test_default_request_deadline_tracks_request_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(_request.__globals__, "NOW", datetime.now(UTC) - timedelta(minutes=2))
    assert _request().deadline_at > datetime.now(UTC) + timedelta(seconds=50)


class _Ranker:
    def __init__(self, result: LayaAttentionResult | Exception) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult:
        self.calls.append(
            {
                "state": state,
                "evidence": evidence,
                "candidates": candidates,
                "timeout_seconds": timeout_seconds,
            }
        )
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _capability(
    probe_id: str,
    *,
    description: str,
    keywords: frozenset[str] = frozenset(),
    cost_ms: int = 100,
) -> ProbeCapability:
    return ProbeCapability(
        probe_id=probe_id,
        description=description,
        keywords=keywords,
        baseline_priority=0.5,
        cost_ms=cost_ms,
        resource_class=ResourceClass.CPU,
    )


def _request(*, deadline_at: datetime | None = None, budget_ms: int = 500) -> DecisionRequest:
    evidence_id = EvidenceId.new()
    return DecisionRequest(
        case_id=CaseId.new(),
        state_version=2,
        correlation_id="corr_laya",
        deadline_at=deadline_at or datetime.now(UTC) + timedelta(minutes=1),
        symptom="application fails to launch",
        evidence_ids=(evidence_id,),
        evidence_context=(
            EvidenceContext(
                evidence_id=evidence_id,
                observed_at=NOW,
                captured_at=NOW,
                probe_id="core.system",
                summary="The application process exited during initialization.",
                facts={"exit.code": 1},
                status=EvidenceContextStatus.OBSERVED,
            ),
        ),
        completed_probe_ids=frozenset({"core.system"}),
        available_probes=(
            _capability("core.system", description="system snapshot", cost_ms=50),
            _capability(
                "application.snapshot",
                description="application process and failure snapshot",
                keywords=frozenset({"application", "launch"}),
                cost_ms=125,
            ),
            _capability(
                "eventlog.application",
                description="application event log errors",
                keywords=frozenset({"application"}),
                cost_ms=200,
            ),
        ),
        budget_ms=budget_ms,
        max_probes=2,
    )


def test_provider_uses_rank_order_but_rebuilds_every_trusted_catalog_field() -> None:
    request = _request()
    ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("eventlog.application", "application.snapshot"),
            ranked_evidence_ids=(str(request.evidence_ids[0]),),
            considered_probe_ids=("eventlog.application", "application.snapshot"),
            considered_evidence_ids=(str(request.evidence_ids[0]),),
            ranked_attention_page_ids=(f"{request.evidence_ids[0]}:0",),
            considered_attention_page_ids=(f"{request.evidence_ids[0]}:0",),
            attention_notes=("ordinal_relevance_only",),
        )
    )
    provider = LayaDecisionProvider(ranker=ranker, timeout_seconds=5)

    response = provider.decide(request)

    assert response.provider.provider_id == "laya-local-decision"
    assert [proposal.probe_id for proposal in response.proposals] == [
        "eventlog.application",
        "application.snapshot",
    ]
    assert [proposal.estimated_cost_ms for proposal in response.proposals] == [200, 125]
    assert all(proposal.resource_class is ResourceClass.CPU for proposal in response.proposals)
    assert response.proposals[0].priority > response.proposals[1].priority
    assert response.ranked_evidence_ids == request.evidence_ids
    assert response.ranked_attention_page_ids == (f"{request.evidence_ids[0]}:0",)
    assert response.considered_evidence_count == 1
    assert response.considered_evidence_ids == request.evidence_ids
    assert response.attention_notes == ("ordinal_relevance_only",)
    assert response.validate_against(request) == response
    sent_ids = [item["probe_id"] for item in ranker.calls[0]["candidates"]]  # type: ignore[index]
    assert "core.system" not in sent_ids


def test_provider_falls_back_explicitly_on_unavailable_or_invalid_ranking() -> None:
    for result in (
        LayaRuntimeError("offline worker unavailable"),
        LayaRuntimeError("Laya host RAM admission rejected cold worker start"),
        LayaAttentionResult(
            ranked_probe_ids=("unknown.probe", "application.snapshot"),
            considered_probe_ids=("unknown.probe", "application.snapshot"),
        ),
        LayaAttentionResult(
            ranked_probe_ids=("application.snapshot", "application.snapshot"),
            considered_probe_ids=("application.snapshot",),
        ),
    ):
        provider = LayaDecisionProvider(ranker=_Ranker(result))
        response = provider.decide(_request())
        assert response.degraded is True
        assert response.provider.provider_id == "keyword-baseline"
        assert response.stop_reason is not None
        assert response.stop_reason.startswith("laya_invalid_or_unavailable:")
        assert "LayaRuntimeError" in response.stop_reason
        if isinstance(result, LayaRuntimeError) and "RAM" in str(result):
            assert "RAM" in response.stop_reason
        assert provider.status.available is False


def test_fake_ranker_metadata_is_not_attested_as_worker_presentation() -> None:
    request = _request()
    result = LayaAttentionResult(
        ranked_probe_ids=("eventlog.application", "application.snapshot"),
        considered_probe_ids=("eventlog.application", "application.snapshot"),
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("eventlog.application", "application.snapshot"),
                cache_hit_ids=("eventlog.application", "application.snapshot"),
                cached_origins=(
                    LayaCachedOrigin(item_id="eventlog.application", presentation_sha256="a" * 64),
                    LayaCachedOrigin(item_id="application.snapshot", presentation_sha256="b" * 64),
                ),
            ),
        ),
    )
    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)
    assert response.provider.provider_id == "laya-local-decision"
    assert response.presentation_trace is None


def test_laya_escalates_only_when_deadline_left_a_presented_page_unconsidered() -> None:
    base = _request()
    unseen = EvidenceId.new()
    second = base.evidence_context[0].model_copy(update={"evidence_id": unseen})
    request = base.model_copy(
        update={
            "evidence_ids": (*base.evidence_ids, unseen),
            "attention_context": (*base.evidence_context, second),
        }
    )
    first_id = str(base.evidence_ids[0])
    result = LayaAttentionResult(
        ranked_probe_ids=("eventlog.application", "application.snapshot"),
        considered_probe_ids=("eventlog.application", "application.snapshot"),
        ranked_evidence_ids=(first_id,),
        considered_evidence_ids=(first_id,),
        ranked_attention_page_ids=(f"{first_id}:0",),
        considered_attention_page_ids=(f"{first_id}:0",),
        attention_notes=("coverage_limited=true",),
    )
    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)
    assert response.requires_reasoning is True
    assert len(response.signals) == 1
    assert response.signals[0].kind.value == "coverage_gap"
    assert response.signals[0].evidence_ids == ()
    assert response.considered_evidence_ids == base.evidence_ids
    assert response.validate_against(request) == response

    not_deadline_limited = result.model_copy(
        update={"attention_notes": ("coverage_limited=false",)}
    )
    no_signal = LayaDecisionProvider(ranker=_Ranker(not_deadline_limited)).decide(request)
    assert no_signal.requires_reasoning is False
    assert no_signal.signals == ()
    all_pages = result.model_copy(
        update={
            "considered_attention_page_ids": (f"{first_id}:0", f"{unseen}:1"),
            "considered_evidence_ids": (first_id, str(unseen)),
        }
    )
    no_gap = LayaDecisionProvider(ranker=_Ranker(all_pages)).decide(request)
    assert no_gap.requires_reasoning is False
    assert no_gap.signals == ()


def test_provider_obeys_deadline_budget_and_covers_all_candidates() -> None:
    expired_ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("application.snapshot",),
            considered_probe_ids=("application.snapshot",),
        )
    )
    expired = LayaDecisionProvider(ranker=expired_ranker).decide(
        _request(deadline_at=NOW - timedelta(seconds=1))
    )
    assert expired.degraded is True
    assert expired_ranker.calls == []

    ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("eventlog.application", "application.snapshot"),
            considered_probe_ids=("eventlog.application", "application.snapshot"),
        )
    )
    response = LayaDecisionProvider(ranker=ranker).decide(_request(budget_ms=150))
    assert len(ranker.calls[0]["candidates"]) == 2  # type: ignore[arg-type]
    assert sum(item.estimated_cost_ms for item in response.proposals) <= 150


def test_provider_still_ranks_attention_context_when_no_probe_is_eligible() -> None:
    base = _request()
    request = base.model_copy(
        update={
            "completed_probe_ids": frozenset(
                {"core.system", "application.snapshot", "eventlog.application"}
            ),
            "preferred_probe_ids": ("eventlog.application",),
            "attention_context": base.evidence_context,
        }
    )
    attention_id = str(request.attention_context[0].evidence_id)
    ranker = _Ranker(
        LayaAttentionResult(
            ranked_evidence_ids=(attention_id,),
            considered_evidence_ids=(attention_id,),
            attention_notes=("ordinal_relevance_only",),
        )
    )

    response = LayaDecisionProvider(ranker=ranker).decide(request)

    assert response.provider.provider_id == "laya-local-decision"
    assert response.proposals == ()
    assert response.considered_evidence_count == 1
    assert ranker.calls[0]["candidates"] == ()
    assert ranker.calls[0]["state"]["preferred_probe_ids"] == ["eventlog.application"]  # type: ignore[index]
    assert ranker.calls[0]["evidence"]  # type: ignore[index]


def test_attention_only_request_skips_probe_scoring_and_proposals() -> None:
    request = _request().model_copy(update={"attention_only": True})
    evidence_id = str(request.evidence_ids[0])
    ranker = _Ranker(
        LayaAttentionResult(
            ranked_evidence_ids=(evidence_id,),
            considered_evidence_ids=(evidence_id,),
            ranked_attention_page_ids=(f"{evidence_id}:0",),
            considered_attention_page_ids=(f"{evidence_id}:0",),
            attention_notes=("ordinal_relevance_only",),
        )
    )

    response = LayaDecisionProvider(ranker=ranker).decide(request)

    assert response.provider.provider_id == "laya-local-decision"
    assert response.proposals == ()
    assert ranker.calls[0]["candidates"] == ()


def test_state_preserves_graph_mechanisms_instead_of_slicing_packet_json() -> None:
    request = _request().model_copy(
        update={
            "reference_context": (
                {
                    "pack_id": "windows-diagnostics",
                    "nodes": [
                        {
                            "node_id": "kn_process_startup",
                            "label": "Process startup",
                            "aliases": ["launch"],
                            "padding": "x" * 1000,
                        },
                        {
                            "node_id": "kn_eventlog_application",
                            "label": "Application event log",
                            "aliases": [],
                        },
                    ],
                    "relations": [
                        {
                            "relation_id": "kr_startup.eventlog",
                            "source_node_id": "kn_process_startup",
                            "target_node_id": "kn_eventlog_application",
                            "relationship": "can_contribute_to",
                            "mechanism": "Loader failures can terminate a process during startup.",
                            "conditions": ["process exits before its window appears"],
                            "distinguishing_probe_ids": ["eventlog.application"],
                            "limitations": ["an event does not by itself prove cause"],
                        }
                    ],
                },
            )
        }
    )

    ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("eventlog.application", "application.snapshot"),
            considered_probe_ids=("eventlog.application", "application.snapshot"),
        )
    )
    LayaDecisionProvider(ranker=ranker).decide(request)
    state = cast(dict[str, object], ranker.calls[0]["state"])
    assert isinstance(state, dict)

    assert tuple(state)[:3] == (
        "reference_knowledge",
        "machine_relationships",
        "preferred_probe_ids",
    )
    references = cast(list[dict[str, object]], state["reference_knowledge"])
    assert isinstance(references, list)
    assert references[0]["mechanism"] == ("Loader failures can terminate a process during startup.")
    assert references[0]["source"] == "Process startup"
    assert references[0]["distinguishing_probe_ids"] == ["eventlog.application"]


def test_attention_preview_covers_many_pages_and_keeps_late_alarm_visible() -> None:
    base = _request()
    evidence_id = base.evidence_ids[0]
    pages = tuple(
        EvidenceContext(
            evidence_id=evidence_id,
            observed_at=NOW - timedelta(minutes=index),
            captured_at=NOW,
            probe_id="eventlog.application",
            summary="Routine activity " + "context " * 80,
            facts={
                **{f"routine.{fact}": "detail " * 45 for fact in range(12)},
                "critical.failure": "LATE_DISK_FAILURE" if index == 38 else "none",
            },
            status=EvidenceContextStatus.PARTIAL if index == 38 else EvidenceContextStatus.OBSERVED,
            limitations=("Some source records were unavailable",) if index == 38 else (),
        )
        for index in range(39)
    )
    request = base.model_copy(update={"attention_context": pages})

    ranker = _Ranker(LayaAttentionResult())
    LayaDecisionProvider(ranker=ranker).decide(request)
    fragments = cast(tuple[dict[str, str], ...], ranker.calls[0]["evidence"])
    first_batch_pages = {fragment["page_id"] for fragment in fragments[:20]}
    late_page_id = f"{evidence_id}:38"

    assert len(fragments) == 39
    assert len(first_batch_pages) == 20
    assert late_page_id in first_batch_pages
    late = next(fragment for fragment in fragments if fragment["page_id"] == late_page_id)
    preview = json.loads(late["description"])
    assert late["fragment_id"] == f"{late_page_id}:preview:0"
    assert preview["projection"] == "bounded_preview_not_full_page"
    assert late["page_id"] == late_page_id
    assert late["evidence_id"] == str(evidence_id)
    assert preview["observed_at"] == pages[38].observed_at.isoformat()
    assert preview["captured_at"] == pages[38].captured_at.isoformat()
    assert preview["status"] == "partial"
    assert preview["redaction_applied"] is True
    assert preview["facts"]["critical.failure"] == "LATE_DISK_FAILURE"
    assert "LATE_DISK_FAILURE" in late["description"][:240]
    assert "Some source records were unavailable" in preview["limitations"]
    assert preview["facts_omitted"] > 0
    assert preview["summary_truncated"] is True
    assert len(late["description"]) <= 650
    state = cast(dict[str, object], ranker.calls[0]["state"])
    assert "evidence_pages_are_bounded_previews" in cast(list[str], state["coverage_notes"])


def test_preview_reserves_room_for_alarm_when_optional_text_is_maximal() -> None:
    base = _request()
    alarm_key = "critical." + "x" * 111
    alarm = EvidenceContext(
        evidence_id=base.evidence_ids[0],
        observed_at=NOW,
        captured_at=NOW,
        probe_id="a" * 120,
        summary="s" * 1000,
        facts={alarm_key: "DISK_FAILURE"},
        status=EvidenceContextStatus.PARTIAL,
        limitations=("l" * 240,) * 3,
    )
    request = base.model_copy(update={"attention_context": (*base.evidence_context * 255, alarm)})
    ranker = _Ranker(LayaAttentionResult())

    LayaDecisionProvider(ranker=ranker).decide(request)

    fragments = cast(tuple[dict[str, str], ...], ranker.calls[0]["evidence"])
    late = next(item for item in fragments if item["page_id"].endswith(":255"))
    preview = json.loads(late["description"])
    assert preview["facts"].get(alarm_key) == "DISK_FAILURE", preview
    assert preview["facts_omitted"] == 0
    assert preview["limitations_omitted"] > 0
    assert late["page_id"] == f"{base.evidence_ids[0]}:255"
    assert late["evidence_id"] == str(base.evidence_ids[0])
    assert preview["redaction_applied"] is True
    assert len(json.dumps(preview, ensure_ascii=False, separators=(",", ":"))) <= 650

    long_alarm = alarm.model_copy(update={"facts": {alarm_key: "DISK_FAILURE" + "x" * 500}})
    long_request = base.model_copy(update={"attention_context": (long_alarm,)})
    long_ranker = _Ranker(LayaAttentionResult())
    LayaDecisionProvider(ranker=long_ranker).decide(long_request)
    long_fragment = cast(tuple[dict[str, str], ...], long_ranker.calls[0]["evidence"])[0]
    long_preview = json.loads(long_fragment["description"])
    assert long_preview["facts"] or long_preview["fact_excerpt_unavailable"] == "budget"
    assert len(long_fragment["description"]) <= 650
