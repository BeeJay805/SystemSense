"""The model may anchor a request claim only to an actual request window."""

from datetime import UTC, datetime
from typing import Literal, cast

from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.structured import StructuredReasoningProvider
from tests.unit.reasoning.test_providers import _request  # pyright: ignore[reportPrivateUsage]


def _context(
    facts: dict[str, JsonValue],
    *,
    scope: Literal["current_case", "historical", "unspecified"] = "current_case",
    status: EvidenceContextStatus = EvidenceContextStatus.OBSERVED,
) -> EvidenceContext:
    now = datetime(2026, 9, 29, 12, tzinfo=UTC)
    return EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=now,
        captured_at=now,
        probe_id="task.loopback_http" if "action" in facts else "application.snapshot",
        summary="Synthetic contract fixture, not a host measurement.",
        facts=facts,
        status=status,
        case_scope=scope,
        incident_relevant=True,
    )


def _anchor_schema(
    contexts: tuple[EvidenceContext, ...], visible: tuple[EvidenceId, ...]
) -> dict[str, object]:
    request = _request().model_copy(
        update={
            "schema_version": 7,
            "evidence_context": contexts,
            "evidence_ids": tuple(item.evidence_id for item in contexts),
        }
    )
    schema = StructuredReasoningProvider._advice_schema(  # pyright: ignore[reportPrivateUsage]
        request, visible
    )
    definitions = cast(dict[str, dict[str, object]], schema["$defs"])
    props = cast(dict[str, dict[str, object]], definitions["_HypothesisAdvice"]["properties"])
    return props["claim_window_evidence_id"]


def test_inventory_cannot_be_offered_as_a_request_window() -> None:
    inventory = _context({"processes": [], "collection_status": "available"})
    field = _anchor_schema((inventory,), (inventory.evidence_id,))
    assert field == {"anyOf": [{"type": "null"}]}


def test_only_visible_current_observed_request_windows_are_offered() -> None:
    facts: dict[str, JsonValue] = {
        "target_handle": "127.0.0.1:61234",
        "action": "GET /health/" + "a" * 32,
        "request_started_at_utc": "2026-09-29T12:00:00+00:00",
        "request_finished_at_utc": "2026-09-29T12:00:00.005+00:00",
    }
    task = _context(facts)
    replay = _context({"loopback_replay": facts})
    process = _context({"processes": []})
    malformed = _context({**facts, "request_started_at_utc": "not-a-time"})
    historical = _context(facts, scope="historical")
    denied = _context(facts, status=EvidenceContextStatus.DENIED)
    hidden = _context(facts)
    contexts = (task, replay, process, malformed, historical, denied, hidden)
    field = _anchor_schema(contexts, tuple(item.evidence_id for item in contexts[:-1]))
    assert field == {
        "anyOf": [
            {"type": "string", "enum": [str(task.evidence_id), str(replay.evidence_id)]},
            {"type": "null"},
        ]
    }
