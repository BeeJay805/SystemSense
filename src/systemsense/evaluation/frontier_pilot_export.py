"""Small, fixture-only export of exact persisted frontier decision packets.

This is a custody pilot, not a training admission decision. In particular the
database does not retain actual worker token IDs or a tokenizer/build receipt.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from typing import Literal, cast

from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    _verify_exact_worker_capture,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.storage.candidate_decision_snapshots import (
    CandidateDecisionSnapshotRepository,
    FrontierCandidateSnapshot,
)
from systemsense.storage.frontier_packet_receipts import (
    FrontierPacketReceiptRepository,
    FrontierPacketReceiptV1,
)
from systemsense.storage.sqlite_store import SQLiteStore

OutcomeStatus = Literal["useful", "uninformative", "contradictory", "failed", "unrun"]
PilotSplit = Literal["pilot_train", "pilot_holdout"]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _worker_call_json(call: dict[str, object]) -> str:
    """Preserve worker insertion order, which its presentation digests attest."""

    return json.dumps(call, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _complete_id_coverage(actual: tuple[str, ...], expected: tuple[str, ...]) -> bool:
    """Coverage is identity-complete even when the model ranks IDs differently."""

    return len(actual) == len(expected) == len(set(actual)) and set(actual) == set(expected)


@dataclass(frozen=True)
class FixtureOutcome:
    status: OutcomeStatus
    oracle_receipt_sha256: str | None = None
    checked_by: str | None = None

    @property
    def utility(self) -> str:
        return "unknown" if self.status == "unrun" else self.status


@dataclass(frozen=True)
class PilotFixtureCase:
    snapshot_id: str
    split: PilotSplit
    machine_group: str
    software_group: str
    fault_family: str
    privacy_review_id: str
    privacy_review_payload_sha256: str
    consent_id: str
    selected_outcome: FixtureOutcome


@dataclass(frozen=True)
class PilotItemOutcome:
    item_id: str
    status: OutcomeStatus
    utility: str
    oracle_receipt_sha256: str | None
    checked_by: str | None


@dataclass(frozen=True)
class FrontierPilotExample:
    snapshot_id: str
    case_id: str
    epoch_state_version: int
    split: PilotSplit
    machine_group: str
    software_group: str
    fault_family: str
    selected_item_id: str
    request_json: str
    request_sha256: str
    response_json: str
    response_sha256: str
    receipt_json: str
    receipt_sha256: str
    source_row_sha256: tuple[str, ...]
    payload_sha256: str
    privacy_review_id: str
    consent_id: str
    item_outcomes: tuple[PilotItemOutcome, ...]

    @property
    def selected_outcome(self) -> PilotItemOutcome:
        return next(item for item in self.item_outcomes if item.item_id == self.selected_item_id)


@dataclass(frozen=True)
class FrontierFixturePilot:
    schema_version: Literal[1]
    source_authenticity: Literal["controlled_fixture_only"]
    training_admissible: Literal[False]
    model_preference_labels: Literal[False]
    worker_token_parity: Literal["not_verified"]
    examples: tuple[FrontierPilotExample, ...]
    export_sha256: str

    def to_json(self) -> str:
        return _canonical(asdict(self))


@dataclass(frozen=True)
class FrontierWorkerBatchReceipt:
    phase: Literal["evidence", "probe", "compare"]
    batch_index: int
    candidate_ids: tuple[str, ...]
    presentation_sha256: str
    exact_worker_call_json: str
    exact_worker_call_sha256: str


@dataclass(frozen=True)
class FrontierWorkerReceipt:
    """Local-only raw tensor custody, not a training or privacy admission token."""

    schema_version: Literal[1]
    snapshot_id: str
    request_sha256: str
    response_sha256: str
    packet_receipt_sha256: str
    attention_sha256: str
    reviewed_payload_sha256: str
    privacy_review_id: str
    consent_id: str
    artifact_pins: tuple[tuple[str, str], ...]
    batches: tuple[FrontierWorkerBatchReceipt, ...]
    training_admissible: Literal[False] = False

    def to_json(self) -> str:
        return _canonical(asdict(self))


@dataclass(frozen=True)
class ControlledWorkerFixtureCase:
    """Caller-declared fixture receipts; callbacks must check their provenance."""

    fixture: PilotFixtureCase
    source_artifact_sha256: str
    worker_privacy_review_id: str
    worker_privacy_review_payload_sha256: str
    artifact_pins: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class ControlledWorkerPilotExample:
    fixture: FrontierPilotExample
    source_artifact_sha256: str
    draft_sha256: str
    worker_receipt: FrontierWorkerReceipt
    worker_receipt_sha256: str


@dataclass(frozen=True)
class ControlledWorkerFixturePilot:
    """Local assembly only; review callbacks do not authenticate their issuer."""

    schema_version: Literal[1]
    source_authenticity: Literal["caller_checked_fixture_claim"]
    training_admissible: Literal[False]
    diagnostic_performance_admissible: Literal[False]
    worker_token_parity: Literal["not_verified"]
    examples: tuple[ControlledWorkerPilotExample, ...]
    pilot_sha256: str


def _payloads(
    store: SQLiteStore, snapshot_id: str
) -> tuple[FrontierCandidateSnapshot, FrontierPacketReceiptV1, str, str, str]:
    """Return persisted bytes only after repository custody checks pass."""
    with store.read_snapshot():
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_id)
        receipt = FrontierPacketReceiptRepository(store).bound_receipt(snapshot_id)
        if receipt is None:
            raise ValueError("frontier pilot requires a bound source receipt")
        row = store.connection.execute(
            "SELECT request_json,response_json FROM candidate_decision_snapshots "
            "WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        receipt_row = store.connection.execute(
            "SELECT receipt_json FROM frontier_packet_receipts WHERE receipt_id=?",
            (receipt.receipt_id,),
        ).fetchone()
        if row is None or receipt_row is None:
            raise ValueError("frontier pilot source payload disappeared")
        return snapshot, receipt, str(row[0]), str(row[1]), str(receipt_row[0])


def snapshot_payload_sha256(store: SQLiteStore, snapshot_id: str) -> str:
    """Privacy-review digest over exact stored request, response and receipt JSON."""
    _, _, request_json, response_json, receipt_json = _payloads(store, snapshot_id)
    return _sha(_canonical((request_json, response_json, receipt_json)))


def frontier_worker_payload_sha256(
    store: SQLiteStore,
    snapshot_id: str,
    attention: LayaAttentionResult,
    captured_calls: dict[tuple[str, int], dict[str, object]],
) -> str:
    """Digest exact source rows and worker bytes for an external privacy review."""

    _, _, request_json, response_json, receipt_json = _payloads(store, snapshot_id)
    ordered_calls = tuple(
        (
            batch.phase,
            batch.batch_index,
            None
            if (call := captured_calls.get((batch.phase, batch.batch_index))) is None
            else _worker_call_json(call),
        )
        for batch in attention.microbatches
    )
    return _sha(
        _canonical(
            (
                request_json,
                response_json,
                receipt_json,
                attention.model_dump(mode="json"),
                ordered_calls,
            )
        )
    )


def assemble_frontier_worker_receipt(
    store: SQLiteStore,
    snapshot_id: str,
    *,
    attention: LayaAttentionResult,
    captured_calls: dict[tuple[str, int], dict[str, object]],
    artifact_pins: dict[str, str],
    privacy_review_id: str,
    privacy_review_payload_sha256: str,
    consent_id: str,
    verify_privacy_review: Callable[[str, str], bool] | None,
) -> FrontierWorkerReceipt:
    """Bind opt-in worker tensors to a readback frontier decision and source packet.

    This object can be durably serialized by the local owner. Caller-supplied
    consent, reviewer, and artifact claims remain independently unverified here.
    """

    snapshot, _receipt, request_json, response_json, receipt_json = _payloads(store, snapshot_id)
    if (
        snapshot.response.ranking_source != "laya"
        or snapshot.response.cache_hit
        or not snapshot.response.coverage_complete
        or snapshot.response.presentation_trace != attention
        or attention.ranked_probe_ids != snapshot.response.ranked_item_ids
    ):
        raise ValueError("frontier worker receipt requires the persisted uncached Laya trace")
    offered = tuple(item.item_id for item in snapshot.request.items)
    fragments = tuple(packet.fragment_id for packet in snapshot.request.evidence_packets)
    if (
        not _complete_id_coverage(attention.considered_probe_ids, offered)
        or not 1 <= len(attention.microbatches) <= 32
        or len(captured_calls) != len(attention.microbatches)
    ):
        raise ValueError("frontier worker capture coverage is incomplete")
    batches: list[FrontierWorkerBatchReceipt] = []
    actual_ids: dict[str, list[str]] = {"evidence": [], "probe": []}
    next_index = {"evidence": 0, "probe": 0, "compare": 0}
    phase_order = {"evidence": 0, "probe": 1, "compare": 2}
    last_phase = 0
    for batch in attention.microbatches:
        phase, index = batch.phase, batch.batch_index
        if index != next_index[phase] or phase_order[phase] < last_phase:
            raise ValueError("frontier worker batch order invalid")
        next_index[phase] += 1
        last_phase = phase_order[phase]
        if phase == "compare" and (
            len(batch.candidate_ids) < 2
            or not set(batch.candidate_ids).issubset(actual_ids["probe"])
        ):
            raise ValueError("frontier worker comparison contains an unoffered candidate")
        proof = batch.worker_presentation
        key = (phase, index)
        call = captured_calls.get(key)
        if (
            batch.cache_hit_ids
            or batch.cached_origins
            or batch.inference_ids != batch.candidate_ids
            or proof is None
            or call is None
            or call.get("schema_version") != 2
        ):
            raise ValueError("frontier worker capture needs exact uncached model input")
        _verify_exact_worker_capture(call, proof)
        questions_raw = call["questions"]
        assert isinstance(questions_raw, list)
        questions = cast(list[object], questions_raw)
        presented_ids: list[str] = []
        for row_raw in questions:
            assert isinstance(row_raw, dict)
            row = cast(dict[str, object], row_raw)
            item_id = row["item_id"]
            assert isinstance(item_id, str)
            if item_id not in presented_ids:
                presented_ids.append(item_id)
        presented = tuple(presented_ids)
        if presented != batch.candidate_ids:
            raise ValueError("frontier worker questions differ from batch identity")
        if phase != "compare":
            actual_ids[phase].extend(batch.candidate_ids)
        call_json = _worker_call_json(call)
        batches.append(
            FrontierWorkerBatchReceipt(
                phase=phase,
                batch_index=index,
                candidate_ids=batch.candidate_ids,
                presentation_sha256=proof.presentation_sha256,
                exact_worker_call_json=call_json,
                exact_worker_call_sha256=_sha(call_json),
            )
        )
    if not _complete_id_coverage(tuple(actual_ids["evidence"]), fragments) or not (
        _complete_id_coverage(tuple(actual_ids["probe"]), offered)
    ):
        raise ValueError("frontier worker capture does not cover the offered frontier")
    if set(captured_calls) != {
        (batch.phase, batch.batch_index) for batch in attention.microbatches
    }:
        raise ValueError("frontier worker capture contains unmatched callbacks")
    required_artifacts = {
        "model_weight_sha256",
        "package_wheel_sha256",
        "tokenizer_sha256",
        "model_config_sha256",
        "upstream_common_sha256",
        "upstream_agent_sha256",
        "worker_sha256",
    }
    if (
        set(artifact_pins) != required_artifacts
        or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in artifact_pins.values())
        or artifact_pins["model_weight_sha256"] != snapshot.request.model_weight_sha256
    ):
        raise ValueError("frontier worker artifact pins are missing or inconsistent")
    reviewed = frontier_worker_payload_sha256(store, snapshot_id, attention, captured_calls)
    if (
        not privacy_review_id
        or not consent_id
        or privacy_review_payload_sha256 != reviewed
        or verify_privacy_review is None
        or not verify_privacy_review(privacy_review_id, reviewed)
    ):
        raise ValueError("frontier worker exact payload lacks matching privacy review")
    attention_json = _canonical(attention.model_dump(mode="json"))
    result = FrontierWorkerReceipt(
        schema_version=1,
        snapshot_id=snapshot_id,
        request_sha256=_sha(request_json),
        response_sha256=_sha(response_json),
        packet_receipt_sha256=_sha(receipt_json),
        attention_sha256=_sha(attention_json),
        reviewed_payload_sha256=reviewed,
        privacy_review_id=privacy_review_id,
        consent_id=consent_id,
        artifact_pins=tuple(sorted(artifact_pins.items())),
        batches=tuple(batches),
    )
    if len(result.to_json().encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("frontier worker receipt exceeds its local size bound")
    return result


def export_frontier_fixture_pilot(
    store: SQLiteStore,
    cases: Sequence[PilotFixtureCase],
    *,
    verify_fixture_oracle: Callable[[PilotFixtureCase, FrontierCandidateSnapshot], bool]
    | None = None,
    verify_privacy_review: Callable[[PilotFixtureCase], bool] | None = None,
) -> FrontierFixturePilot:
    """Export two to four reviewed fixture snapshots, never model-derived labels.

    The oracle callback belongs to the controlled fixture harness, not to the
    ranker. A useful/failed/etc. label is rejected unless that external checker
    validates its receipt for the selected snapshot and action. This API does
    not establish real-world authenticity.
    """
    if not 2 <= len(cases) <= 4:
        raise ValueError("frontier pilot requires two to four examples")
    if len({case.snapshot_id for case in cases}) != len(cases):
        raise ValueError("frontier pilot repeats a snapshot")
    examples: list[FrontierPilotExample] = []
    split_groups: dict[tuple[str, str], PilotSplit] = {}
    for case in cases:
        if case.split not in {"pilot_train", "pilot_holdout"}:
            raise ValueError("frontier pilot split is invalid")
        if case.selected_outcome.status not in {
            "useful",
            "uninformative",
            "contradictory",
            "failed",
            "unrun",
        }:
            raise ValueError("frontier pilot outcome status is invalid")
        if not all(
            (
                case.machine_group,
                case.software_group,
                case.fault_family,
                case.privacy_review_id,
                case.consent_id,
            )
        ):
            raise ValueError("frontier pilot lacks fixture provenance, consent or privacy review")
        snapshot, receipt, request_json, response_json, receipt_json = _payloads(
            store, case.snapshot_id
        )
        payload_sha = _sha(_canonical((request_json, response_json, receipt_json)))
        if case.privacy_review_payload_sha256 != payload_sha:
            raise ValueError("frontier pilot privacy review does not bind exact payload")
        if verify_privacy_review is None or not verify_privacy_review(case):
            raise ValueError("frontier pilot privacy review was not independently checked")
        outcome = case.selected_outcome
        if outcome.status == "unrun":
            if outcome.oracle_receipt_sha256 is not None or outcome.checked_by is not None:
                raise ValueError("unrun outcome cannot claim an oracle result")
        elif (
            outcome.oracle_receipt_sha256 is None
            or re.fullmatch(r"[0-9a-f]{64}", outcome.oracle_receipt_sha256) is None
            or outcome.checked_by is None
            or verify_fixture_oracle is None
            or not verify_fixture_oracle(case, snapshot)
        ):
            raise ValueError("frontier pilot outcome lacks an independently checked oracle")
        for group_type, group_value in (
            ("case", str(snapshot.case_id)),
            ("machine", case.machine_group),
            ("software", case.software_group),
            ("fault", case.fault_family),
        ):
            key = (group_type, group_value)
            if key in split_groups and split_groups[key] != case.split:
                raise ValueError("frontier pilot split leaks a case or fixture group")
            split_groups[key] = case.split
        outcomes = tuple(
            PilotItemOutcome(
                item_id=item.item_id,
                status=outcome.status if item.item_id == snapshot.selected_item_id else "unrun",
                utility=outcome.utility if item.item_id == snapshot.selected_item_id else "unknown",
                oracle_receipt_sha256=(
                    outcome.oracle_receipt_sha256
                    if item.item_id == snapshot.selected_item_id
                    else None
                ),
                checked_by=outcome.checked_by
                if item.item_id == snapshot.selected_item_id
                else None,
            )
            for item in snapshot.request.items
        )
        examples.append(
            FrontierPilotExample(
                snapshot_id=case.snapshot_id,
                case_id=str(snapshot.case_id),
                epoch_state_version=snapshot.epoch_state_version,
                split=case.split,
                machine_group=case.machine_group,
                software_group=case.software_group,
                fault_family=case.fault_family,
                selected_item_id=snapshot.selected_item_id,
                request_json=request_json,
                request_sha256=_sha(request_json),
                response_json=response_json,
                response_sha256=_sha(response_json),
                receipt_json=receipt_json,
                receipt_sha256=_sha(receipt_json),
                source_row_sha256=tuple(source.row_sha256 for source in receipt.sources),
                payload_sha256=payload_sha,
                privacy_review_id=case.privacy_review_id,
                consent_id=case.consent_id,
                item_outcomes=outcomes,
            )
        )
    export_sha = _sha(_canonical([asdict(example) for example in examples]))
    return FrontierFixturePilot(
        schema_version=1,
        source_authenticity="controlled_fixture_only",
        training_admissible=False,
        model_preference_labels=False,
        worker_token_parity="not_verified",
        examples=tuple(examples),
        export_sha256=export_sha,
    )


def build_controlled_frontier_worker_pilot(
    store: SQLiteStore,
    cases: Sequence[ControlledWorkerFixtureCase],
    *,
    verify_fixture_source: Callable[[ControlledWorkerFixtureCase, FrontierCandidateSnapshot], bool],
    verify_fixture_outcome: Callable[
        [ControlledWorkerFixtureCase, FrontierCandidateSnapshot], bool
    ],
    verify_packet_privacy_review: Callable[[PilotFixtureCase], bool],
    verify_worker_privacy_review: Callable[[str, str], bool],
    verify_consent: Callable[[ControlledWorkerFixtureCase, str], bool],
) -> ControlledWorkerFixturePilot:
    """Bind checked fixture labels to immutable, local schema-35 worker drafts.

    Callbacks represent independent fixture/review/consent authorities supplied
    by the harness. Their identities and decisions are not authenticated here;
    this remains a non-admissible fixture pilot and never reads an unreviewed
    private capture into an external export destination.
    """

    if not 2 <= len(cases) <= 4:
        raise ValueError("controlled worker pilot requires two to four fixture cases")
    repo = CandidateDecisionSnapshotRepository(store)
    with store.read_snapshot():
        bound = tuple(
            (
                case,
                repo.readback_frontier(case.fixture.snapshot_id),
                repo.readback_frontier_worker_draft(case.fixture.snapshot_id),
            )
            for case in cases
        )
        worker_receipts: list[FrontierWorkerReceipt] = []
        draft_digests: list[str] = []
        for case, snapshot, draft in bound:
            if (
                re.fullmatch(r"[0-9a-f]{64}", case.source_artifact_sha256) is None
                or not case.worker_privacy_review_id
                or re.fullmatch(r"[0-9a-f]{64}", case.worker_privacy_review_payload_sha256) is None
                or len(dict(case.artifact_pins)) != len(case.artifact_pins)
            ):
                raise ValueError("controlled worker fixture receipts are invalid")
            if not verify_fixture_source(case, snapshot):
                raise ValueError("controlled worker fixture source was not independently checked")
            if case.fixture.selected_outcome.status != "unrun" and not verify_fixture_outcome(
                case, snapshot
            ):
                raise ValueError("controlled worker fixture outcome was not independently checked")
            attention = snapshot.response.presentation_trace
            if attention is None:
                raise ValueError("controlled worker pilot lacks the persisted Laya presentation")
            calls = draft.captured_calls
            reviewed = frontier_worker_payload_sha256(store, snapshot.snapshot_id, attention, calls)
            if not verify_consent(case, reviewed):
                raise ValueError("controlled worker pilot lacks exact-payload consent")
            worker_receipts.append(
                assemble_frontier_worker_receipt(
                    store,
                    snapshot.snapshot_id,
                    attention=attention,
                    captured_calls=calls,
                    artifact_pins=dict(case.artifact_pins),
                    privacy_review_id=case.worker_privacy_review_id,
                    privacy_review_payload_sha256=case.worker_privacy_review_payload_sha256,
                    consent_id=case.fixture.consent_id,
                    verify_privacy_review=verify_worker_privacy_review,
                )
            )
            draft_digests.append(draft.capture_sha256)
        fixture_pilot = export_frontier_fixture_pilot(
            store,
            tuple(case.fixture for case in cases),
            verify_fixture_oracle=lambda fixture, snapshot: any(
                fixture is case.fixture and snapshot.snapshot_id == checked_snapshot.snapshot_id
                for case, checked_snapshot, _draft in bound
                if fixture.selected_outcome.status != "unrun"
            ),
            verify_privacy_review=verify_packet_privacy_review,
        )
        examples = tuple(
            ControlledWorkerPilotExample(
                fixture=fixture_example,
                source_artifact_sha256=case.source_artifact_sha256,
                draft_sha256=draft_sha,
                worker_receipt=worker_receipt,
                worker_receipt_sha256=_sha(worker_receipt.to_json()),
            )
            for (case, _snapshot, _draft), fixture_example, draft_sha, worker_receipt in zip(
                bound, fixture_pilot.examples, draft_digests, worker_receipts, strict=True
            )
        )
        pilot_sha = _sha(
            _canonical(
                (
                    fixture_pilot.export_sha256,
                    tuple(
                        (
                            item.fixture.snapshot_id,
                            item.source_artifact_sha256,
                            item.draft_sha256,
                            item.worker_receipt_sha256,
                        )
                        for item in examples
                    ),
                )
            )
        )
        return ControlledWorkerFixturePilot(
            schema_version=1,
            source_authenticity="caller_checked_fixture_claim",
            training_admissible=False,
            diagnostic_performance_admissible=False,
            worker_token_parity="not_verified",
            examples=examples,
            pilot_sha256=pilot_sha,
        )
