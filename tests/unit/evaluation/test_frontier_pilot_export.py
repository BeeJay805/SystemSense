"""A fixture pilot exports custody, not inferred preference labels."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from systemsense.application.frontier_policy import assemble_frontier_request
from systemsense.decision.frontier_ranker import FrontierRankRequestV1
from systemsense.domain.ids import EvidenceId
from systemsense.domain.time import utc_now
from systemsense.evaluation import frontier_pilot_export as pilot_export
from systemsense.evaluation.frontier_pilot_export import (
    FixtureOutcome,
    OutcomeStatus,
    PilotFixtureCase,
    assemble_frontier_worker_receipt,
    export_frontier_fixture_pilot,
    frontier_worker_payload_sha256,
    snapshot_payload_sha256,
)
from systemsense.inference import laya_worker
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaWorkerPresentation,
    _verify_exact_worker_capture,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.search_frontier import FrontierReferenceV1
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_frontier_policy import (
    CASE,
    EPOCH,
    MODEL_SHA,
    PROVIDER,
    _candidate_fixture,  # pyright: ignore[reportPrivateUsage]
    _issued_candidates,  # pyright: ignore[reportPrivateUsage]
    _ranker,  # pyright: ignore[reportPrivateUsage]
    _versions,  # pyright: ignore[reportPrivateUsage]
)


def _snapshots(store: SQLiteStore, *, laya: bool = False) -> tuple[str, str]:
    registry, retriever, frontier = _candidate_fixture(store)
    row = store.connection.execute(
        "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(CASE),)
    ).fetchone()
    assert row is not None
    state = json.loads(str(row[0]))
    now = utc_now()
    state.update(
        objective="Game stutters",
        created_at=(now - timedelta(seconds=10)).isoformat(),
        updated_at=now.isoformat(),
        incident_start=(now - timedelta(minutes=1)).isoformat(),
        incident_end=now.isoformat(),
    )
    store.connection.execute(
        "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
        (json.dumps(state), str(CASE)),
    )
    versions = _versions(retriever)
    ids: list[str] = []
    for candidate in _issued_candidates(registry)[:2]:
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )
        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=CASE,
            epoch_state_version=EPOCH,
            evidence_ids=(EvidenceId(root="ev_" + "9" * 32),),
            expected_generation=versions.evidence or 0,
        )
        frozen_at = utc_now()
        request = assemble_frontier_request(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=frozen_at + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            evidence_packets=receipt.packets,
        )
        ranking = _ranker().rank(request)
        if laya:
            attention, _calls = _fixture_worker_capture(request)
            ranking = ranking.model_copy(
                update={
                    "ranking_source": "laya",
                    "model_abstained": False,
                    "coverage_complete": True,
                    "degraded_reason": None,
                    "considered_item_ids": (item.item_id,),
                    "attention_notes": attention.attention_notes,
                    "presentation_trace": attention,
                }
            )
        snapshot = CandidateDecisionSnapshotRepository(store).capture_frontier(
            request,
            ranking,
            registry=registry,
            retriever=retriever,
            frontier=frontier,
            catalog_entries=(),
            candidate_refs=(candidate,),
            selected_item_id=item.item_id,
            epoch_state_version=EPOCH,
            request_frozen_at=frozen_at,
            packet_receipt_id=receipt.receipt_id,
        )
        ids.append(snapshot.snapshot_id)
    return ids[0], ids[1]


def _fixture_worker_capture(
    request: FrontierRankRequestV1,
) -> tuple[LayaAttentionResult, dict[tuple[str, int], dict[str, object]]]:
    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1

        def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            return {"input_ids": [len(part) for part in text.split()]}

    class WorkerAgent:
        tok = Tokenizer()

        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 64, "head_max_len": 32}

    state: dict[str, object] = {"symptom": "synthetic game stutter"}
    question: dict[str, object] = {
        "type": "noul",
        "instructions": "Check synthetic graphics",
        "criteria": {"false": "not useful", "true": "useful"},
    }
    coverage = {
        "state_tokens_original": 3,
        "state_fields_omitted": 0,
        "state_list_items_omitted": 0,
    }

    def worker_call(
        candidate_ids: tuple[str, ...],
    ) -> tuple[LayaWorkerPresentation, dict[str, object]]:
        question_ids = tuple(f"item_{index}_piece_0" for index in range(len(candidate_ids)))
        proof_raw = laya_worker._presentation(  # pyright: ignore[reportPrivateUsage]
            cast(Any, WorkerAgent()),
            state,
            {name: question for name in question_ids},
            dict(zip(question_ids, candidate_ids, strict=True)),
            coverage,
        )
        proof = LayaWorkerPresentation.model_validate(proof_raw)
        call: dict[str, object] = {
            "schema_version": 2,
            "state": state,
            "questions": [
                {"question_id": name, "item_id": candidate_id, "question": question}
                for name, candidate_id in zip(question_ids, candidate_ids, strict=True)
            ],
            "state_coverage": coverage,
            "model_input": {
                "input_ids": [[101, 1, 102] for _ in candidate_ids],
                "attention_mask": [[1, 1, 1] for _ in candidate_ids],
                "marker_pos": [[1, 2] for _ in candidate_ids],
                "marker_mask": [[True, True] for _ in candidate_ids],
                "qtype": [2 for _ in candidate_ids],
            },
        }
        model_input = call["model_input"]
        proof = proof.model_copy(
            update={
                "model_input_sha256": hashlib.sha256(
                    b"systemsense.laya.model_input.v1\0"
                    + json.dumps(
                        model_input,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
            }
        )
        return proof, call

    fragments = tuple(packet.fragment_id for packet in request.evidence_packets)
    items = tuple(item.item_id for item in request.items)
    batches: list[LayaAttentionMicrobatch] = []
    calls: dict[tuple[str, int], dict[str, object]] = {}
    for phase, ids in (("evidence", fragments), ("probe", items)):
        for index, candidate_id in enumerate(ids):
            proof, call = worker_call((candidate_id,))
            batches.append(
                LayaAttentionMicrobatch(
                    phase=phase,  # type: ignore[arg-type]
                    batch_index=index,
                    candidate_ids=(candidate_id,),
                    inference_ids=(candidate_id,),
                    worker_presentation=proof,
                )
            )
            calls[(phase, index)] = call
    if len(items) > 1:
        proof, call = worker_call(items)
        batches.append(
            LayaAttentionMicrobatch(
                phase="compare",
                batch_index=0,
                candidate_ids=items,
                inference_ids=items,
                worker_presentation=proof,
            )
        )
        calls[("compare", 0)] = call
    pages = tuple(dict.fromkeys(packet.page_id for packet in request.evidence_packets))
    evidence = tuple(dict.fromkeys(packet.evidence_id for packet in request.evidence_packets))
    return (
        LayaAttentionResult(
            ranked_probe_ids=items,
            considered_probe_ids=items,
            ranked_evidence_ids=evidence,
            considered_evidence_ids=evidence,
            ranked_attention_page_ids=pages,
            considered_attention_page_ids=pages,
            attention_notes=(
                "coverage_limited=false",
                "state_truncated_batches=0",
                "instruction_truncated_items=0",
            ),
            microbatches=tuple(batches),
        ),
        calls,
    )


def _case(
    snapshot_id: str, payload_sha: str, *, outcome: OutcomeStatus = "unrun"
) -> PilotFixtureCase:
    oracle = hashlib.sha256(b"independent fixture oracle").hexdigest()
    return PilotFixtureCase(
        snapshot_id=snapshot_id,
        split="pilot_holdout",
        machine_group="fixture-machine-1",
        software_group="fixture-build-1",
        fault_family="fixture-pressure",
        privacy_review_id="fixture-review-1",
        privacy_review_payload_sha256=payload_sha,
        consent_id="fixture-consent-1",
        selected_outcome=FixtureOutcome(
            status=outcome,
            oracle_receipt_sha256=oracle if outcome != "unrun" else None,
            checked_by="fixture-oracle" if outcome != "unrun" else None,
        ),
    )


def test_exact_persisted_packets_and_unrun_unknown(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot.db") as store:
        snapshot_id, second_id = _snapshots(store)
        payload_sha = snapshot_payload_sha256(store, snapshot_id)
        corpus = export_frontier_fixture_pilot(
            store,
            (
                _case(snapshot_id, payload_sha),
                _case(second_id, snapshot_payload_sha256(store, second_id)),
            ),
            verify_privacy_review=lambda case: case.privacy_review_id == "fixture-review-1",
        )
        assert (
            corpus.examples[0].request_json
            == store.connection.execute(
                "SELECT request_json FROM candidate_decision_snapshots WHERE snapshot_id=?",
                (snapshot_id,),
            ).fetchone()[0]
        )
        assert corpus.examples[0].receipt_json is not None
        assert corpus.examples[0].selected_outcome.status == "unrun"
        assert corpus.examples[0].selected_outcome.utility == "unknown"
        assert corpus.training_admissible is False
        assert corpus.model_preference_labels is False
        assert corpus.worker_token_parity == "not_verified"


def test_pilot_rejects_unreviewed_oracle_and_privacy_mismatch(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot-negative.db") as store:
        snapshot_id, second_id = _snapshots(store)
        payload_sha = snapshot_payload_sha256(store, snapshot_id)
        case = _case(snapshot_id, payload_sha, outcome="useful")
        with pytest.raises(ValueError, match="oracle"):
            export_frontier_fixture_pilot(
                store,
                (case, _case(second_id, snapshot_payload_sha256(store, second_id))),
                verify_privacy_review=lambda case: True,
            )
        changed = _case(snapshot_id, "0" * 64)
        with pytest.raises(ValueError, match="privacy"):
            export_frontier_fixture_pilot(
                store,
                (changed, _case(second_id, snapshot_payload_sha256(store, second_id))),
                verify_privacy_review=lambda case: True,
            )


def test_checked_fixture_outcome_and_case_split_fence(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pilot-checked.db") as store:
        first_id, second_id = _snapshots(store)
        first = _case(first_id, snapshot_payload_sha256(store, first_id), outcome="useful")
        second = _case(second_id, snapshot_payload_sha256(store, second_id))
        expected_oracle = hashlib.sha256(b"independent fixture oracle").hexdigest()
        corpus = export_frontier_fixture_pilot(
            store,
            (first, second),
            verify_fixture_oracle=lambda outcome: (
                outcome.oracle_receipt_sha256 == expected_oracle
                and outcome.checked_by == "fixture-oracle"
            ),
            verify_privacy_review=lambda case: case.privacy_review_id == "fixture-review-1",
        )
        assert corpus.examples[0].selected_outcome.utility == "useful"
        assert corpus.examples[1].selected_outcome.utility == "unknown"
        assert (
            corpus.export_sha256
            == hashlib.sha256(
                json.dumps(
                    [asdict(example) for example in corpus.examples],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode()
            ).hexdigest()
        )
        with pytest.raises(ValueError, match="split leaks"):
            export_frontier_fixture_pilot(
                store,
                (first, replace(second, split="pilot_train")),
                verify_fixture_oracle=lambda outcome: True,
                verify_privacy_review=lambda case: True,
            )


def test_frontier_worker_receipt_binds_actual_tensors_to_snapshot_and_review(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "worker-receipt.db") as store:
        snapshot_id, _second = _snapshots(store, laya=True)
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_id)
        attention, calls = _fixture_worker_capture(snapshot.request)
        call = calls[("probe", 0)]
        artifacts = {
            "model_weight_sha256": snapshot.request.model_weight_sha256,
            "package_wheel_sha256": "a" * 64,
            "tokenizer_sha256": "b" * 64,
            "model_config_sha256": "c" * 64,
            "upstream_common_sha256": "d" * 64,
            "upstream_agent_sha256": "e" * 64,
            "worker_sha256": "f" * 64,
        }
        reviewed = frontier_worker_payload_sha256(store, snapshot_id, attention, calls)
        reordered_call = {key: call[key] for key in reversed(tuple(call))}
        reordered_calls = {**calls, ("probe", 0): reordered_call}
        assert (
            frontier_worker_payload_sha256(store, snapshot_id, attention, reordered_calls)
            != reviewed
        )
        receipt = assemble_frontier_worker_receipt(
            store,
            snapshot_id,
            attention=attention,
            captured_calls=calls,
            artifact_pins=artifacts,
            privacy_review_id="synthetic-reviewed",
            privacy_review_payload_sha256=reviewed,
            consent_id="synthetic-consent",
            verify_privacy_review=lambda review_id, digest: (
                review_id == "synthetic-reviewed" and digest == reviewed
            ),
        )
        assert receipt.training_admissible is False
        assert receipt.snapshot_id == snapshot_id
        assert json.loads(receipt.batches[0].exact_worker_call_json)["model_input"]["input_ids"]
        proof = attention.microbatches[0].worker_presentation
        assert proof is not None
        _verify_exact_worker_capture(json.loads(receipt.batches[0].exact_worker_call_json), proof)
        bad_calls = {**calls, ("probe", 0): {**call, "model_input": None}}
        with pytest.raises(ValueError, match="model input"):
            assemble_frontier_worker_receipt(
                store,
                snapshot_id,
                attention=attention,
                captured_calls=bad_calls,
                artifact_pins=artifacts,
                privacy_review_id="synthetic-reviewed",
                privacy_review_payload_sha256=reviewed,
                consent_id="synthetic-consent",
                verify_privacy_review=lambda _review_id, _digest: True,
            )
        with pytest.raises(ValueError, match="privacy review"):
            assemble_frontier_worker_receipt(
                store,
                snapshot_id,
                attention=attention,
                captured_calls=calls,
                artifact_pins=artifacts,
                privacy_review_id="synthetic-reviewed",
                privacy_review_payload_sha256="0" * 64,
                consent_id="synthetic-consent",
                verify_privacy_review=lambda _review_id, _digest: True,
            )
        with pytest.raises(ValueError, match="artifact pins"):
            assemble_frontier_worker_receipt(
                store,
                snapshot_id,
                attention=attention,
                captured_calls=calls,
                artifact_pins={**artifacts, "model_weight_sha256": "0" * 64},
                privacy_review_id="synthetic-reviewed",
                privacy_review_payload_sha256=reviewed,
                consent_id="synthetic-consent",
                verify_privacy_review=lambda _review_id, _digest: True,
            )
        substituted = attention.model_copy(update={"attention_notes": ("substituted",)})
        with pytest.raises(ValueError, match="persisted uncached Laya trace"):
            assemble_frontier_worker_receipt(
                store,
                snapshot_id,
                attention=substituted,
                captured_calls=calls,
                artifact_pins=artifacts,
                privacy_review_id="synthetic-reviewed",
                privacy_review_payload_sha256=reviewed,
                consent_id="synthetic-consent",
                verify_privacy_review=lambda _review_id, _digest: True,
            )


def test_worker_receipt_accepts_score_ranked_multi_choice_coverage(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "score-ranked-worker.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        row = store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(CASE),)
        ).fetchone()
        assert row is not None
        state = json.loads(str(row[0]))
        now = utc_now()
        state.update(
            objective="Game stutters",
            created_at=(now - timedelta(seconds=10)).isoformat(),
            updated_at=now.isoformat(),
            incident_start=(now - timedelta(minutes=1)).isoformat(),
            incident_end=now.isoformat(),
        )
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
            (json.dumps(state), str(CASE)),
        )
        candidates = _issued_candidates(registry)
        versions = _versions(retriever)
        items = tuple(
            frontier.upsert_item(
                CASE,
                FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
                versions,
                cost_ms=candidate.cost_ms,
            )
            for candidate in candidates
        )
        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=CASE,
            epoch_state_version=EPOCH,
            evidence_ids=(EvidenceId(root="ev_" + "9" * 32),),
            expected_generation=versions.evidence or 0,
        )
        frozen_at = utc_now()
        request = assemble_frontier_request(
            case_id=CASE,
            items=items,
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=frozen_at + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=candidates,
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            evidence_packets=receipt.packets,
        )
        attention, calls = _fixture_worker_capture(request)
        ranked = tuple(reversed(tuple(item.item_id for item in request.items)))
        attention = attention.model_copy(
            update={"ranked_probe_ids": ranked, "considered_probe_ids": ranked}
        )
        baseline = _ranker().rank(request)
        ranking = baseline.model_copy(
            update={
                "ranking_source": "laya",
                "ranked_item_ids": ranked,
                "considered_item_ids": tuple(item.item_id for item in request.items),
                "model_abstained": False,
                "coverage_complete": True,
                "degraded_reason": None,
                "attention_notes": attention.attention_notes,
                "presentation_trace": attention,
            }
        )
        snapshot = CandidateDecisionSnapshotRepository(store).capture_frontier(
            request,
            ranking,
            registry=registry,
            retriever=retriever,
            frontier=frontier,
            catalog_entries=(),
            candidate_refs=candidates,
            selected_item_id=ranked[0],
            epoch_state_version=EPOCH,
            request_frozen_at=frozen_at,
            packet_receipt_id=receipt.receipt_id,
        )
        artifacts = {
            "model_weight_sha256": snapshot.request.model_weight_sha256,
            "package_wheel_sha256": "a" * 64,
            "tokenizer_sha256": "b" * 64,
            "model_config_sha256": "c" * 64,
            "upstream_common_sha256": "d" * 64,
            "upstream_agent_sha256": "e" * 64,
            "worker_sha256": "f" * 64,
        }
        reviewed = frontier_worker_payload_sha256(store, snapshot.snapshot_id, attention, calls)
        bound = assemble_frontier_worker_receipt(
            store,
            snapshot.snapshot_id,
            attention=attention,
            captured_calls=calls,
            artifact_pins=artifacts,
            privacy_review_id="synthetic-reviewed",
            privacy_review_payload_sha256=reviewed,
            consent_id="synthetic-consent",
            verify_privacy_review=lambda _id, digest: digest == reviewed,
        )
        assert {
            item
            for batch in bound.batches
            for item in batch.candidate_ids
            if batch.phase == "probe"
        } == set(ranked)


def test_controlled_pilot_binds_stored_worker_drafts_to_independent_fixture_checks(
    tmp_path: Path,
) -> None:
    fixture_source = hashlib.sha256(b"authored fault recipe v1").hexdigest()
    with SQLiteStore(tmp_path / "controlled-pilot.db") as store:
        snapshot_ids = _snapshots(store, laya=True)
        repo = CandidateDecisionSnapshotRepository(store)
        known_outcomes: dict[str, tuple[str, str]] = {}
        cases: list[pilot_export.ControlledWorkerFixtureCase] = []
        for index, snapshot_id in enumerate(snapshot_ids):
            snapshot = repo.readback_frontier(snapshot_id)
            attention, calls = _fixture_worker_capture(snapshot.request)
            draft = repo.capture_frontier_worker_draft(snapshot_id, calls)
            status: OutcomeStatus = "uninformative" if index == 0 else "useful"
            oracle_digest = hashlib.sha256(
                f"{fixture_source}:{snapshot_id}:{status}".encode()
            ).hexdigest()
            known_outcomes[snapshot_id] = (status, oracle_digest)
            fixture = replace(
                _case(snapshot_id, snapshot_payload_sha256(store, snapshot_id), outcome=status),
                selected_outcome=FixtureOutcome(
                    status=status,
                    oracle_receipt_sha256=oracle_digest,
                    checked_by="authored-fixture-oracle",
                ),
            )
            pins = {
                "model_weight_sha256": snapshot.request.model_weight_sha256,
                "package_wheel_sha256": "a" * 64,
                "tokenizer_sha256": "b" * 64,
                "model_config_sha256": "c" * 64,
                "upstream_common_sha256": "d" * 64,
                "upstream_agent_sha256": "e" * 64,
                "worker_sha256": "f" * 64,
            }
            cases.append(
                pilot_export.ControlledWorkerFixtureCase(
                    fixture=fixture,
                    source_artifact_sha256=fixture_source,
                    worker_privacy_review_id="fixture-worker-review-1",
                    worker_privacy_review_payload_sha256=frontier_worker_payload_sha256(
                        store, snapshot_id, attention, draft.captured_calls
                    ),
                    artifact_pins=tuple(sorted(pins.items())),
                )
            )
        pilot = pilot_export.build_controlled_frontier_worker_pilot(
            store,
            cases,
            verify_fixture_source=lambda case, _snapshot: (
                case.source_artifact_sha256 == fixture_source
            ),
            verify_fixture_outcome=lambda case, snapshot: (
                (
                    case.fixture.selected_outcome.status,
                    case.fixture.selected_outcome.oracle_receipt_sha256,
                )
                == known_outcomes[snapshot.snapshot_id]
                and case.fixture.selected_outcome.checked_by == "authored-fixture-oracle"
            ),
            verify_packet_privacy_review=lambda case: case.privacy_review_id == "fixture-review-1",
            verify_worker_privacy_review=lambda review_id, _digest: (
                review_id == "fixture-worker-review-1"
            ),
            verify_consent=lambda case, digest: (
                case.fixture.consent_id == "fixture-consent-1"
                and digest == case.worker_privacy_review_payload_sha256
            ),
        )
        assert len(pilot.examples) == 2
        assert [example.fixture.selected_outcome.status for example in pilot.examples] == [
            "uninformative",
            "useful",
        ]
        assert pilot.examples[0].worker_receipt.batches[0].exact_worker_call_json
        assert (
            pilot.examples[0].draft_sha256
            == repo.readback_frontier_worker_draft(snapshot_ids[0]).capture_sha256
        )
        assert pilot.training_admissible is False
        assert pilot.diagnostic_performance_admissible is False
        assert pilot.worker_token_parity == "not_verified"
        assert pilot.source_authenticity == "caller_checked_fixture_claim"


def test_controlled_pilot_rejects_missing_draft_and_unchecked_outcome(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "controlled-pilot-negative.db") as store:
        snapshot_ids = _snapshots(store, laya=True)
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_ids[0])
        attention, calls = _fixture_worker_capture(snapshot.request)
        fixture = _case(
            snapshot_ids[0], snapshot_payload_sha256(store, snapshot_ids[0]), outcome="useful"
        )
        pins = (
            ("model_weight_sha256", snapshot.request.model_weight_sha256),
            ("package_wheel_sha256", "a" * 64),
            ("tokenizer_sha256", "b" * 64),
            ("model_config_sha256", "c" * 64),
            ("upstream_common_sha256", "d" * 64),
            ("upstream_agent_sha256", "e" * 64),
            ("worker_sha256", "f" * 64),
        )
        case = pilot_export.ControlledWorkerFixtureCase(
            fixture=fixture,
            source_artifact_sha256="a" * 64,
            worker_privacy_review_id="fixture-worker-review",
            worker_privacy_review_payload_sha256=frontier_worker_payload_sha256(
                store, snapshot_ids[0], attention, calls
            ),
            artifact_pins=pins,
        )

        def build() -> object:
            return pilot_export.build_controlled_frontier_worker_pilot(
                store,
                (case, replace(case, fixture=replace(fixture, snapshot_id=snapshot_ids[1]))),
                verify_fixture_source=lambda _case, _snapshot: True,
                verify_fixture_outcome=lambda _case, _snapshot: False,
                verify_packet_privacy_review=lambda _case: True,
                verify_worker_privacy_review=lambda _id, _digest: True,
                verify_consent=lambda _case, _digest: True,
            )

        with pytest.raises(ValueError, match="worker draft"):
            build()
        CandidateDecisionSnapshotRepository(store).capture_frontier_worker_draft(
            snapshot_ids[0], calls
        )
        second = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_ids[1])
        _second_attention, second_calls = _fixture_worker_capture(second.request)
        CandidateDecisionSnapshotRepository(store).capture_frontier_worker_draft(
            snapshot_ids[1], second_calls
        )
        with pytest.raises(ValueError, match="fixture outcome"):
            build()

        second_case = replace(
            case,
            fixture=_case(snapshot_ids[1], snapshot_payload_sha256(store, snapshot_ids[1])),
            worker_privacy_review_payload_sha256=frontier_worker_payload_sha256(
                store, snapshot_ids[1], _second_attention, second_calls
            ),
        )

        def checked_build(
            *,
            consent: bool = True,
            worker_review: bool = True,
            packet_review: bool = True,
            split_leak: bool = False,
        ) -> object:
            alternate = second_case
            if split_leak:
                alternate = replace(
                    second_case,
                    fixture=replace(second_case.fixture, split="pilot_train"),
                )
            return pilot_export.build_controlled_frontier_worker_pilot(
                store,
                (case, alternate),
                verify_fixture_source=lambda _case, _snapshot: True,
                verify_fixture_outcome=lambda _case, _snapshot: True,
                verify_packet_privacy_review=lambda _case: packet_review,
                verify_worker_privacy_review=lambda _id, _digest: worker_review,
                verify_consent=lambda _case, _digest: consent,
            )

        with pytest.raises(ValueError, match="consent"):
            checked_build(consent=False)
        with pytest.raises(ValueError, match="privacy review"):
            checked_build(worker_review=False)
        with pytest.raises(ValueError, match="privacy review"):
            checked_build(packet_review=False)
        with pytest.raises(ValueError, match="split leaks"):
            checked_build(split_leak=True)
