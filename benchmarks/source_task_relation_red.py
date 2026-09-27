"""CPU-only, source-bound RED fixture for task coverage in actual frontier menus.

The two candidate summaries and costs are equal. Their source locators alone
say whether they cover the observed task. No cause or result is read to rank.
"""

from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from benchmarks.source_backed_frontier_pilot import (
    _CASES,  # pyright: ignore[reportPrivateUsage]
    _evidence_id,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.source_backed_full_run import (
    _SOURCE_IDS,  # pyright: ignore[reportPrivateUsage]
    FrozenMenuRanker,
    _app,  # pyright: ignore[reportPrivateUsage]
    _checkpoint,  # pyright: ignore[reportPrivateUsage]
)
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
from systemsense.evidence.retrieval import (
    EvidenceCatalogQuery,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
)
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _seed(
    store: SQLiteStore,
    case_id: CaseId,
    domain: str,
    task: dict[str, Any],
    matched_evidence_id: EvidenceId,
) -> None:
    task_facts = task["facts"]
    task_start = str(task_facts["synthetic_window_start_utc"])
    task_end = str(task_facts["synthetic_window_end_utc"])
    observed = datetime.fromisoformat(task_end) + timedelta(microseconds=1)
    for index in range(1, 53):
        evidence_id = _evidence_id(index)
        trusted = index in (49, 50)
        locator: dict[str, JsonValue]
        if trusted:
            matches = evidence_id == matched_evidence_id
            other_is_short_window = domain == "application_performance"
            locator = {
                "case_id": str(case_id),
                "domain": domain,
                "source_index": index,
                "target_handle": (
                    str(task_facts["target_handle"])
                    if matches or other_is_short_window
                    else f"synthetic:{domain}:other"
                ),
                "coverage_start_utc": (
                    (datetime.fromisoformat(task_start) + timedelta(milliseconds=100)).isoformat()
                    if not matches and other_is_short_window
                    else task_start
                ),
                "coverage_end_utc": task_end,
            }
        else:
            locator = {"domain": domain, "source_index": index}
        source_type = "fixture.task_coverage" if trusted else "fixture.scripted.source"
        source_id = stable_source_id(source_type, locator)
        record = EvidenceRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            statement_kind=StatementKind.OBSERVED_FACT,
            observed_at=observed,
            captured_at=observed,
            source=EvidenceSource(type=source_type, source_id=source_id, locator=locator),
            collector=CollectorReference(
                id="fixture.task_coverage",
                version=1,
                execution_id=ExecutionId(root=f"exec_{index:032x}"),
            ),
            summary=(
                "Affected task coverage sample" if trusted else f"Background source record {index}"
            ),
            facts=(
                EvidenceFact(name="source_result_sentinel", value="private_source_result_unopened")
                if trusted
                else EvidenceFact(name="background_index", value=index),
            ),
            extraction=Extraction(
                confidence=1.0,
                parser="fixture.task_coverage" if trusted else "fixture.scripted",
                parser_version=1,
            ),
            sensitivity=Sensitivity.SYSTEM_METADATA,
            limitations=("Preexisting synthetic fixture source; no on-case probe execution.",),
        )
        with store.transaction() as transaction:
            assert transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=source_id,
                record_json=record.model_dump_json(),
                observed_at=observed.isoformat(),
                captured_at=observed.isoformat(),
                execution_id=str(record.collector.execution_id),
                time_basis="fixture_observed",
                time_quality="exact",
            )


def run_balanced_relation_probe(root: Path) -> list[dict[str, Any]]:
    """Return actual app.run requests plus exact selected/alternative readback."""

    root.mkdir(parents=True, exist_ok=False)
    cells: list[dict[str, Any]] = []
    for spec in _CASES:
        checkpoint_path = root / f"{spec.case_key}-checkpoint.db"
        checkpoint = _checkpoint(checkpoint_path, spec)
        checkpoint_sha = hashlib.sha256(checkpoint_path.read_bytes()).hexdigest()
        for matched_index in (49, 50):
            for chosen_index in (49, 50):
                database = (
                    root / f"{spec.case_key}-matched-{matched_index}-chosen-{chosen_index}.db"
                )
                shutil.copyfile(checkpoint_path, database)
                assert hashlib.sha256(database.read_bytes()).hexdigest() == checkpoint_sha
                with SQLiteStore(database) as store:
                    case_id = CaseId(root=str(checkpoint["case_id"]))
                    matched_id = _evidence_id(matched_index)
                    chosen_id = _evidence_id(chosen_index)
                    alternative_id = _evidence_id(99 - chosen_index)
                    _seed(store, case_id, spec.domain, checkpoint["task_observation"], matched_id)
                    retriever = EvidenceRetriever(store)
                    catalog = retriever.discover(EvidenceCatalogQuery(case_id=case_id, limit=64))
                    ranker = FrozenMenuRanker(chosen_index - 49)  # type: ignore[arg-type]
                    app = _app(store, spec, ranker)
                    frontier = SearchFrontierRepository(store)
                    with store.transaction():
                        event = frontier.append_result_event(
                            case_id,
                            source_evidence_id=_evidence_id(49),
                            source_execution_id=None,
                            versions=RelevantVersionsV1(
                                objective=1, evidence=catalog.case_evidence_generation
                            ),
                        )
                    assert isinstance(event, FrontierEventV1) and event.source_state == "present"
                    state = app.run(str(case_id))
                    request = ranker.target_request
                    assert request is not None
                    menu = [
                        str(item.reference.evidence_id)
                        for item in request.items
                        if item.reference.kind == "retrieve_evidence"
                    ]
                    assert menu == list(_SOURCE_IDS)
                    assert chosen_id in state.fast_catalog_selected_ids
                    packet = retriever.retrieve(
                        EvidenceRetrievalQuery(
                            current_case_id=case_id,
                            evidence_ids=(chosen_id, alternative_id),
                            priority_evidence_ids=(chosen_id, alternative_id),
                            evidence_limit=2,
                            coverage_limit=1,
                        )
                    )
                    readback = {str(item.evidence_id): item for item in packet.evidence}
                    assert set(readback) == {str(chosen_id), str(alternative_id)}
                    raw_records: dict[str, EvidenceRecord] = {}
                    for evidence_id in (chosen_id, alternative_id):
                        row = store.evidence(case_id=str(case_id), evidence_id=str(evidence_id))
                        assert row is not None
                        raw_records[str(evidence_id)] = EvidenceRecord.model_validate_json(
                            row.record_json
                        )
                    cells.append(
                        {
                            "domain": spec.domain,
                            "checkpoint_sha256": checkpoint_sha,
                            "matched_evidence_id": str(matched_id),
                            "chosen_evidence_id": str(chosen_id),
                            "alternative_evidence_id": str(alternative_id),
                            "menu": menu,
                            "request": request,
                            "selected_readback": readback[str(chosen_id)].model_dump(mode="json"),
                            "alternative_readback": readback[str(alternative_id)].model_dump(
                                mode="json"
                            ),
                            "source_locators": {
                                key: record.source.locator for key, record in raw_records.items()
                            },
                        }
                    )
    return cells
