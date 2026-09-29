from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindowBasis
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
from systemsense.evidence.targets import (
    exact_executable_name,
    retrieve_details,
    select_target_evidence,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import EvidenceDetailRequest
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("objective", "expected"),
    [
        ("Is MyApp.EXE using CPU?", "myapp.exe"),
        (r"Open C:\Tools\MyApp.exe", None),
        ("Fetch https://example.test/MyApp.exe", None),
        ("Compare MyApp.exe and Other.exe", None),
    ],
)
def test_exact_executable_name_requires_one_standalone_literal(
    objective: str, expected: str | None
) -> None:
    assert exact_executable_name(objective) == expected


def test_exact_process_cpu_sample_is_reserved_for_deep_review(tmp_path: Path) -> None:
    pressure: dict[str, JsonValue] = {
        "target_pid": 4242,
        "target_creation_time": NOW.isoformat(),
        "status": "available",
        "samples": [
            {"name": "alpha-helper.exe", "delta_status": "baseline", "cpu_percent": None},
            {"name": "alpha-helper.exe", "delta_status": "measured", "cpu_percent": 4.1},
            {"name": "alpha-helper.exe", "delta_status": "measured", "cpu_percent": 4.0},
        ],
    }
    with SQLiteStore(tmp_path / "target-pressure.db") as store:
        context = _context(
            store,
            {"target_pressure": pressure},
            probe_id="application.target_pressure",
        )
        selected = select_target_evidence(
            store, (context,), "Is my alpha-helper.exe process using CPU?"
        )

    assert len(selected.context) == 1
    assert selected.context[0].evidence_id == context.evidence_id
    assert selected.context[0].observed_at == context.observed_at
    assert selected.context[0].facts["target_pressure"] == pressure
    assert selected.matched_row_paths == (f"{context.evidence_id}:target_pressure",)


def _context(
    store: SQLiteStore, facts: dict[str, JsonValue], *, probe_id: str = "network.listeners"
) -> EvidenceContext:
    case_id = CaseId(root="case_11111111111111111111111111111111")
    evidence_id = EvidenceId(root="ev_11111111111111111111111111111111")
    execution_id = ExecutionId(root="exec_11111111111111111111111111111111")
    source_id = stable_source_id("fixture.targets", {"case_id": str(case_id)})
    store.create_case(
        case_id=str(case_id),
        kind=CaseKind.GENERAL.value,
        symptom="fixture",
        created_at=NOW.isoformat(),
        status=CaseStatus.OPEN.value,
        time_window_start=NOW.isoformat(),
        time_window_end=NOW.isoformat(),
        time_window_basis=CaseTimeWindowBasis.USER_REPORTED.value,
    )
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW,
        captured_at=NOW,
        source=EvidenceSource(
            type="fixture.targets",
            source_id=source_id,
            locator={"probe_id": probe_id},
        ),
        collector=CollectorReference(
            id=probe_id,
            version=1,
            execution_id=execution_id,
        ),
        summary="Bounded TCP listeners",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1.0, parser="fixture", parser_version=1),
        sensitivity=Sensitivity.PERSONAL,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=NOW.isoformat(),
            captured_at=NOW.isoformat(),
            execution_id=str(execution_id),
            dedupe_key="fixture:target",
            time_basis="source_observed",
            time_quality="exact",
        )
    return EvidenceContext(
        evidence_id=evidence_id,
        observed_at=NOW,
        captured_at=NOW,
        probe_id=probe_id,
        summary=record.summary,
        facts={"omitted_listener_count": facts.get("omitted_listener_count")},
        status=EvidenceContextStatus.OBSERVED,
    )


def _listener(address: str, port: int, pid: int) -> dict[str, JsonValue]:
    return {
        "protocol": "tcp4",
        "local_address": address,
        "local_port": port,
        "pid": pid,
        "process_name": f"process-{pid}.exe",
        "process_creation_time": "2026-09-22T11:00:00Z",
        "owner_status": "available",
    }


def test_exact_listener_target_finds_complete_row_beyond_first_128_records(
    tmp_path: Path,
) -> None:
    listeners: list[JsonValue] = [
        _listener("127.0.0.1", 20_000 + index, index + 1) for index in range(200)
    ]
    listeners[180] = {
        **_listener("127.0.0.1", 18765, 52048),
        "process_name": "python.exe",
    }
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "listeners": listeners,
                "omitted_listener_count": 0,
                "collection_status": "available",
            },
        )

        selected = select_target_evidence(store, (context,), "Why can I not bind 127.0.0.1:18765?")

    assert selected.context[0].facts["listeners.180"] == listeners[180]
    assert selected.context[0].facts["omitted_listener_count"] == 0
    assert selected.matched_row_paths == (f"{context.evidence_id}:listeners.180",)


def test_address_qualified_target_does_not_select_same_port_on_other_address(
    tmp_path: Path,
) -> None:
    listeners: list[JsonValue] = [
        _listener("0.0.0.0", 18765, 1),
        _listener("127.0.0.1", 18765, 2),
    ]
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(store, {"listeners": listeners, "omitted_listener_count": 0})

        selected = select_target_evidence(store, (context,), "Check 127.0.0.1:18765")

    assert selected.context[0].facts["listeners.1"] == listeners[1]
    assert "listeners.0" not in selected.context[0].facts


def test_complete_listener_table_exposes_sampled_target_port_absence(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "listeners": [_listener("127.0.0.1", 18766, 2)],
                "omitted_listener_count": 0,
                "collection_status": "partial",
                "listener_table_started_at": "2026-09-22T11:59:59Z",
                "listener_table_completed_at": "2026-09-22T12:00:00Z",
            },
        )
        selected = select_target_evidence(store, (context,), "GET 127.0.0.1:18765 timed out")

    assert len(selected.context) == 1
    excerpt = selected.context[0]
    assert excerpt.evidence_id == context.evidence_id
    assert excerpt.facts["target_listener_search"] == [
        {
            "address": "127.0.0.1",
            "port": 18765,
            "status": "no_listener_on_target_port_at_sample_time",
            "same_port_other_address_count": 0,
        }
    ]
    assert excerpt.facts["omitted_listener_count"] == 0
    assert excerpt.facts["collection_status"] == "partial"
    assert excerpt.facts["listener_table_completed_at"] == "2026-09-22T12:00:00Z"
    assert "listeners" not in excerpt.facts
    assert any("sample" in note.casefold() for note in excerpt.limitations)


@pytest.mark.parametrize("omitted", [1, None])
def test_incomplete_listener_table_never_proves_target_absence(
    tmp_path: Path, omitted: int | None
) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "listeners": [_listener("127.0.0.1", 18766, 2)],
                "omitted_listener_count": omitted,
                "collection_status": "partial",
            },
        )
        selected = select_target_evidence(store, (context,), "GET 127.0.0.1:18765 timed out")

    search = selected.context[0].facts["target_listener_search"]
    assert isinstance(search, list)
    assert isinstance(search[0], dict)
    assert search[0]["status"] == "incomplete_listener_coverage"
    assert selected.context[0].facts["omitted_listener_count"] == omitted


def test_same_port_on_other_address_is_not_no_port_finding(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "listeners": [_listener("10.1.2.3", 18765, 2)],
                "omitted_listener_count": 0,
                "collection_status": "available",
            },
        )
        selected = select_target_evidence(store, (context,), "GET 127.0.0.1:18765 timed out")

    search = selected.context[0].facts["target_listener_search"]
    assert isinstance(search, list)
    assert isinstance(search[0], dict)
    assert search[0]["status"] == "same_port_other_address_observed"


def test_stale_listener_absence_retains_time_and_relevance_limits(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(store, {"listeners": [], "omitted_listener_count": 0}).model_copy(
            update={
                "case_scope": "historical",
                "incident_relevant": False,
                "status": EvidenceContextStatus.STALE,
                "limitations": ("outside the reported incident window",),
            }
        )
        selected = select_target_evidence(store, (context,), "GET 127.0.0.1:18765 timed out")

    excerpt = selected.context[0]
    assert excerpt.case_scope == "historical"
    assert excerpt.incident_relevant is False
    assert excerpt.status is EvidenceContextStatus.STALE
    assert "outside the reported incident window" in excerpt.limitations


def test_listener_scan_limit_does_not_prove_absence(tmp_path: Path) -> None:
    listeners: list[JsonValue] = [
        _listener("127.0.0.1", 20_000 + index, index + 1) for index in range(2050)
    ]
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "listeners": listeners,
                "omitted_listener_count": 0,
                "collection_status": "available",
            },
        )
        selected = select_target_evidence(store, (context,), "GET 127.0.0.1:18765 timed out")

    assert selected.truncated is True
    assert selected.context == () or all(
        "no_listener_on_target_port_at_sample_time" not in str(item.facts)
        for item in selected.context
    )


def test_pid_literal_selects_complete_process_row_without_guessing(tmp_path: Path) -> None:
    processes: list[JsonValue] = [
        {"pid": 7, "name": "other.exe", "creation_time": "2026-09-22T10:00:00Z"},
        {"pid": 52048, "name": "python.exe", "creation_time": "2026-09-22T08:20:01Z"},
    ]
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(store, {"processes": processes})

        selected = select_target_evidence(store, (context,), "Inspect PID 52048")

    assert selected.context[0].facts == {"processes.1": processes[1]}


def test_exact_executable_name_rehydrates_live_process_row_beyond_compact_view(
    tmp_path: Path,
) -> None:
    processes: list[JsonValue] = [
        {"pid": index + 1, "name": f"other-{index}.exe", "creation_time": NOW.isoformat()}
        for index in range(200)
    ]
    processes[180] = {
        "pid": 57000,
        "name": "alpha-helper.exe",
        "creation_time": NOW.isoformat(),
    }
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "processes": processes,
                "omitted_counts": {"processes": 51},
                "collection_status": "partial",
                "collection_started_at": NOW.isoformat(),
                "collection_completed_at": NOW.isoformat(),
            },
            probe_id="application.snapshot",
        )
        selected = select_target_evidence(
            store, (context,), "My alpha-helper.exe process stopped unexpectedly"
        )

    excerpt = selected.context[0]
    assert excerpt.facts["processes.180"] == processes[180]
    searches = cast("list[dict[str, JsonValue]]", excerpt.facts["target_process_search"])
    assert searches[0]["status"] == "matching_process_observed"
    assert excerpt.facts["omitted_counts"] == {"processes": 51}
    assert selected.matched_row_paths == (f"{context.evidence_id}:processes.180",)


@pytest.mark.parametrize(
    ("omitted", "expected"),
    [(0, "no_matching_process_in_saved_complete_table"), (51, "incomplete_process_inventory")],
)
def test_exact_executable_name_absence_requires_complete_saved_process_table(
    tmp_path: Path, omitted: int, expected: str
) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "processes": [{"pid": 7, "name": "other.exe", "creation_time": NOW.isoformat()}],
                "omitted_counts": {"processes": omitted},
                "collection_status": "available" if omitted == 0 else "partial",
                "collection_started_at": NOW.isoformat(),
                "collection_completed_at": NOW.isoformat(),
            },
            probe_id="application.snapshot",
        )
        selected = select_target_evidence(
            store, (context,), "My alpha-helper.exe process stopped unexpectedly"
        )

    assert selected.matched_row_paths == ()
    searches = cast(
        "list[dict[str, JsonValue]]", selected.context[0].facts["target_process_search"]
    )
    assert searches[0]["status"] == expected
    assert selected.context[0].facts["omitted_counts"] == {"processes": omitted}


def test_process_name_search_does_not_count_a_different_pid_match(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "processes": [{"pid": 7, "name": "other.exe", "creation_time": NOW.isoformat()}],
                "omitted_counts": {"processes": 0},
                "collection_status": "available",
            },
            probe_id="application.snapshot",
        )
        selected = select_target_evidence(store, (context,), "Check PID 7 and alpha-helper.exe")

    searches = cast(
        "list[dict[str, JsonValue]]", selected.context[0].facts["target_process_search"]
    )
    assert searches[0]["matched_row_count"] == 0
    assert searches[0]["status"] == "no_matching_process_in_saved_complete_table"


@pytest.mark.parametrize(
    "objective",
    [
        r"Open C:\Tools\alpha-helper.exe",
        "Download https://example.com/alpha-helper.exe",
        "Compare alpha-helper.exe and another-app.exe",
    ],
)
def test_path_url_or_ambiguous_executable_text_does_not_select_process(
    tmp_path: Path, objective: str
) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {
                "processes": [
                    {"pid": 7, "name": "alpha-helper.exe", "creation_time": NOW.isoformat()}
                ],
                "omitted_counts": {"processes": 0},
                "collection_status": "available",
            },
            probe_id="application.snapshot",
        )
        selected = select_target_evidence(store, (context,), objective)

    assert selected.context == ()
    assert selected.matched_row_paths == ()


def test_no_supported_literal_returns_no_match_and_does_not_guess_localhost(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {"listeners": [_listener("127.0.0.1", 18765, 2)], "omitted_listener_count": 0},
        )

        selected = select_target_evidence(store, (context,), "Why can localhost not bind?")

    assert selected.context == ()
    assert selected.matched_row_paths == ()
    assert any("no target evidence was selected" in note.casefold() for note in selected.notes)


def test_detail_request_selects_complete_atomic_row_using_all_plain_literals(
    tmp_path: Path,
) -> None:
    listeners: list[JsonValue] = [
        _listener("127.0.0.1", 20_000 + index, index + 1) for index in range(200)
    ]
    listeners[180] = {
        **_listener("127.0.0.1", 18765, 52048),
        "process_name": "python.exe",
    }
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(store, {"listeners": listeners, "omitted_listener_count": 0})
        request = EvidenceDetailRequest(
            evidence_id=context.evidence_id,
            match_literals=("python", "52048"),
        )

        selected = retrieve_details(store, (context,), (request,))

    assert selected.context[0].facts["listeners.180"] == listeners[180]
    assert selected.matched_request_keys == (request.key(),)
    assert selected.scanned_object_count == 200
    assert any("plain substring" in note.casefold() for note in selected.notes)


def test_detail_request_reports_only_exact_requests_with_admitted_matches(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {"processes": [{"pid": 52, "name": "python.exe"}]},
        )
        matched = EvidenceDetailRequest(
            evidence_id=context.evidence_id,
            match_literals=("python.exe", "52"),
        )
        absent = EvidenceDetailRequest(
            evidence_id=context.evidence_id,
            match_literals=("missing.exe",),
        )

        selected = retrieve_details(store, (context,), (matched, absent))

    assert selected.matched_request_keys == (matched.key(),)
    assert absent.key() not in selected.matched_request_keys


def test_detail_request_rejects_evidence_outside_scoped_context(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(store, {"listeners": [_listener("127.0.0.1", 18765, 2)]})
        request = EvidenceDetailRequest(
            evidence_id=EvidenceId(root="ev_22222222222222222222222222222222"),
            match_literals=("18765",),
        )

        with pytest.raises(ValueError, match="outside scoped context"):
            retrieve_details(store, (context,), (request,))


def test_detail_request_reports_fixed_scan_truncation_without_false_no_match(
    tmp_path: Path,
) -> None:
    processes: list[JsonValue] = [
        {"pid": index + 1, "name": f"process-{index}.exe"} for index in range(2050)
    ]
    processes[-1] = {"pid": 99999, "name": "needle.exe"}
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(store, {"processes": processes})
        request = EvidenceDetailRequest(
            evidence_id=context.evidence_id,
            match_literals=("needle.exe",),
        )

        selected = retrieve_details(store, (context,), (request,))

    assert selected.context == ()
    assert selected.truncated is True
    assert selected.scanned_object_count == 2048
    assert any("scan limit" in note.casefold() for note in selected.notes)


def test_exact_targets_do_not_collide_on_long_unsafe_source_paths(tmp_path: Path) -> None:
    shared = "segment" * 20
    first_name = f"{shared} first/value"
    second_name = f"{shared} second:value"
    first = _listener("127.0.0.1", 18765, 1)
    second = _listener("127.0.0.1", 18765, 2)
    nested: dict[str, JsonValue] = {
        first_name: first,
        second_name: second,
        "padding": "x" * 8100,
    }
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(store, {"nested": nested})

        selected = select_target_evidence(store, (context,), "Check 127.0.0.1:18765")

    assert len(selected.context[0].facts) == 2
    wrappers = list(selected.context[0].facts.values())
    pids: set[int] = set()
    for wrapper in wrappers:
        assert isinstance(wrapper, dict)
        wrapped_value = wrapper.get("value")
        assert isinstance(wrapped_value, dict)
        pid = wrapped_value.get("pid")
        assert isinstance(pid, int) and not isinstance(pid, bool)
        pids.add(pid)
    assert pids == {1, 2}


def test_rehydrated_match_replaces_only_packet_compaction_limitations(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        context = _context(
            store,
            {"listeners": [_listener("127.0.0.1", 18765, 2)], "omitted_listener_count": 3},
        ).model_copy(
            update={
                "limitations": (
                    "Evidence facts were truncated for this compact packet.",
                    "collector stopped at its fixed row limit",
                )
            }
        )

        selected = select_target_evidence(store, (context,), "Check 127.0.0.1:18765")

    limitations = selected.context[0].limitations
    assert "Evidence facts were truncated for this compact packet." not in limitations
    assert "collector stopped at its fixed row limit" in limitations
    assert any("rehydrated" in item.casefold() for item in limitations)
