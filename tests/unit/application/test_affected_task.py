from pathlib import Path

from systemsense.application.bootstrap import default_investigator
from systemsense.application.investigator import (
    _baseline_probe_ids,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.domain.affected_task import AffectedTaskKind, ReportedAffectedTaskV1
from systemsense.storage.sqlite_store import SQLiteStore


def test_reported_task_is_durable_but_unverified(tmp_path: Path) -> None:
    report = ReportedAffectedTaskV1(
        kind=AffectedTaskKind.APPLICATION_OPERATION,
        action="Open a document in the viewer",
        target_hint="viewer process",
        expected_outcome="Document opens promptly",
        reported_outcome="Document takes a long time to open",
    )
    with SQLiteStore(tmp_path / "case.db") as store:
        investigator = default_investigator(store)
        created = investigator.create(objective="It hangs", reported_task=report)
        reloaded = investigator.repository.load(str(created.case_id))

    assert reloaded.reported_task == report
    assert reloaded.reported_task is not None
    assert reloaded.reported_task.verification == "unverified"


def test_reported_task_seeds_only_relevant_registered_probes() -> None:
    available = frozenset(
        {
            "network.connectivity",
            "network.configuration",
            "application.snapshot",
            "core.resources",
            "core.system",
            "devices.snapshot",
            "storage.snapshot",
        }
    )
    browser = ReportedAffectedTaskV1(
        kind=AffectedTaskKind.BROWSER_NAVIGATION,
        action="Open a page",
        reported_outcome="Page does not load",
    )
    application = ReportedAffectedTaskV1(
        kind=AffectedTaskKind.APPLICATION_OPERATION,
        action="Open a document",
        reported_outcome="It hangs",
    )

    assert _baseline_probe_ids("It fails", available, browser) == (
        "network.connectivity",
        "network.configuration",
        "core.system",
    )
    assert _baseline_probe_ids("It hangs", available, application) == (
        "application.snapshot",
        "core.resources",
        "core.system",
    )
