import os
from collections import Counter
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_case_runtime
from systemsense.domain.cases import CaseKind, CaseStatus
from systemsense.domain.time import utc_now
from systemsense.storage.sqlite_store import SQLiteStore


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to run the complete live case runtime",
)
@pytest.mark.parametrize(
    ("kind", "symptom", "traits"),
    [
        (CaseKind.APPLICATION, "application crash", ("application",)),
        (CaseKind.DEVICES_AUDIO, "audio driver missing", ("device",)),
        (CaseKind.NETWORK, "network proxy failure", ()),
        (CaseKind.SERVICING, "Windows Update failure", ()),
        (CaseKind.LOCAL_AI, "CUDA Python GPU failure", ()),
    ],
)
def test_live_family_case_finishes_with_evidence_or_coverage(
    tmp_path: Path,
    kind: CaseKind,
    symptom: str,
    traits: tuple[str, ...],
) -> None:
    with SQLiteStore(tmp_path / f"{kind.value}.db") as store:
        opened = default_case_runtime(store).open_case(
            kind=kind,
            symptom=symptom,
            target_traits=traits,
            created_at=utc_now(),
            budget_ms=60_000,
            max_probes=16,
        )

        assert opened.case.status is CaseStatus.READY
        executions = store.connection.execute(
            "SELECT probe_id, execution_id FROM probe_executions WHERE case_id=?",
            (str(opened.case.case_id),),
        ).fetchall()
        assert Counter(row[0] for row in executions) == Counter(
            probe.probe_id for probe in opened.plan.probes
        )
        assert all(
            store.connection.execute(
                "SELECT 1 FROM evidence WHERE case_id=? AND execution_id=? LIMIT 1",
                (str(opened.case.case_id), row[1]),
            ).fetchone()
            is not None
            for row in executions
        )
        assert store.audit_count(case_id=str(opened.case.case_id)) == len(opened.plan.probes)
        assert store.integrity_check() == "ok"
