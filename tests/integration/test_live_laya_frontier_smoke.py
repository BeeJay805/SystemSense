"""Opt-in pinned-Laya smoke for exact stored-evidence frontier retrieval."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from systemsense.application.investigator import Investigator
from systemsense.storage.search_frontier import FrontierStatus
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_catalog_attention_loop import (
    _fill_case,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator
from tests.integration.test_live_laya_receipt_smoke import (
    _managed_pinned_laya_providers,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_LAYA_FRONTIER") != "1",
    reason="explicit opt-in managed CUDA Laya frontier smoke",
)
def test_real_pinned_laya_delivers_exact_stored_evidence(tmp_path: Path) -> None:
    providers = _managed_pinned_laya_providers()
    try:
        providers.prewarm_laya(timeout_seconds=90)
        assert providers.frontier_ranker is not None
        with SQLiteStore(tmp_path / "live-laya-frontier.db") as store:
            base = investigator(store)
            app = Investigator(
                store=store,
                runtime=base.runtime,
                capabilities=base.capabilities,
                decision=base.decision,
                reasoning=base.reasoning,
                knowledge=providers.knowledge,
                frontier_ranker=providers.frontier_ranker,
            )
            state = app.create(objective="Investigate slow network", budget_ms=120_000)
            _fill_case(store, str(state.case_id), count=60)
            before = app.context(str(state.case_id))
            before_ids = {str(item.evidence_id) for item in before}

            updated, after, delivered = app._frontier_retrieval(  # pyright: ignore[reportPrivateUsage]
                state, before
            )

            after_ids = {str(item.evidence_id) for item in after}
            assert delivered is True
            assert len(after_ids - before_ids) == 1
            assert updated.provider_calls[-1].detail == "frontier_laya"
            assert updated.provider_calls[-1].degraded is False
            assert (
                store.connection.execute(
                    "SELECT COUNT(*) FROM search_frontier_transitions WHERE to_status=?",
                    (FrontierStatus.SATISFIED.value,),
                ).fetchone()[0]
                == 1
            )
            assert (
                store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0
            )
    finally:
        providers.close()
