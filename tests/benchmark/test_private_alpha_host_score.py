"""Cold startup is measured once; reused or missing setup is not zero time."""

import pytest

from benchmarks.private_alpha_host_score import _aggregate  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "setup,seconds,status",
    [
        ({"elapsed_ms": 27875.0}, 27.875, "measured"),
        (
            {"elapsed_ms": None, "startup_attempted": False, "provider_reused": True},
            None,
            "provider_reused",
        ),
        ({"elapsed_ms": None}, None, "not_measured"),
        ({}, None, "not_measured"),
    ],
)
def test_cold_startup_preserves_measurement_status(
    setup: dict[str, object], seconds: float | None, status: str
) -> None:
    row = {
        "complete": True,
        "product_observation_matches_oracle": True,
        "restored_before_cleanup": True,
        "all_owned_helpers_exited": True,
        "laya_provider_call_receipts": 0,
        "laya_candidate_rank_receipts": 1,
        "sol_calls": 1,
        "warm_elapsed_ms": 20000,
        "tree_rss_peak_bytes": 1024**2,
    }
    result = _aggregate([row], setup)
    assert result["cold_setup_s"] == seconds
    assert result["cold_setup_status"] == status
    assert result["warm_median_s"] == 20
    assert result["cases"] == 1
