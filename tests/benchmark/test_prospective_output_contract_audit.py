"""The archived model response must not receive credit for unregistered facts."""

from benchmarks.prospective_output_contract_audit import score_predictions
from systemsense.reasoning.contracts import ExpectedFact


def test_prediction_credit_requires_registered_name_and_value_domain() -> None:
    probe_id = "fixture.direct_origin_after_source"
    rows = (
        (
            "wrong_name",
            ExpectedFact(
                probe_id=probe_id,
                fact_name="browser_direct_origin_reachable",
                expected_value="running",
            ),
        ),
        (
            "wrong_value",
            ExpectedFact(
                probe_id=probe_id,
                fact_name="direct_origin_status",
                expected_value="running",
            ),
        ),
        (
            "aligned",
            ExpectedFact(
                probe_id=probe_id,
                fact_name="direct_origin_status",
                expected_value="offline",
            ),
        ),
    )
    review = score_predictions(
        rows,
        probe_id=probe_id,
        declared_output_names=frozenset({"direct_origin_status"}),
        declared_value_domain=frozenset({"online", "offline"}),
        fixture_value_domain=frozenset({"online", "offline"}),
        prompt_probe={"probe_id": probe_id, "description": "Synthetic source check"},
    )
    assert review["invalid_output_name_count"] == 1
    assert review["fixture_value_mismatch_count"] == 2
    assert review["useful_prospective_test_count"] == 1
    assert [row["useful_prospective_test"] for row in review["predictions"]] == [
        False,
        False,
        True,
    ]
    assert review["model_visible_output_names"] == []

    unknown_domain = score_predictions(
        (rows[2],),
        probe_id=probe_id,
        declared_output_names=frozenset({"direct_origin_status"}),
        declared_value_domain=None,
        fixture_value_domain=frozenset({"online", "offline"}),
        prompt_probe={"probe_id": probe_id},
    )
    assert unknown_domain["predictions"][0]["value_in_declared_domain"] is None
    assert unknown_domain["useful_prospective_test_count"] == 0
