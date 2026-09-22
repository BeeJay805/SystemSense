from __future__ import annotations

import pytest

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.evaluation.tracking import TrackedDecisionProvider


class InvalidDecisionProvider(KeywordBaselineDecisionProvider):
    def decide(self, request):  # type: ignore[no-untyped-def]
        response = super().decide(request)
        return response.model_copy(update={"state_version": request.state_version + 1})


def test_tracking_counts_invalid_provider_output_as_a_failed_call() -> None:
    from tests.unit.decision.test_contracts import request

    tracked = TrackedDecisionProvider(InvalidDecisionProvider())
    with pytest.raises(ValueError, match="state_version"):
        tracked.decide(request())
    assert tracked.measurement().calls == 1
    assert tracked.measurement().failures == 1
