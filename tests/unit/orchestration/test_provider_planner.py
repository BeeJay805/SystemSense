import pytest

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
    ResponseValidationError,
)
from systemsense.domain.probes import SafetyClass
from systemsense.orchestration.planner import (
    CasePlanningRequest,
    ProbeCandidate,
    ProviderBackedPlanner,
)
from systemsense.orchestration.scheduler import ResourceClass


class _Provider:
    def __init__(self, proposals: tuple[ProbeProposal, ...]) -> None:
        self.proposals = proposals
        self.request: DecisionRequest | None = None

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="test-provider",
            provider_version="1",
            role="fast_decision",
        )

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        self.request = request
        return DecisionResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            proposals=self.proposals,
        )


def _candidate() -> ProbeCandidate:
    return ProbeCandidate(
        probe_id="network.snapshot",
        description="Read-only network snapshot",
        symptom_terms=frozenset({"network"}),
        cost_ms=250,
        value=0.8,
        resource_class=ResourceClass.NETWORK,
    )


def _request(*, fresh_probe_ids: frozenset[str] = frozenset()) -> CasePlanningRequest:
    return CasePlanningRequest(
        symptom="network failure",
        target_traits=frozenset({"network"}),
        fresh_probe_ids=fresh_probe_ids,
        budget_ms=1000,
        max_probes=4,
    )


def test_provider_planner_builds_typed_read_only_request_and_case_plan() -> None:
    provider = _Provider(
        (
            ProbeProposal(
                probe_id="network.snapshot",
                purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
                priority=0.9,
                estimated_cost_ms=250,
                resource_class=ResourceClass.NETWORK,
                dedupe_key="network.snapshot:current",
            ),
        )
    )
    planner = ProviderBackedPlanner(candidates=(_candidate(),), provider=provider)

    plan = planner.plan(_request())

    assert plan.probe_ids == ("network.snapshot",)
    assert plan.total_cost_ms == 250
    assert provider.request is not None
    capability = provider.request.available_probes[0]
    assert capability.resource_class is ResourceClass.NETWORK
    assert capability.permission_class.value == "read_only"
    assert capability.safety_class.value == "R1"


def test_provider_planner_rejects_fresh_probe_proposal() -> None:
    provider = _Provider(
        (
            ProbeProposal(
                probe_id="network.snapshot",
                purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
                priority=0.9,
                estimated_cost_ms=250,
                resource_class=ResourceClass.NETWORK,
                dedupe_key="network.snapshot:current",
            ),
        )
    )

    with pytest.raises(ResponseValidationError, match="fresh probe"):
        ProviderBackedPlanner(candidates=(_candidate(),), provider=provider).plan(
            _request(fresh_probe_ids=frozenset({"network.snapshot"}))
        )


def test_provider_planner_rejects_unsafe_candidate() -> None:
    with pytest.raises(ValueError, match="safety class"):
        ProbeCandidate(
            probe_id="unsafe.snapshot",
            cost_ms=100,
            value=0.5,
            safety_class=SafetyClass.R2,
        )


def test_provider_planner_rejects_unselected_or_cyclic_dependencies() -> None:
    candidates = (
        _candidate(),
        ProbeCandidate(
            probe_id="core.resources",
            cost_ms=100,
            value=0.8,
            resource_class=ResourceClass.CPU,
        ),
    )
    network = ProbeProposal(
        probe_id="network.snapshot",
        purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
        priority=0.9,
        estimated_cost_ms=250,
        resource_class=ResourceClass.NETWORK,
        dedupe_key="network.snapshot:current",
        depends_on=("core.resources",),
    )
    with pytest.raises(ResponseValidationError, match="not selected"):
        ProviderBackedPlanner(
            candidates=candidates,
            provider=_Provider((network,)),
        ).plan(_request())

    core = ProbeProposal(
        probe_id="core.resources",
        purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
        priority=0.8,
        estimated_cost_ms=100,
        resource_class=ResourceClass.CPU,
        dedupe_key="core.resources:current",
        depends_on=("network.snapshot",),
    )
    with pytest.raises(ResponseValidationError, match="cycle"):
        ProviderBackedPlanner(
            candidates=candidates,
            provider=_Provider((network, core)),
        ).plan(_request())
