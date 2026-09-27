import pytest

import systemsense.application.investigator as investigator
from systemsense.application.bootstrap import default_capabilities
from systemsense.application.investigator import (
    _baseline_probe_ids,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.domain.evidence import Sensitivity
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import default_probe_runner


@pytest.mark.parametrize(
    ("symptom", "expected"),
    [
        ("I cannot connect to Wi-Fi", ("network.connectivity", "core.system")),
        ("Proxy is blocking the browser", ("network.connectivity", "core.system")),
        ("My game is at 12 FPS", ("gpu.telemetry.sample", "core.system")),
        ("This PDF is slow", ("application.snapshot", "core.resources", "core.system")),
        (
            "PDF viewer and related indexing service both run slowly",
            ("application.snapshot", "core.resources", "core.system"),
        ),
        ("My audio driver failed", ("devices.snapshot", "core.system")),
        ("The disk is failing", ("storage.snapshot", "core.system")),
        ("Something is wrong", ("core.system",)),
    ],
)
def test_seed_does_not_broad_scan_unrelated_families(
    symptom: str, expected: tuple[str, ...]
) -> None:
    available = frozenset(
        {
            "core.system",
            "core.resources",
            "application.snapshot",
            "devices.snapshot",
            "network.configuration",
            "network.connectivity",
            "storage.snapshot",
            "gpu.telemetry.sample",
        }
    )
    assert _baseline_probe_ids(symptom, available) == expected


def test_seed_uses_existing_network_probe_when_targeted_probe_is_unavailable() -> None:
    assert _baseline_probe_ids(
        "Wi-Fi will not connect", frozenset({"core.system", "network.configuration"})
    ) == ("network.configuration", "core.system")


def test_fast_hypothesis_attention_retains_new_and_rotates_old_alternatives() -> None:
    hypotheses = tuple(f"Mechanism {index}" for index in range(16))

    assert hasattr(investigator, "_fast_hypothesis_briefs")
    turns = tuple(
        investigator._fast_hypothesis_briefs(hypotheses, generation)  # pyright: ignore[reportPrivateUsage,reportAttributeAccessIssue]
        for generation in range(3)
    )

    assert all(len(turn) <= 8 for turn in turns)
    assert all("Mechanism 15" in turn and "Mechanism 14" in turn for turn in turns)
    assert set().union(*(set(turn) for turn in turns)) == set(hypotheses)


@pytest.mark.parametrize(
    ("objective", "baseline"),
    [
        ("My game runs at 12 FPS", ("gpu.telemetry.sample", "core.system")),
        ("My disk is slow", ("storage.snapshot", "core.system")),
    ],
)
def test_scout_looks_one_reference_step_ahead_with_a_separate_small_budget(
    objective: str, baseline: tuple[str, ...]
) -> None:
    assert hasattr(investigator, "_scout_prefetch_probe_ids")
    scout = investigator._scout_prefetch_probe_ids  # pyright: ignore[reportPrivateUsage,reportAttributeAccessIssue]
    graph = ReferenceKnowledgeGraph.load_default()
    tools = default_probe_runner().discover_applicable(
        observed_probe_ids=frozenset(),
        available_target_kinds=frozenset(),
        allowed_sensitivities=frozenset({Sensitivity.SYSTEM_METADATA}),
        allowed_resources=frozenset({"cpu"}),
        remaining_budget_ms=2_000,
    )

    assert scout(
        objective=objective,
        selected_probe_ids=baseline,
        capabilities=default_capabilities(),
        applicable_tools=tools,
        knowledge=graph,
        max_cost_ms=2_000,
    ) == ("core.resources",)
    assert (
        scout(
            objective=objective,
            selected_probe_ids=baseline,
            capabilities=default_capabilities(),
            applicable_tools=tools,
            knowledge=graph,
            max_cost_ms=50,
        )
        == ()
    )


def test_scout_never_uses_undeclared_process_inventory_even_when_capability_cost_is_tiny() -> None:
    tools = default_probe_runner().discover_applicable(
        observed_probe_ids=frozenset(),
        available_target_kinds=frozenset(),
        allowed_sensitivities=frozenset({Sensitivity.SYSTEM_METADATA}),
        allowed_resources=frozenset({"cpu"}),
        remaining_budget_ms=2_000,
    )
    capabilities = tuple(
        capability.model_copy(update={"cost_ms": 1, "resource_class": ResourceClass.CPU})
        if capability.probe_id == "application.snapshot"
        else capability
        for capability in default_capabilities()
    )
    selected = investigator._scout_prefetch_probe_ids(  # pyright: ignore[reportPrivateUsage]
        objective="Check Windows health and resource pressure",
        selected_probe_ids=("core.system",),
        capabilities=capabilities,
        applicable_tools=tools,
        knowledge=ReferenceKnowledgeGraph.load_default(),
        max_cost_ms=2_000,
    )
    assert "application.snapshot" not in selected


def test_followup_retrieval_combines_registered_applicability_lexical_and_graph_hints() -> None:
    tools = default_probe_runner().discover_applicable(
        observed_probe_ids=frozenset(),
        available_target_kinds=frozenset(),
        allowed_sensitivities=frozenset(Sensitivity),
        allowed_resources=frozenset({"cpu", "disk", "gpu", "network", "process"}),
        remaining_budget_ms=20_000,
    )
    ranked = investigator._rank_applicable_followups(  # pyright: ignore[reportPrivateUsage]
        objective="Browser proxy configuration conflicts with the network route",
        capabilities=default_capabilities(),
        applicable_tools=tools,
        knowledge=ReferenceKnowledgeGraph.load_default(),
    )
    ids = tuple(item.probe_id for item in ranked)
    assert ids.index("network.configuration") < ids.index("power.snapshot")
    assert ids.index("network.connectivity") < ids.index("security.snapshot")
    assert "application.target_pressure" not in ids


def test_failed_followup_shortlist_widens_without_dropping_its_head() -> None:
    ranked = default_capabilities()
    first = investigator._followup_shortlist(ranked, stagnant_rounds=0)  # pyright: ignore[reportPrivateUsage]
    widened = investigator._followup_shortlist(ranked, stagnant_rounds=1)  # pyright: ignore[reportPrivateUsage]
    assert first == ranked[:8]
    assert widened[:4] == ranked[:4]
    assert ranked[8] in widened
    assert len(widened) <= 8


@pytest.mark.parametrize(
    ("status", "started", "evidence", "used", "expected"),
    [
        (None, False, frozenset[str](), frozenset[str](), "unaccounted"),
        ("cancelled", False, frozenset[str](), frozenset[str](), "cancelled_queued"),
        ("succeeded", True, frozenset({"e1"}), frozenset({"e1"}), "used"),
        ("succeeded", True, frozenset({"e1"}), frozenset({"e2"}), "wasted"),
        ("failed", True, frozenset[str](), frozenset[str](), "wasted"),
    ],
)
def test_scout_usage_requires_explicit_attention_or_citation(
    status: str | None,
    started: bool,
    evidence: frozenset[str],
    used: frozenset[str],
    expected: str,
) -> None:
    assert (
        investigator._scout_prefetch_usage(  # pyright: ignore[reportPrivateUsage]
            status, started, evidence, used
        )
        == expected
    )
