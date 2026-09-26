"""The closed built-in registry must describe its actual measurement choices."""

from systemsense.domain.evidence import Sensitivity
from systemsense.packs.runtime import default_probe_definitions, default_probe_runner


def test_every_builtin_has_truthful_bounded_discovery_metadata() -> None:
    definitions = default_probe_definitions()
    assert definitions
    for definition in definitions:
        metadata = definition.discovery
        assert metadata is not None, definition.manifest.probe_id
        assert metadata.probe_id == definition.manifest.probe_id
        assert metadata.probe_version == definition.manifest.version
        assert metadata.outputs
        assert metadata.purpose
        assert metadata.estimated_cost_ms <= definition.manifest.limits.timeout_ms
        assert metadata.parameter_fields == tuple(definition.parameter_model.model_fields)


def test_discovery_filters_targeted_and_personal_tools_without_minting_authority() -> None:
    runner = default_probe_runner()
    unrestricted = runner.discover_applicable(
        observed_probe_ids=frozenset({"application.snapshot"}),
        available_target_kinds=frozenset({"process"}),
        allowed_sensitivities=frozenset(Sensitivity),
        allowed_resources=frozenset({"cpu", "disk", "gpu", "network", "process"}),
        remaining_budget_ms=20_000,
        allow_network=True,
        allow_heavy_io=True,
    )
    assert {item.probe_id for item in unrestricted} == {
        item.manifest.probe_id for item in default_probe_definitions()
    }
    no_target = runner.discover_applicable(
        observed_probe_ids=frozenset(),
        available_target_kinds=frozenset(),
        allowed_sensitivities=frozenset({Sensitivity.SYSTEM_METADATA}),
        allowed_resources=frozenset({"cpu", "disk", "gpu", "network", "process"}),
        remaining_budget_ms=20_000,
    )
    assert "application.target_pressure" not in {item.probe_id for item in no_target}
    assert "network.connectivity" not in {item.probe_id for item in no_target}
