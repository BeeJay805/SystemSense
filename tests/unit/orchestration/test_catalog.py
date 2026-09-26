import pytest
from pydantic import BaseModel, ConfigDict

from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import (
    ProbeManifest,
    ProbeOutputFieldV1,
    ProbeToolMetadataV1,
    SelfWrite,
)
from systemsense.orchestration.catalog import CatalogError, ProbeCatalog
from systemsense.policy import PolicyDenied, ProbePolicy
from tests.security.test_probe_policy import manifest_data


class CaseParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: CaseId


def test_catalog_rejects_duplicate_probe_ids() -> None:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    manifest = ProbeManifest.model_validate(manifest_data())
    catalog.register(manifest, CaseParameters)

    with pytest.raises(CatalogError, match="already registered"):
        catalog.register(manifest, CaseParameters)


def test_catalog_returns_registered_probe() -> None:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    manifest = ProbeManifest.model_validate(manifest_data())
    catalog.register(manifest, CaseParameters)

    registration = catalog.get("application.file_identity")

    assert registration is not None
    assert registration.manifest == manifest
    assert registration.parameter_model is CaseParameters


def _discovery(**changes: object) -> ProbeToolMetadataV1:
    values: dict[str, object] = {
        "probe_id": "application.file_identity",
        "probe_version": 1,
        "observable_ids": ("file.identity",),
        "target_kind": "registered.file",
        "parameter_fields": ("case_id",),
        "supports_window": False,
        "prerequisite_probe_ids": ("application.snapshot",),
        "outputs": (ProbeOutputFieldV1(name="file.identity", unit=None),),
        "estimated_cost_ms": 1200,
        "resource_class": "disk",
        "sensitivity": Sensitivity.PERSONAL,
        "network_effect": "none",
        "io_intensity": "light",
        "target_state_effect": "none",
        "self_writes": (SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
        "purpose": "Distinguish the registered application's file identity.",
    }
    values.update(changes)
    return ProbeToolMetadataV1.model_validate(values)


def _applicable(
    catalog: ProbeCatalog,
    *,
    observed_probe_ids: frozenset[str] = frozenset({"application.snapshot"}),
    available_target_kinds: frozenset[str] = frozenset({"registered.file"}),
    allowed_sensitivities: frozenset[Sensitivity] = frozenset({Sensitivity.PERSONAL}),
    allowed_resources: frozenset[str] = frozenset({"disk"}),
    remaining_budget_ms: int = 1200,
    allow_network: bool = False,
    allow_heavy_io: bool = False,
) -> tuple[ProbeToolMetadataV1, ...]:
    return catalog.discover_applicable(
        observed_probe_ids=observed_probe_ids,
        available_target_kinds=available_target_kinds,
        allowed_sensitivities=allowed_sensitivities,
        allowed_resources=allowed_resources,
        remaining_budget_ms=remaining_budget_ms,
        allow_network=allow_network,
        allow_heavy_io=allow_heavy_io,
    )


def test_discovery_requires_registered_target_source_budget_and_privacy() -> None:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    manifest = ProbeManifest.model_validate(manifest_data())
    original_manifest = manifest.model_dump(mode="json")
    catalog.register(manifest, CaseParameters, discovery=_discovery())

    assert _applicable(catalog) == (_discovery(),)
    with pytest.raises(PolicyDenied, match="parameters"):
        ProbePolicy(catalog).authorize(
            manifest.probe_id, {"case_id": str(CaseId.new()), "command": "whoami"}
        )
    assert _applicable(catalog, observed_probe_ids=frozenset()) == ()
    assert _applicable(catalog, available_target_kinds=frozenset()) == ()
    assert _applicable(catalog, remaining_budget_ms=1199) == ()
    assert (
        _applicable(catalog, allowed_sensitivities=frozenset({Sensitivity.SYSTEM_METADATA})) == ()
    )
    assert manifest.model_dump(mode="json") == original_manifest


def test_discovery_network_and_heavy_io_require_separate_policy_opt_in() -> None:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    catalog.register(
        ProbeManifest.model_validate(manifest_data()),
        CaseParameters,
        discovery=_discovery(network_effect="local", io_intensity="heavy"),
    )
    assert _applicable(catalog) == ()
    assert _applicable(catalog, allow_network=True) == ()
    assert len(_applicable(catalog, allow_network=True, allow_heavy_io=True)) == 1


def test_unqualified_or_mismatched_discovery_never_adds_executable_capability() -> None:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    manifest = ProbeManifest.model_validate(manifest_data())
    with pytest.raises(CatalogError, match="identity"):
        catalog.register(manifest, CaseParameters, discovery=_discovery(probe_version=2))
    assert catalog.get(manifest.probe_id) is None
    catalog.register(manifest, CaseParameters)
    assert _applicable(catalog) == ()
    assert catalog.get(manifest.probe_id) is not None


def test_discovery_cannot_misstate_registered_effects() -> None:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    manifest = ProbeManifest.model_validate(manifest_data())
    with pytest.raises(CatalogError, match="effects"):
        catalog.register(manifest, CaseParameters, discovery=_discovery(self_writes=()))
    assert catalog.get(manifest.probe_id) is None


def test_discovery_names_cannot_be_arbitrary_selectors() -> None:
    with pytest.raises(ValueError, match="observable_ids"):
        _discovery(observable_ids=("https://example.invalid/execute",))
