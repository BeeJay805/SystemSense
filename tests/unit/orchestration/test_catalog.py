import pytest
from pydantic import BaseModel, ConfigDict

from systemsense.domain.ids import CaseId
from systemsense.domain.probes import ProbeManifest
from systemsense.orchestration.catalog import CatalogError, ProbeCatalog
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
