"""Runtime authorization for executing an allowlisted diagnostic probe."""

from collections.abc import Mapping
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from systemsense.domain.probes import Privilege, ProbeManifest
from systemsense.orchestration.catalog import ProbeCatalog


class PolicyDenied(ValueError):
    """A requested probe cannot be safely authorized."""


@dataclass(frozen=True, slots=True)
class AuthorizedProbe:
    manifest: ProbeManifest
    parameters: BaseModel


class ProbePolicy:
    def __init__(self, catalog: ProbeCatalog) -> None:
        self._catalog = catalog

    def authorize(
        self,
        probe_id: str,
        parameters: Mapping[str, object],
    ) -> AuthorizedProbe:
        registration = self._catalog.get(probe_id)
        if registration is None:
            raise PolicyDenied(f"unknown probe: {probe_id}")
        if registration.manifest.safety.privilege is not Privilege.STANDARD:
            raise PolicyDenied("probe privilege is unavailable in this runtime")

        try:
            typed_parameters = registration.parameter_model.model_validate(dict(parameters))
        except ValidationError as error:
            raise PolicyDenied("probe parameters rejected") from error

        return AuthorizedProbe(
            manifest=registration.manifest,
            parameters=typed_parameters,
        )
