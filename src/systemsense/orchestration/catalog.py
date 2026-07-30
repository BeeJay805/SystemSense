"""Closed catalog of probe manifests and typed parameter models."""

from dataclasses import dataclass

from pydantic import BaseModel

from systemsense.domain.probes import ProbeManifest

_FORBIDDEN_PARAMETER_TOKENS = frozenset(
    {
        "argument",
        "arguments",
        "argv",
        "command",
        "executable",
        "path",
        "powershell",
        "registry",
        "shell",
        "sql",
        "uri",
        "url",
        "xpath",
    }
)


class CatalogError(ValueError):
    """A manifest is not safe to add to the trusted probe catalog."""


@dataclass(frozen=True, slots=True)
class ProbeRegistration:
    manifest: ProbeManifest
    parameter_model: type[BaseModel]


class ProbeCatalog:
    """An in-process allowlist with no dynamic implementation loading."""

    def __init__(self, *, trusted_implementation_ids: frozenset[str]) -> None:
        self._trusted_implementation_ids = trusted_implementation_ids
        self._registrations: dict[str, ProbeRegistration] = {}

    def register(
        self,
        manifest: ProbeManifest,
        parameter_model: type[BaseModel],
    ) -> None:
        if manifest.implementation_id not in self._trusted_implementation_ids:
            raise CatalogError(f"untrusted implementation: {manifest.implementation_id}")
        if manifest.probe_id in self._registrations:
            raise CatalogError(f"probe already registered: {manifest.probe_id}")

        for field_name in parameter_model.model_fields:
            tokens = frozenset(field_name.lower().split("_"))
            if tokens & _FORBIDDEN_PARAMETER_TOKENS:
                raise CatalogError(f"forbidden parameter field: {field_name}")

        self._registrations[manifest.probe_id] = ProbeRegistration(
            manifest=manifest,
            parameter_model=parameter_model,
        )

    def get(self, probe_id: str) -> ProbeRegistration | None:
        return self._registrations.get(probe_id)
