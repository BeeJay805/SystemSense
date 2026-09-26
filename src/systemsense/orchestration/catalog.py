"""Closed catalog of probe manifests and typed parameter models."""

from dataclasses import dataclass

from pydantic import BaseModel

from systemsense.domain.evidence import Sensitivity
from systemsense.domain.probes import Privilege, ProbeManifest, ProbeToolMetadataV1, SafetyClass

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
    discovery: ProbeToolMetadataV1 | None = None


class ProbeCatalog:
    """An in-process allowlist with no dynamic implementation loading."""

    def __init__(self, *, trusted_implementation_ids: frozenset[str]) -> None:
        self._trusted_implementation_ids = trusted_implementation_ids
        self._registrations: dict[str, ProbeRegistration] = {}

    def register(
        self,
        manifest: ProbeManifest,
        parameter_model: type[BaseModel],
        *,
        discovery: ProbeToolMetadataV1 | None = None,
    ) -> None:
        if manifest.implementation_id not in self._trusted_implementation_ids:
            raise CatalogError(f"untrusted implementation: {manifest.implementation_id}")
        if manifest.probe_id in self._registrations:
            raise CatalogError(f"probe already registered: {manifest.probe_id}")

        for field_name in parameter_model.model_fields:
            tokens = frozenset(field_name.lower().split("_"))
            if tokens & _FORBIDDEN_PARAMETER_TOKENS:
                raise CatalogError(f"forbidden parameter field: {field_name}")

        if discovery is not None:
            if (discovery.probe_id, discovery.probe_version) != (
                manifest.probe_id,
                manifest.version,
            ):
                raise CatalogError("discovery identity does not match registered manifest")
            if discovery.parameter_fields != tuple(parameter_model.model_fields):
                raise CatalogError("discovery parameters do not match registered model")
            if discovery.supports_window and not {"window_start", "window_end"}.issubset(
                parameter_model.model_fields
            ):
                raise CatalogError("window discovery lacks typed window parameters")
            if discovery.estimated_cost_ms > manifest.limits.timeout_ms:
                raise CatalogError("discovery cost exceeds registered probe timeout")
            if discovery.network_effect == "outbound" and not manifest.safety.outbound_network:
                raise CatalogError("discovery network effect conflicts with manifest")
            if (
                discovery.target_state_effect != manifest.safety.target_state_effect
                or discovery.self_writes != manifest.safety.self_writes
            ):
                raise CatalogError("discovery effects do not match registered manifest")

        self._registrations[manifest.probe_id] = ProbeRegistration(
            manifest=manifest,
            parameter_model=parameter_model,
            discovery=discovery,
        )

    def get(self, probe_id: str) -> ProbeRegistration | None:
        return self._registrations.get(probe_id)

    def discover_applicable(
        self,
        *,
        observed_probe_ids: frozenset[str],
        available_target_kinds: frozenset[str],
        allowed_sensitivities: frozenset[Sensitivity],
        allowed_resources: frozenset[str],
        remaining_budget_ms: int,
        allow_network: bool = False,
        allow_heavy_io: bool = False,
    ) -> tuple[ProbeToolMetadataV1, ...]:
        """Prefilter registered tools for search, never authorize an invocation.

        Missing declarations stay invisible. A later owner must still validate the
        exact source, target, parameters, window, permissions, and fresh manifest.
        """
        if remaining_budget_ms < 0:
            raise ValueError("remaining budget cannot be negative")
        applicable: list[ProbeToolMetadataV1] = []
        for probe_id in sorted(self._registrations):
            registration = self._registrations[probe_id]
            metadata = registration.discovery
            if metadata is None:
                continue
            safety = registration.manifest.safety
            if (
                safety.safety_class not in {SafetyClass.R0, SafetyClass.R1}
                or safety.privilege is not Privilege.STANDARD
                or safety.target_state_effect != "none"
                or (safety.outbound_network and not allow_network)
                or (metadata.network_effect != "none" and not allow_network)
                or (metadata.io_intensity == "heavy" and not allow_heavy_io)
                or metadata.sensitivity not in allowed_sensitivities
                or metadata.resource_class not in allowed_resources
                or metadata.estimated_cost_ms > remaining_budget_ms
                or not set(metadata.prerequisite_probe_ids) <= observed_probe_ids
                or (
                    metadata.target_kind is not None
                    and metadata.target_kind not in available_target_kinds
                )
            ):
                continue
            applicable.append(metadata)
        return tuple(applicable)
