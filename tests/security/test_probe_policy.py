from collections.abc import Mapping

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from systemsense.domain.ids import CaseId, TargetId
from systemsense.domain.probes import ProbeManifest
from systemsense.orchestration.catalog import CatalogError, ProbeCatalog
from systemsense.policy import PolicyDenied, ProbePolicy


class TargetReferenceParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: CaseId
    target_id: TargetId


class UnsafePathParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str


def manifest_data(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": 1,
        "probe_id": "application.file_identity",
        "version": 1,
        "implementation_id": "builtin.application.file_identity",
        "question": "What is the current identity of the registered target?",
        "safety": {
            "safety_class": "R1",
            "privilege": "standard",
            "target_state_effect": "none",
            "outbound_network": False,
            "self_writes": ["audit_record", "evidence_record"],
        },
        "input_model": "TargetReferenceParametersV1",
        "limits": {
            "timeout_ms": 3000,
            "max_output_bytes": 262144,
            "max_records": 1,
        },
        "category": "application",
    }
    values.update(overrides)
    return values


def registered_policy() -> tuple[ProbeCatalog, ProbePolicy]:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    catalog.register(ProbeManifest.model_validate(manifest_data()), TargetReferenceParameters)
    return catalog, ProbePolicy(catalog)


def test_policy_authorizes_registered_read_only_probe() -> None:
    _, policy = registered_policy()
    case_id = CaseId.new()
    target_id = TargetId.new()

    authorized = policy.authorize(
        "application.file_identity",
        {"case_id": str(case_id), "target_id": str(target_id)},
    )

    assert authorized.manifest.probe_id == "application.file_identity"
    assert authorized.parameters == TargetReferenceParameters(
        case_id=case_id,
        target_id=target_id,
    )


def test_policy_denies_unknown_probe() -> None:
    _, policy = registered_policy()

    with pytest.raises(PolicyDenied, match="unknown probe"):
        policy.authorize("unknown.probe", {})


def test_policy_rejects_unknown_parameters() -> None:
    _, policy = registered_policy()

    with pytest.raises(PolicyDenied, match="parameters"):
        policy.authorize(
            "application.file_identity",
            {
                "case_id": str(CaseId.new()),
                "target_id": str(TargetId.new()),
                "command": "cmd.exe /c whoami",
            },
        )


def test_catalog_rejects_untrusted_implementation() -> None:
    catalog = ProbeCatalog(trusted_implementation_ids=frozenset())
    manifest = ProbeManifest.model_validate(manifest_data())

    with pytest.raises(CatalogError, match="untrusted implementation"):
        catalog.register(manifest, TargetReferenceParameters)


def test_catalog_rejects_parameter_models_with_arbitrary_path_fields() -> None:
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    manifest = ProbeManifest.model_validate(manifest_data())

    with pytest.raises(CatalogError, match="forbidden parameter"):
        catalog.register(manifest, UnsafePathParameters)


@pytest.mark.parametrize(
    "unsafe_fields",
    [
        {"executable_path": "C:\\Windows\\System32\\cmd.exe"},
        {"arguments": ["/c", "whoami"]},
        {"shell": "powershell.exe"},
    ],
)
def test_manifest_rejects_executable_and_shell_fields(
    unsafe_fields: Mapping[str, object],
) -> None:
    data = manifest_data(**unsafe_fields)

    with pytest.raises(ValidationError):
        ProbeManifest.model_validate(data)


def test_manifest_rejects_mutation_class() -> None:
    data = manifest_data()
    safety = data["safety"]
    assert isinstance(safety, dict)
    safety["safety_class"] = "M1"

    with pytest.raises(ValidationError):
        ProbeManifest.model_validate(data)


def test_manifest_requires_resource_limits() -> None:
    data = manifest_data()
    del data["limits"]

    with pytest.raises(ValidationError):
        ProbeManifest.model_validate(data)


@pytest.mark.parametrize(
    "limits",
    [
        {"timeout_ms": 120001, "max_output_bytes": 1, "max_records": 1},
        {"timeout_ms": 1, "max_output_bytes": 10485761, "max_records": 1},
        {"timeout_ms": 1, "max_output_bytes": 1, "max_records": 100001},
    ],
)
def test_manifest_rejects_excessive_limits(limits: dict[str, int]) -> None:
    with pytest.raises(ValidationError):
        ProbeManifest.model_validate(manifest_data(limits=limits))


def test_policy_denies_elevated_probe_in_standard_runtime() -> None:
    data = manifest_data()
    safety = data["safety"]
    assert isinstance(safety, dict)
    safety["privilege"] = "elevated"
    catalog = ProbeCatalog(
        trusted_implementation_ids=frozenset({"builtin.application.file_identity"})
    )
    catalog.register(ProbeManifest.model_validate(data), TargetReferenceParameters)
    policy = ProbePolicy(catalog)

    with pytest.raises(PolicyDenied, match="privilege"):
        policy.authorize(
            "application.file_identity",
            {"case_id": str(CaseId.new()), "target_id": str(TargetId.new())},
        )
