import pytest

from systemsense.inference.admission import AdmissionError, admit_resources


def test_admission_reserves_memory_and_does_not_evict_foreign_models() -> None:
    with pytest.raises(AdmissionError, match="GPU"):
        admit_resources(
            artifact_bytes=18_000_000_000,
            available_ram=32_000_000_000,
            gpu_free_bytes=8_000_000_000,
            selected_resident=False,
            allow_gpu=True,
        )


def test_selected_warm_model_requires_headroom_not_a_second_copy() -> None:
    admit_resources(
        artifact_bytes=18_000_000_000,
        available_ram=32_000_000_000,
        gpu_free_bytes=4_000_000_000,
        selected_resident=True,
        allow_gpu=True,
    )


def test_unknown_gpu_capacity_and_cpu_memory_pressure_fail_closed() -> None:
    with pytest.raises(AdmissionError):
        admit_resources(
            artifact_bytes=18_000_000_000,
            available_ram=32_000_000_000,
            gpu_free_bytes=None,
            selected_resident=False,
            allow_gpu=True,
        )
    with pytest.raises(AdmissionError):
        admit_resources(
            artifact_bytes=18_000_000_000,
            available_ram=2_000_000_000,
            gpu_free_bytes=None,
            selected_resident=False,
            allow_gpu=False,
        )
