from systemsense.packs.local_ai.cuda import assess_cuda_compatibility
from systemsense.packs.local_ai.gpu import GpuObservation, collect_gpus
from systemsense.packs.local_ai.packages import PackageObservation, collect_packages
from systemsense.packs.local_ai.python import current_python_environment


def test_gpu_identity_and_driver_are_bounded() -> None:
    gpu = GpuObservation(
        name="Fixture GPU",
        vendor="NVIDIA",
        driver_version="560.94",
        adapter_ram_bytes=8 * 1024**3,
        vendor_utility_available=True,
    )

    assert collect_gpus((gpu,), max_records=8)[0].driver_version == "560.94"


def test_current_python_environment_reports_runtime_without_importing_targets() -> None:
    environment = current_python_environment()

    assert environment.version
    assert environment.executable
    assert environment.implementation
    assert environment.architecture


def test_package_metadata_is_sorted_and_bounded() -> None:
    packages = (
        PackageObservation(name="torch", version="2.7.0"),
        PackageObservation(name="numpy", version="2.2.0"),
    )

    result = collect_packages(packages, max_records=1)

    assert result == (PackageObservation(name="numpy", version="2.2.0"),)


def test_cuda_compatibility_is_a_version_fact_not_a_diagnosis() -> None:
    result = assess_cuda_compatibility(
        driver_supported_cuda="12.4",
        framework="torch",
        framework_version="2.7.0",
        framework_cuda="12.1",
    )

    assert result.compatible is True
    assert result.framework == "torch"
    assert result.limitation == "numeric version comparison only"


def test_missing_cuda_metadata_produces_unknown_compatibility() -> None:
    result = assess_cuda_compatibility(
        driver_supported_cuda=None,
        framework="torch",
        framework_version="2.7.0",
        framework_cuda=None,
    )

    assert result.compatible is None
