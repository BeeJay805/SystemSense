import os

import pytest

from systemsense.packs.local_ai.gpu import WmiGpuBackend, collect_gpus
from systemsense.packs.local_ai.packages import current_packages
from systemsense.packs.local_ai.python import current_python_environment


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to collect live local-AI evidence",
)
def test_live_local_ai_metadata_collection_is_bounded() -> None:
    environment = current_python_environment()
    packages = current_packages(max_records=2048)
    gpus = collect_gpus(WmiGpuBackend().gpus(), max_records=8)

    assert environment.version
    assert len(packages) <= 2048
    assert len(gpus) <= 8
