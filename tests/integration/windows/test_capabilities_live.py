import os
import platform
from datetime import timedelta

import pytest

from systemsense.platform.windows.capabilities import (
    CapabilityDetector,
    SystemCapabilityBackend,
)


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to run live Windows probes",
)
def test_live_windows_capabilities_do_not_fail_on_missing_optional_sources() -> None:
    assert platform.system() == "Windows"
    detector = CapabilityDetector(
        SystemCapabilityBackend(),
        cache_ttl=timedelta(minutes=5),
    )

    snapshot = detector.detect()

    assert snapshot.platform == "Windows"
    assert snapshot.windows_build
    assert snapshot.architecture
    assert snapshot.capabilities
