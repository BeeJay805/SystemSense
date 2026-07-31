import os
import platform

import pytest

from systemsense.domain.time import utc_now
from systemsense.packs.core.resources import PsutilResourceBackend, collect_resources
from systemsense.packs.core.system import PsutilSystemBackend, collect_system_identity


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to collect live core evidence",
)
def test_live_core_pack_collects_read_only_local_state() -> None:
    assert platform.system() == "Windows"
    captured_at = utc_now()

    system = collect_system_identity(PsutilSystemBackend(), captured_at=captured_at)
    resources = collect_resources(PsutilResourceBackend(), captured_at=captured_at)

    assert system.os_name == "Windows"
    assert system.windows_build
    assert system.logical_cpu_count >= 1
    assert system.total_memory_bytes > 0
    assert 0 <= resources.cpu_percent <= 100
    assert resources.memory.total_bytes > 0
