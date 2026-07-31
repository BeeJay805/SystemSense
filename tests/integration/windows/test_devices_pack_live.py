import os

import pytest

from systemsense.packs.devices.pnp import WmiDeviceBackend, collect_devices


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to collect live device evidence",
)
def test_live_device_collection_is_bounded() -> None:
    devices = collect_devices(WmiDeviceBackend().devices(), max_records=256)

    assert len(devices) <= 256
    assert all(device.instance_id for device in devices)
