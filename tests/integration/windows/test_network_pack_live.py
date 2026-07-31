import os

import pytest

from systemsense.packs.network.adapters import PsutilAdapterBackend, collect_adapters
from systemsense.packs.network.connections import (
    PsutilNetworkConnectionBackend,
    collect_connections,
)
from systemsense.packs.network.routes import WmiRouteBackend, collect_routes


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to collect live network evidence",
)
def test_live_network_pack_reads_bounded_local_state() -> None:
    adapters = collect_adapters(PsutilAdapterBackend().adapters(), max_records=64)
    routes = collect_routes(WmiRouteBackend().routes(), max_records=256)
    connections = collect_connections(
        PsutilNetworkConnectionBackend().connections(),
        max_records=256,
    )

    assert len(adapters) <= 64
    assert len(routes) <= 256
    assert len(connections) <= 256
    assert adapters
