import os
import sys
from pathlib import Path

import pytest

from systemsense.domain.time import utc_now
from systemsense.packs.application.files import (
    Win32FileMetadataBackend,
    inspect_file,
)
from systemsense.packs.application.processes import (
    PsutilProcessBackend,
    collect_matching_processes,
)


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_LIVE_WINDOWS") != "1",
    reason="set SYSTEMSENSE_LIVE_WINDOWS=1 to collect live application evidence",
)
def test_live_application_identity_and_current_process_are_observable() -> None:
    executable = os.path.realpath(sys.executable)
    identity = inspect_file(
        Path(executable),
        Win32FileMetadataBackend(),
        captured_at=utc_now(),
    )
    processes = collect_matching_processes(
        PsutilProcessBackend().snapshots(),
        executable_name=os.path.basename(executable),
    )

    assert identity.byte_size > 0
    assert identity.sha256
    assert any(process.pid == os.getpid() for process in processes)
