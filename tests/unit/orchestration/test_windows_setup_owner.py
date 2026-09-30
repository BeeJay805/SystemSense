"""Real owned Windows children, never the pytest process, join the setup Job."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job custody")

_HELPER = """
import json, os, subprocess, sys, time
from pathlib import Path
import psutil
from systemsense.orchestration.windows_setup_owner import WindowsSetupOwner
owner = WindowsSetupOwner()
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    close_fds=True, creationflags=subprocess.CREATE_NO_WINDOW | 4)
record = {'owner_pid': os.getpid(), 'owner_created': psutil.Process().create_time(),
          'child_pid': child.pid, 'child_created': psutil.Process(child.pid).create_time(),
          'release_with_live_child': owner.release_if_alone()}
Path(sys.argv[1]).write_text(json.dumps(record))
if sys.argv[2] in {'release', 'nested_cancel'}:
    if sys.argv[2] == 'nested_cancel':
        from systemsense.orchestration.windows_probe_job import WindowsProbeJob
        inner = WindowsProbeJob()
        inner.assign_suspended(child)
        inner.resume_assigned(child)
        inner.terminate_processes()
        assert inner.wait_until_empty(5)
        inner.close()
    else:
        child.terminate()
    child.wait(timeout=10)
    record['released_after_child_exit'] = owner.release_if_alone()
    Path(sys.argv[1]).write_text(json.dumps(record))
else:
    time.sleep(60)
"""


@pytest.mark.parametrize("mode", ["parent_loss", "release", "nested_cancel"])
def test_outer_job_covers_suspended_child_before_inner_assignment(
    tmp_path: Path, mode: str
) -> None:
    helper = tmp_path / "owned_setup_helper.py"
    helper.write_text(_HELPER)
    receipt = tmp_path / "receipt.json"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[3] / "src")
    owner_process: psutil.Process | None = None
    child_process: psutil.Process | None = None
    with (tmp_path / "stderr.log").open("wb") as errors:
        launcher = subprocess.Popen(
            [sys.executable, str(helper), str(receipt), mode],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=errors,
            env=env,
            close_fds=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            deadline = time.monotonic() + 10
            while not receipt.exists() and time.monotonic() < deadline:
                if launcher.poll() is not None:
                    pytest.fail((tmp_path / "stderr.log").read_text())
                time.sleep(0.02)
            if mode in {"release", "nested_cancel"}:
                assert launcher.wait(timeout=10) == 0
                record: dict[str, Any] = json.loads(receipt.read_text())
                assert record["release_with_live_child"] is False
                assert record["released_after_child_exit"] is True
                assert not psutil.pid_exists(record["child_pid"])
            else:
                record = json.loads(receipt.read_text())
                candidate_owner = psutil.Process(record["owner_pid"])
                assert candidate_owner.create_time() == record["owner_created"]
                assert candidate_owner.pid == launcher.pid or candidate_owner.ppid() == launcher.pid
                assert candidate_owner.cmdline()[-3:] == [str(helper), str(receipt), mode]
                owner_process = candidate_owner
                candidate_child = psutil.Process(record["child_pid"])
                assert candidate_child.create_time() == record["child_created"]
                child_process = candidate_child
                assert record["release_with_live_child"] is False
                owner_process.terminate()
                owner_process.wait(timeout=10)
                child_process.wait(timeout=10)
                launcher.wait(timeout=10)
                assert not child_process.is_running()
        finally:
            if owner_process is not None and owner_process.is_running():
                owner_process.terminate()
                owner_process.wait(timeout=10)
            if launcher.poll() is None:
                launcher.terminate()
                launcher.wait(timeout=10)
            if child_process is not None and child_process.is_running():
                child_process.terminate()
                child_process.wait(timeout=10)
