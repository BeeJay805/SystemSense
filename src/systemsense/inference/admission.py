"""Conservative local memory admission; never unload or interrupt another workload."""

import os
import shutil
import subprocess

GIB = 1024**3


class AdmissionError(RuntimeError):
    """Model inference is deferred because available memory is inadequate or unknown."""


def admit_resources(
    *,
    artifact_bytes: int,
    available_ram: int,
    gpu_free_bytes: int | None,
    selected_resident: bool,
    allow_gpu: bool,
) -> None:
    if available_ram < 4 * GIB:
        raise AdmissionError("Insufficient available system RAM for bounded local inference")
    if allow_gpu:
        required = 2 * GIB + (0 if selected_resident else artifact_bytes + GIB)
        if gpu_free_bytes is None or gpu_free_bytes < required:
            available = "unknown" if gpu_free_bytes is None else str(gpu_free_bytes // (1024**2))
            raise AdmissionError(
                f"GPU free {available} MiB below required {required // (1024**2)} MiB "
                f"({'resident' if selected_resident else 'cold'} model); no workload evicted"
            )
    elif not selected_resident and available_ram < artifact_bytes + 6 * GIB:
        raise AdmissionError("Insufficient available RAM for CPU model load plus reserve")


def gpu_free_memory(*, timeout_seconds: float) -> int | None:
    executable = shutil.which("nvidia-smi")
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            check=False,
            timeout=min(2, timeout_seconds),
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        lines = result.stdout.strip().splitlines()
        # Single-GPU admission is measured. Multi-GPU placement needs its own policy.
        if result.returncode != 0 or len(lines) != 1:
            return None
        return int(lines[0]) * 1024**2
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None
