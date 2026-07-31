"""Bounded target file identity and PE metadata."""

import hashlib
import importlib
import struct
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime

_MAX_HASH_BYTES = 2 * 1024**3


class SignatureState(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    UNSIGNED = "unsigned"
    UNKNOWN = "unknown"


class FileIdentity(FrozenModel):
    file_name: str = Field(min_length=1, max_length=255)
    byte_size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    version: str | None = Field(default=None, max_length=255)
    architecture: str
    signature: SignatureState
    captured_at: UtcDateTime
    limitations: tuple[str, ...] = ()


class FileMetadataBackend(Protocol):
    def version(self, path: Path) -> str | None: ...

    def signature(self, path: Path) -> SignatureState: ...


class StaticFileMetadataBackend:
    def __init__(self, *, version: str | None, signature: SignatureState) -> None:
        self._version = version
        self._signature = signature

    def version(self, path: Path) -> str | None:
        del path
        return self._version

    def signature(self, path: Path) -> SignatureState:
        del path
        return self._signature


def inspect_file(
    path: Path,
    metadata: FileMetadataBackend,
    *,
    captured_at: UtcDateTime,
) -> FileIdentity:
    file_size = path.stat().st_size
    if file_size > _MAX_HASH_BYTES:
        raise ValueError("target file exceeds hashing limit")
    digest = hashlib.sha256()
    with path.open("rb") as target:
        while chunk := target.read(1024 * 1024):
            digest.update(chunk)
    signature = metadata.signature(path)
    limitations = (
        ("signature verification unavailable",) if signature is SignatureState.UNKNOWN else ()
    )
    return FileIdentity(
        file_name=path.name,
        byte_size=file_size,
        sha256=digest.hexdigest(),
        version=metadata.version(path),
        architecture=_pe_architecture(path),
        signature=signature,
        captured_at=captured_at,
        limitations=limitations,
    )


def _pe_architecture(path: Path) -> str:
    with path.open("rb") as target:
        header = target.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            return "not_pe"
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
        if pe_offset > 16 * 1024 * 1024:
            return "invalid_pe"
        target.seek(pe_offset)
        pe_header = target.read(6)
    if len(pe_header) != 6 or pe_header[:4] != b"PE\x00\x00":
        return "invalid_pe"
    machine = struct.unpack_from("<H", pe_header, 4)[0]
    return {
        0x014C: "x86",
        0x8664: "x64",
        0xAA64: "arm64",
    }.get(machine, f"machine_0x{machine:04x}")


class _Win32Api(Protocol):
    def GetFileVersionInfo(self, path: str, sub_block: str) -> dict[str, int]: ...


class Win32FileMetadataBackend:
    def version(self, path: Path) -> str | None:
        try:
            module = cast("_Win32Api", importlib.import_module("win32api"))
            info = module.GetFileVersionInfo(str(path), "\\")
            most = int(info["FileVersionMS"])
            least = int(info["FileVersionLS"])
        except Exception:
            return None
        return f"{most >> 16}.{most & 0xFFFF}.{least >> 16}.{least & 0xFFFF}"

    def signature(self, path: Path) -> SignatureState:
        del path
        return SignatureState.UNKNOWN
