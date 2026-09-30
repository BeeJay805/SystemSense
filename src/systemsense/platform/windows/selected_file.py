"""Read one UI-selected local file; expose metadata and validation codes, never content.

This module is an in-process primitive, not a path-accepting tool or HTTP endpoint.
Its caller owns the native selection grant and must keep paths/captures private.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import re
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, utc_now

MAX_SELECTED_FILE_BYTES = 256 * 1024
MAX_JSON_NESTING = 128
MAX_JSON_INTEGER_DIGITS = 4300
ReadOutcome = Literal[
    "read_ok", "read_denied", "missing", "too_large", "changed_during_read", "unsupported"
]
ErrorCode = Literal[
    "none",
    "path_not_supported",
    "not_regular_file",
    "reparse_point",
    "windows_unavailable",
    "read_denied",
    "missing",
    "too_large",
    "changed_during_read",
    "read_failed",
    "identity_mismatch",
    "invalid_utf8",
    "utf8_bom",
    "empty_document",
    "json_syntax",
    "non_finite_number",
    "nesting_limit",
    "number_limit",
    "read_unavailable",
]


class SelectedFileObservation(FrozenModel):
    schema_version: Literal[1] = 1
    outcome: ReadOutcome
    error_code: ErrorCode = "none"
    identity_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)
    modified_at: UtcDateTime | None = None
    collection_started_at: UtcDateTime
    collection_completed_at: UtcDateTime
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_capture(self) -> SelectedFileObservation:
        if self.collection_completed_at < self.collection_started_at:
            raise ValueError("selected_file_clock_rollback")
        if self.outcome == "read_ok" and (
            self.identity_sha256 is None
            or self.content_sha256 is None
            or self.modified_at is None
            or self.size_bytes is None
            or self.size_bytes > MAX_SELECTED_FILE_BYTES
            or self.error_code != "none"
        ):
            raise ValueError("selected_file_success_metadata_missing")
        if self.outcome != "read_ok" and self.content_sha256 is not None:
            raise ValueError("selected_file_unstable_hash")
        return self


class SelectedFileCheck(FrozenModel):
    schema_version: Literal[1] = 1
    stage: Literal["utf8", "json"]
    outcome: Literal["valid_utf8", "invalid_utf8", "valid_json", "invalid_json", "read_unavailable"]
    error_code: ErrorCode = "none"
    identity_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    content_sha256: str | None = Field(pattern=r"^[0-9a-f]{64}$")
    collection_started_at: UtcDateTime
    collection_completed_at: UtcDateTime
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)


class SelectedFileCapture:
    """Immutable private bytes with a separately serializable observation.

    Deliberately not a dataclass/Pydantic object: generic asdict/model_dump must
    not accidentally export the captured document. Only observation is public.
    """

    __slots__ = ("__contents", "_observation")
    __contents: bytes | None
    _observation: SelectedFileObservation

    def __init__(self, observation: SelectedFileObservation, contents: bytes | None) -> None:
        if contents is not None and (
            type(contents) is not bytes
            or observation.outcome != "read_ok"
            or len(contents) > MAX_SELECTED_FILE_BYTES
            or len(contents) != observation.size_bytes
            or hashlib.sha256(contents).hexdigest() != observation.content_sha256
        ):
            raise ValueError("capture_binding_invalid")
        if contents is None and observation.outcome == "read_ok":
            raise ValueError("capture_bytes_missing")
        object.__setattr__(self, "_observation", observation)
        object.__setattr__(self, "_SelectedFileCapture__contents", contents)

    @property
    def observation(self) -> SelectedFileObservation:
        return self._observation

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("selected_file_capture_is_immutable")

    def __repr__(self) -> str:
        return f"SelectedFileCapture(observation={self.observation!r})"

    def __getstate__(self) -> object:
        raise TypeError("selected_file_capture_is_private")

    def _private_bytes(self) -> bytes | None:
        return self.__contents


@dataclass(frozen=True)
class _FileState:
    identity_sha256: str
    size_bytes: int
    modified_ticks: int
    changed_ticks: int


class _FileReader(Protocol):
    def state(self) -> _FileState: ...
    def read(self, limit: int) -> bytes: ...


class _ReadFailure(Exception):
    def __init__(self, outcome: ReadOutcome, code: ErrorCode) -> None:
        super().__init__(code)
        self.outcome: ReadOutcome = outcome
        self.code: ErrorCode = code


def _path_components(path: str) -> tuple[str, tuple[str, ...]]:
    # Refuse alternate namespaces, UNC, relative paths, ADS and DOS aliases
    # before any filesystem call. Native components are opened one at a time.
    if (
        len(path) > 32700
        or not re.match(r"^[A-Za-z]:\\", path)
        or any(character in path for character in ("/", "\x00"))
        or ":" in path[2:]
    ):
        raise _ReadFailure("unsupported", "path_not_supported")
    components = tuple(path[3:].split("\\"))
    if len(components) > 64:
        raise _ReadFailure("unsupported", "path_not_supported")
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or component[-1] in {".", " "}
            or len(component.encode("utf-16-le", errors="surrogatepass")) > 510
            or any(
                ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF or character in '<>"|?*'
                for character in component
            )
            or component.partition(".")[0].rstrip(" ").upper()
            in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                "CONIN$",
                "CONOUT$",
                *(prefix + digit for prefix in ("COM", "LPT") for digit in "123456789¹²³"),
            }
        ):
            raise _ReadFailure("unsupported", "path_not_supported")
    return path[:3], components


def capture_selected_file(
    path: str, *, expected_identity_sha256: str | None = None
) -> SelectedFileCapture:
    """Capture the explicitly selected target once, optionally enforcing a prior identity.

    Checks later reuse these immutable bytes; they never reopen a supplied path.
    Stable means unchanged identity/size/write/change metadata over this read,
    not an atomic filesystem snapshot or proof against a privileged writer.
    """
    started = utc_now()
    initial: _FileState | None = None
    contents: bytes | None = None
    outcome: ReadOutcome = "read_ok"
    error_code: ErrorCode = "none"
    try:
        root, components = _path_components(path)
        with _open_selected_file(root, components) as source:
            initial = source.state()
            if (
                expected_identity_sha256 is not None
                and initial.identity_sha256 != expected_identity_sha256
            ):
                raise _ReadFailure("changed_during_read", "identity_mismatch")
            if initial.size_bytes > MAX_SELECTED_FILE_BYTES:
                raise _ReadFailure("too_large", "too_large")
            contents = source.read(MAX_SELECTED_FILE_BYTES)
            final = source.state()
            if initial != final or len(contents) != initial.size_bytes:
                raise _ReadFailure("changed_during_read", "changed_during_read")
    except _ReadFailure as error:
        outcome, error_code = error.outcome, error.code
        contents = None
    completed = utc_now()
    if completed < started:
        raise ValueError("selected_file_clock_rollback")
    observation = SelectedFileObservation(
        outcome=outcome,
        error_code=error_code,
        identity_sha256=None if initial is None else initial.identity_sha256,
        size_bytes=None if initial is None else initial.size_bytes,
        modified_at=None if initial is None else _file_time(initial.modified_ticks),
        collection_started_at=started,
        collection_completed_at=completed,
        content_sha256=None if contents is None else hashlib.sha256(contents).hexdigest(),
    )
    return SelectedFileCapture(observation, contents)


def _file_time(ticks: int) -> datetime:
    return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=ticks // 10)


def _check(
    capture: SelectedFileCapture,
    *,
    stage: Literal["utf8", "json"],
    outcome: Literal[
        "valid_utf8", "invalid_utf8", "valid_json", "invalid_json", "read_unavailable"
    ],
    code: ErrorCode = "none",
    line: int | None = None,
    column: int | None = None,
) -> SelectedFileCheck:
    return SelectedFileCheck(
        stage=stage,
        outcome=outcome,
        error_code=code,
        identity_sha256=capture.observation.identity_sha256,
        content_sha256=capture.observation.content_sha256,
        collection_started_at=capture.observation.collection_started_at,
        collection_completed_at=capture.observation.collection_completed_at,
        line=line,
        column=column,
    )


def check_utf8(capture: SelectedFileCapture) -> SelectedFileCheck:
    """Pure strict UTF-8 check of the original private captured bytes."""
    contents = capture._private_bytes()  # pyright: ignore[reportPrivateUsage]
    if contents is None:
        return _check(capture, stage="utf8", outcome="read_unavailable", code="read_unavailable")
    try:
        contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _check(capture, stage="utf8", outcome="invalid_utf8", code="invalid_utf8")
    return _check(capture, stage="utf8", outcome="valid_utf8")


class _NonFiniteNumber(ValueError):
    pass


def _reject_constant(_value: str) -> object:
    raise _NonFiniteNumber


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise _NonFiniteNumber
    return number


def _bounded_int(value: str) -> int:
    if len(value.lstrip("-")) > MAX_JSON_INTEGER_DIGITS:
        raise ValueError("number_limit")
    return int(value)


def _exceeds_nesting_limit(document: str) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in document:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                return True
        elif character in "]}":
            depth -= 1
    return False


def check_json(capture: SelectedFileCapture) -> SelectedFileCheck:
    """Pure bounded overall parse attempt; parser messages and document values stay private."""
    contents = capture._private_bytes()  # pyright: ignore[reportPrivateUsage]
    if contents is None:
        return _check(capture, stage="json", outcome="read_unavailable", code="read_unavailable")
    try:
        document = contents.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _check(capture, stage="json", outcome="invalid_utf8", code="invalid_utf8")
    if document.startswith("\ufeff"):
        return _check(
            capture, stage="json", outcome="invalid_json", code="utf8_bom", line=1, column=1
        )
    if not document.strip(" \t\r\n"):
        return _check(
            capture, stage="json", outcome="invalid_json", code="empty_document", line=1, column=1
        )
    if _exceeds_nesting_limit(document):
        return _check(capture, stage="json", outcome="invalid_json", code="nesting_limit")
    try:
        json.loads(
            document,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            parse_int=_bounded_int,
        )
    except json.JSONDecodeError as error:
        return _check(
            capture,
            stage="json",
            outcome="invalid_json",
            code="json_syntax",
            line=error.lineno,
            column=error.colno,
        )
    except _NonFiniteNumber:
        return _check(capture, stage="json", outcome="invalid_json", code="non_finite_number")
    except RecursionError:
        return _check(capture, stage="json", outcome="invalid_json", code="nesting_limit")
    except ValueError:
        return _check(capture, stage="json", outcome="invalid_json", code="number_limit")
    return _check(capture, stage="json", outcome="valid_json")


# Windows structure definitions use fixed-width fields, including on 64-bit hosts.
class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_void_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint32),
        ("RootDirectory", ctypes.c_void_p),
        ("ObjectName", ctypes.POINTER(_UnicodeString)),
        ("Attributes", ctypes.c_uint32),
        ("SecurityDescriptor", ctypes.c_void_p),
        ("SecurityQualityOfService", ctypes.c_void_p),
    ]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]


class _BasicInfo(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_int64),
        ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64),
        ("ChangeTime", ctypes.c_int64),
        ("FileAttributes", ctypes.c_uint32),
    ]


class _FileIdInfo(ctypes.Structure):
    _fields_ = [("VolumeSerialNumber", ctypes.c_uint64), ("FileId", ctypes.c_ubyte * 16)]


def _windows_error(code: int) -> _ReadFailure:
    if code in {2, 3}:
        return _ReadFailure("missing", "missing")
    if code in {5, 32, 33}:
        return _ReadFailure("read_denied", "read_denied")
    if code in {4390, 4392, 4393, 1920, 681}:
        return _ReadFailure("unsupported", "reparse_point")
    if code == 267:
        return _ReadFailure("unsupported", "not_regular_file")
    return _ReadFailure("unsupported", "read_failed")


class _WindowsFile:
    def __init__(self) -> None:
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.native = ctypes.WinDLL("ntdll", use_last_error=True)
        self.handle: int | None = None
        self.kernel.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self.kernel.CreateFileW.restype = ctypes.c_void_p
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.restype = ctypes.c_int
        self.kernel.GetFileInformationByHandleEx.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.kernel.GetFileInformationByHandleEx.restype = ctypes.c_int
        self.kernel.GetFileSizeEx.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int64)]
        self.kernel.GetFileSizeEx.restype = ctypes.c_int
        self.kernel.GetFileType.argtypes = [ctypes.c_void_p]
        self.kernel.GetFileType.restype = ctypes.c_uint32
        self.kernel.GetFinalPathNameByHandleW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        self.kernel.GetFinalPathNameByHandleW.restype = ctypes.c_uint32
        self.kernel.ReadFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self.kernel.ReadFile.restype = ctypes.c_int
        self.native.NtCreateFile.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_uint32,
            ctypes.POINTER(_ObjectAttributes),
            ctypes.POINTER(_IoStatusBlock),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self.native.NtCreateFile.restype = ctypes.c_int32
        self.native.RtlNtStatusToDosError.argtypes = [ctypes.c_int32]
        self.native.RtlNtStatusToDosError.restype = ctypes.c_uint32

    def close(self) -> None:
        if self.handle is not None:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def _basic(self) -> _BasicInfo:
        basic = _BasicInfo()
        if not self.kernel.GetFileInformationByHandleEx(
            self.handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)
        ):
            raise _windows_error(ctypes.get_last_error())
        if basic.FileAttributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            raise _ReadFailure("unsupported", "reparse_point")
        return basic

    def open(self, root: str, components: tuple[str, ...]) -> None:
        # Root is a validated drive root. Its GUID path must identify a local volume.
        self.handle = self.kernel.CreateFileW(root, 0x100080, 7, None, 3, 0x02200000, None)
        if self.handle in (None, ctypes.c_void_p(-1).value):
            self.handle = None
            raise _windows_error(ctypes.get_last_error())
        self._basic()
        volume = ctypes.create_unicode_buffer(128)
        count = self.kernel.GetFinalPathNameByHandleW(self.handle, volume, len(volume), 1)
        if not 0 < count < len(volume) or not volume.value.startswith("\\\\?\\Volume{"):
            raise _ReadFailure("unsupported", "path_not_supported")
        for index, component in enumerate(components):
            leaf = index == len(components) - 1
            name = ctypes.create_unicode_buffer(component)
            length = len(component.encode("utf-16-le"))
            unicode_name = _UnicodeString(length, length + 2, ctypes.addressof(name))
            attributes = _ObjectAttributes(
                ctypes.sizeof(_ObjectAttributes),
                self.handle,
                ctypes.pointer(unicode_name),
                0x40,
                None,
                None,
            )
            status_block = _IoStatusBlock()
            opened = ctypes.c_void_p()
            # FILE_OPEN only, no write access. Open each single component without
            # reparse processing, then verify its handle before traversing further.
            status = self.native.NtCreateFile(
                ctypes.byref(opened),
                0x100080 | (1 if leaf else 0),
                ctypes.byref(attributes),
                ctypes.byref(status_block),
                None,
                0,
                7,
                1,
                0x200020,
                None,
                0,
            )
            if status < 0:
                raise _windows_error(self.native.RtlNtStatusToDosError(status))
            self.close()
            self.handle = opened.value
            basic = self._basic()
            if self.kernel.GetFileType(self.handle) != 1:
                raise _ReadFailure("unsupported", "not_regular_file")
            is_directory = bool(basic.FileAttributes & 0x10)
            if is_directory == leaf:
                raise _ReadFailure("unsupported", "not_regular_file")

    def state(self) -> _FileState:
        basic = self._basic()
        if basic.FileAttributes & 0x10:
            raise _ReadFailure("unsupported", "not_regular_file")
        identity = _FileIdInfo()
        if not self.kernel.GetFileInformationByHandleEx(
            self.handle, 18, ctypes.byref(identity), ctypes.sizeof(identity)
        ):
            raise _windows_error(ctypes.get_last_error())
        size = ctypes.c_int64()
        if not self.kernel.GetFileSizeEx(self.handle, ctypes.byref(size)):
            raise _windows_error(ctypes.get_last_error())
        identity_bytes = identity.VolumeSerialNumber.to_bytes(8, "little") + bytes(identity.FileId)
        return _FileState(
            hashlib.sha256(identity_bytes).hexdigest(),
            size.value,
            basic.LastWriteTime,
            basic.ChangeTime,
        )

    def read(self, limit: int) -> bytes:
        parts: list[bytes] = []
        remaining = limit
        while remaining:
            buffer = ctypes.create_string_buffer(min(remaining, 64 * 1024))
            count = ctypes.c_uint32()
            if not self.kernel.ReadFile(
                self.handle, buffer, len(buffer), ctypes.byref(count), None
            ):
                raise _windows_error(ctypes.get_last_error())
            if not count.value:
                break
            parts.append(buffer.raw[: count.value])
            remaining -= count.value
        return b"".join(parts)


@contextmanager
def _open_selected_file(root: str, components: tuple[str, ...]) -> Generator[_FileReader]:
    if os.name != "nt":
        raise _ReadFailure("unsupported", "windows_unavailable")
    source = _WindowsFile()
    try:
        source.open(root, components)
        yield source
    finally:
        source.close()
