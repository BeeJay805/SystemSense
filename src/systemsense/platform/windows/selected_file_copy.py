"""Create one exact native-approved JSON copy, without reopening its source.

This synchronous primitive belongs inside an owned, deadline-bounded helper.
Approval, cancellation, and durable at-most-once execution belong to its caller.
Paths and payloads are private input only; results contain bounded metadata.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import re
from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.platform.windows import selected_file
from systemsense.platform.windows.selected_file import (
    MAX_SELECTED_FILE_BYTES,
    SelectedFileCheck,
    SelectedFileObservation,
    capture_selected_file,
    check_json,
)

# Deliberate reuse of this package's handle traversal and strict parser internals.
# pyright: reportPrivateUsage=false

CopyError = Literal[
    "none",
    "invalid_payload",
    "too_large",
    "hash_mismatch",
    "invalid_json",
    "path_not_supported",
    "destination_exists",
    "parent_missing",
    "create_denied",
    "create_failed",
    "write_failed",
    "verification_failed",
    "windows_unavailable",
]


class SelectedFileCopyResult(FrozenModel):
    schema_version: Literal[1] = 1
    created: bool
    outcome: Literal["verified", "not_created", "created_unverified"]
    error_code: CopyError
    expected_content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    expected_size_bytes: int | None = Field(default=None, ge=0, le=MAX_SELECTED_FILE_BYTES)
    created_identity_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    started_at: UtcDateTime
    completed_at: UtcDateTime
    verification: SelectedFileObservation | None = None
    verification_check: SelectedFileCheck | None = None

    @model_validator(mode="after")
    def validate_result(self) -> SelectedFileCopyResult:
        if self.completed_at < self.started_at:
            raise ValueError("copy_clock_rollback")
        if self.created != (self.outcome != "not_created"):
            raise ValueError("copy_creation_outcome_mismatch")
        if self.outcome == "verified" and (
            self.error_code != "none"
            or self.created_identity_sha256 is None
            or self.expected_content_sha256 is None
            or self.expected_size_bytes is None
            or self.verification is None
            or self.verification.outcome != "read_ok"
            or self.verification.identity_sha256 != self.created_identity_sha256
            or self.verification.content_sha256 != self.expected_content_sha256
            or self.verification.size_bytes != self.expected_size_bytes
            or not self.started_at
            <= self.verification.collection_started_at
            <= self.verification.collection_completed_at
            <= self.completed_at
            or self.verification_check is None
            or self.verification_check.outcome != "valid_json"
            or self.verification_check.stage != "json"
            or self.verification_check.identity_sha256 != self.created_identity_sha256
            or self.verification_check.content_sha256 != self.expected_content_sha256
            or self.verification_check.collection_started_at
            != self.verification.collection_started_at
            or self.verification_check.collection_completed_at
            != self.verification.collection_completed_at
        ):
            raise ValueError("copy_verification_binding_invalid")
        if self.outcome != "verified" and self.error_code == "none":
            raise ValueError("copy_failure_code_missing")
        return self


class _CopyFailure(Exception):
    def __init__(self, code: CopyError) -> None:
        super().__init__(code)
        self.code: CopyError = code


def _canonical_name(source: selected_file._WindowsFile, handle: int | None) -> str:
    value = ctypes.create_unicode_buffer(32768)
    length = source.kernel.GetFinalPathNameByHandleW(handle, value, len(value), 1)
    if not 0 < length < len(value):
        raise _CopyFailure("path_not_supported")
    return value.value


def _verify_parent_name(parent: selected_file._WindowsFile, components: tuple[str, ...]) -> None:
    root_handle = parent._ancestors[0] if parent._ancestors else parent.handle
    root_name = _canonical_name(parent, root_handle)
    # Reject drive substitutions and 8.3 aliases, in addition to lexical aliases
    # rejected by _path_components. These checks inspect already held handles.
    if re.fullmatch(r"\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\", root_name) is None:
        raise _CopyFailure("path_not_supported")
    expected = root_name + "\\".join(components)
    if _canonical_name(parent, parent.handle).casefold() != expected.casefold():
        raise _CopyFailure("path_not_supported")


class _CopyWriter(selected_file._WindowsFile):
    def __init__(self) -> None:
        super().__init__()
        self.created = False
        self.kernel.WriteFile.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self.kernel.WriteFile.restype = ctypes.c_int
        self.kernel.FlushFileBuffers.argtypes = [ctypes.c_void_p]
        self.kernel.FlushFileBuffers.restype = ctypes.c_int

    def create(self, parent: selected_file._WindowsFile, component: str) -> None:
        name = ctypes.create_unicode_buffer(component)
        length = len(component.encode("utf-16-le"))
        unicode_name = selected_file._UnicodeString(length, length + 2, ctypes.addressof(name))
        attributes = selected_file._ObjectAttributes(
            ctypes.sizeof(selected_file._ObjectAttributes),
            parent.handle,
            ctypes.pointer(unicode_name),
            0x40,
            None,
            None,
        )
        status_block = selected_file._IoStatusBlock()
        opened = ctypes.c_void_p()
        status = self.native.NtCreateFile(
            ctypes.byref(opened),
            0x100082,  # SYNCHRONIZE | READ_ATTRIBUTES | WRITE_DATA
            ctypes.byref(attributes),
            ctypes.byref(status_block),
            None,
            0x80,  # FILE_ATTRIBUTE_NORMAL
            0,  # Exclusive until write and metadata collection finish.
            2,  # FILE_CREATE: collision fails; never open/overwrite an existing file.
            0x200060,  # OPEN_REPARSE_POINT | SYNCHRONOUS_IO_NONALERT | NON_DIRECTORY_FILE
            None,
            0,
        )
        if status < 0:
            code = self.native.RtlNtStatusToDosError(status)
            # STATUS_FILE_IS_A_DIRECTORY maps to access denied at the Win32 layer.
            if code in {80, 183} or status & 0xFFFFFFFF == 0xC00000BA:
                raise _CopyFailure("destination_exists")
            if code in {5, 32, 33}:
                raise _CopyFailure("create_denied")
            raise _CopyFailure("create_failed")
        self.handle = opened.value
        # Set before any fallible metadata/write/verification operation. A failure
        # after this point must never invite automatic retry or partial-file deletion.
        self.created = True
        if status_block.Information != 2 or self.kernel.GetFileType(self.handle) != 1:
            raise _CopyFailure("write_failed")

    def write(self, contents: bytes) -> None:
        offset = 0
        while offset < len(contents):
            chunk = contents[offset : offset + 64 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            count = ctypes.c_uint32()
            if not self.kernel.WriteFile(
                self.handle, buffer, len(chunk), ctypes.byref(count), None
            ) or not 0 < count.value <= len(chunk):
                raise _CopyFailure("write_failed")
            offset += count.value
        if not self.kernel.FlushFileBuffers(self.handle):
            raise _CopyFailure("write_failed")


def create_selected_file_copy(
    destination_path: str, contents: bytes, expected_sha256: str
) -> SelectedFileCopyResult:
    """Create once, then independently verify identity, bytes, and size after close.

    A successful result proves one bounded verification window, not continuing
    filesystem ownership or crash/power-loss durability. Any created result is
    terminal for this grant, including write failures and uncertain verification.
    """
    started = utc_now()
    identity: str | None = None
    verification: SelectedFileObservation | None = None
    verification_check: SelectedFileCheck | None = None
    created = False
    expected = expected_sha256 if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) else None
    size = (
        len(contents)
        if type(contents) is bytes and len(contents) <= MAX_SELECTED_FILE_BYTES
        else None
    )
    error: CopyError = "none"
    try:
        if type(contents) is not bytes:
            raise _CopyFailure("invalid_payload")
        if len(contents) > MAX_SELECTED_FILE_BYTES:
            raise _CopyFailure("too_large")
        if expected is None or hashlib.sha256(contents).hexdigest() != expected:
            raise _CopyFailure("hash_mismatch")
        if selected_file._validate_json_bytes(contents)[0] != "valid_json":
            raise _CopyFailure("invalid_json")
        root, components = selected_file._path_components(destination_path)
        if os.name != "nt":
            raise _CopyFailure("windows_unavailable")
        parent = selected_file._WindowsFile()
        writer = _CopyWriter()
        try:
            parent.open(root, components[:-1], directory=True, retain_ancestors=True)
            _verify_parent_name(parent, components[:-1])
            writer.create(parent, components[-1])
            identity = writer.state().identity_sha256
            writer.write(contents)
            if writer.state().size_bytes != len(contents):
                raise _CopyFailure("write_failed")
        finally:
            created = writer.created
            writer.close()
            parent.close()
        independently_read = capture_selected_file(
            destination_path, expected_identity_sha256=identity
        )
        verification = independently_read.observation
        verification_check = check_json(independently_read)
        if (
            verification.outcome != "read_ok"
            or verification.identity_sha256 != identity
            or verification.content_sha256 != expected
            or verification.size_bytes != size
            or verification_check.outcome != "valid_json"
        ):
            raise _CopyFailure("verification_failed")
    except _CopyFailure as failure:
        error = failure.code
    except selected_file._ReadFailure as failure:
        error = (
            "write_failed"
            if created
            else "parent_missing"
            if failure.outcome == "missing"
            else "create_denied"
            if failure.outcome == "read_denied"
            else "path_not_supported"
        )
    except OSError:
        error = "write_failed" if created else "create_failed"
    return SelectedFileCopyResult(
        created=created,
        outcome="verified"
        if error == "none"
        else "created_unverified"
        if created
        else "not_created",
        error_code=error,
        expected_content_sha256=expected,
        expected_size_bytes=size,
        created_identity_sha256=identity,
        started_at=started,
        completed_at=utc_now(),
        verification=verification,
        verification_check=verification_check,
    )
