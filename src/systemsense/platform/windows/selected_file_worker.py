"""Fixed private child protocol for one native-selected file capture.

The base64 bytes in this pipe are private transport, never evidence or model input.
"""

from __future__ import annotations

import base64
import sys

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.platform.windows.selected_file import (
    MAX_SELECTED_FILE_BYTES,
    SelectedFileCapture,
    SelectedFileObservation,
    capture_selected_file,
)

MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 400 * 1024


class NativeFileRequest(FrozenModel):
    selected_path: str = Field(min_length=1, max_length=32700, strict=True)


class NativeFileResponse(FrozenModel):
    observation: SelectedFileObservation
    contents_base64: str | None = Field(
        default=None, max_length=4 * ((MAX_SELECTED_FILE_BYTES + 2) // 3), repr=False
    )

    def private_capture(self) -> SelectedFileCapture:
        contents = (
            None
            if self.contents_base64 is None
            else base64.b64decode(self.contents_base64, validate=True)
        )
        return SelectedFileCapture(self.observation, contents)


def _encode_private_capture(capture: SelectedFileCapture) -> bytes:
    # This is the sole private transport boundary; only observation may be persisted.
    contents = capture._private_bytes()  # pyright: ignore[reportPrivateUsage]
    response = NativeFileResponse(
        observation=capture.observation,
        contents_base64=None if contents is None else base64.b64encode(contents).decode("ascii"),
    )
    encoded = response.model_dump_json().encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        raise ValueError("private_capture_response_limit")
    return encoded


def main() -> int:
    """Accept exactly one bounded request on stdin, with no paths in argv or stderr."""
    try:
        encoded = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(encoded) > MAX_REQUEST_BYTES:
            return 2
        request = NativeFileRequest.model_validate_json(encoded)
        response = _encode_private_capture(capture_selected_file(request.selected_path))
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # A traceback could expose the private selected path or bytes.
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
