"""Private one-shot create-only copy; no source path, shell or child execution."""

from __future__ import annotations

import base64
import sys

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.platform.windows.selected_file_copy import create_selected_file_copy


class NativeCopyRequest(FrozenModel):
    destination_path: str = Field(min_length=1, max_length=32700, strict=True, repr=False)
    contents_base64: str = Field(max_length=349528, repr=False)
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def main() -> int:
    try:
        encoded = sys.stdin.buffer.read(600 * 1024 + 1)
        if len(encoded) > 600 * 1024:
            return 2
        request = NativeCopyRequest.model_validate_json(encoded)
        result = create_selected_file_copy(
            request.destination_path,
            base64.b64decode(request.contents_base64, validate=True),
            request.output_sha256,
        )
        sys.stdout.buffer.write(result.model_dump_json().encode("utf-8"))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
