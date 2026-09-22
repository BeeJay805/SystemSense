"""Offline pinned tokenizer counting, with a conservative no-dependency fallback."""

import hashlib
import importlib
from functools import lru_cache
from pathlib import Path
from typing import Protocol, cast


class TokenBudgetError(ValueError):
    """The input cannot be admitted without risking silent context loss."""


class _Encoding(Protocol):
    @property
    def ids(self) -> list[int]: ...


class _Tokenizer(Protocol):
    def encode(self, sequence: str, *, add_special_tokens: bool = True) -> _Encoding: ...


class _TokenizerType(Protocol):
    def from_file(self, path: str) -> _Tokenizer: ...


@lru_cache(maxsize=4)
def _load(path: Path, digest: str) -> _Tokenizer:
    if not path.is_absolute() or not path.is_file() or path.stat().st_size > 32_000_000:
        raise TokenBudgetError("tokenizer must be a bounded local file")
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise TokenBudgetError("tokenizer artifact digest mismatch")
    try:
        module = importlib.import_module("tokenizers")
        tokenizer_type = cast(_TokenizerType, cast(object, module.Tokenizer))
        return tokenizer_type.from_file(str(path))
    except Exception as error:
        raise TokenBudgetError("pinned local tokenizer is unavailable") from error


def count_input_tokens(text: str, *, path: Path | None, digest: str | None) -> int:
    # Reserve chat-template/control framing, which is not part of the supplied text.
    if path is None:
        return len(text.encode("utf-8")) + 256
    if digest is None:
        raise TokenBudgetError("local tokenizer requires an artifact digest")
    return len(_load(path, digest).encode(text, add_special_tokens=False).ids) + 256
