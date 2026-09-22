from pathlib import Path

import pytest

from systemsense.inference.token_budget import TokenBudgetError, count_input_tokens


def test_without_tokenizer_uses_conservative_bytes_not_optimistic_word_estimate() -> None:
    assert count_input_tokens("abc\u00e9", path=None, digest=None) == 261


def test_tokenizer_requires_pinned_local_artifact(tmp_path: Path) -> None:
    with pytest.raises(TokenBudgetError, match="digest"):
        count_input_tokens("test", path=tmp_path / "absent.json", digest=None)
    with pytest.raises(TokenBudgetError, match="local file"):
        count_input_tokens("test", path=tmp_path / "absent.json", digest="a" * 64)
