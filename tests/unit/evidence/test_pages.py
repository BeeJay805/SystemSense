from systemsense.domain.ids import JsonValue
from systemsense.evidence.pages import fact_pages


def test_attention_pages_preserve_all_array_items_beyond_old_prefix_limit() -> None:
    processes: list[JsonValue] = [
        {"pid": i, "name": f"process-{i}", "metadata": "x" * 120} for i in range(128)
    ]
    pages = list(fact_pages({"processes": processes}))
    assert len(pages) > 1
    recovered = {key: value for page in pages for key, value in page.items()}
    assert recovered["processes.127"] == processes[-1]
    assert len(recovered) == 128


def test_attention_pages_do_not_clip_numeric_values() -> None:
    value: dict[str, JsonValue] = {"memory": {"bytes": 18446744073709551615, "missing": None}}
    assert list(fact_pages(value)) == [value]


def test_attention_pages_preserve_large_scalar_that_fits_context_bound() -> None:
    detail = "x" * 3000

    pages = list(fact_pages({"event": {"rendered_message": detail}}))

    recovered = {key: value for page in pages for key, value in page.items()}
    assert recovered["event.rendered_message"] == detail


def test_attention_pages_do_not_overwrite_long_or_unsafe_source_paths() -> None:
    shared = "segment" * 20
    first_name = f"{shared} first/value"
    second_name = f"{shared} second:value"
    values: dict[str, JsonValue] = {
        "root": {
            first_name: "a" * 1800,
            second_name: "b" * 1800,
        }
    }

    pages = list(fact_pages(values))

    recovered = {key: value for page in pages for key, value in page.items()}
    assert len(recovered) == 2
    assert len(set(recovered)) == 2
    wrappers = list(recovered.values())
    values_found: set[str] = set()
    paths_found: set[str] = set()
    for wrapper in wrappers:
        assert isinstance(wrapper, dict)
        wrapped_value = wrapper.get("value")
        source_path = wrapper.get("source_path")
        assert isinstance(wrapped_value, str)
        assert isinstance(source_path, str)
        values_found.add(wrapped_value)
        paths_found.add(source_path)
    assert values_found == {"a" * 1800, "b" * 1800}
    assert paths_found == {
        f'root.["{first_name}"]',
        f'root.["{second_name}"]',
    }
