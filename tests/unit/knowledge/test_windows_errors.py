import json

import pytest

from systemsense.knowledge.windows_errors import (
    WindowsErrorCatalog,
    WindowsErrorNamespace,
    WindowsErrorSource,
)


@pytest.fixture
def catalog() -> WindowsErrorCatalog:
    constants = {
        "ERROR_ACCESS_DENIED": 5,
        "ERROR_FILE_NOT_FOUND": 2,
        "ERROR_SERVICE_NOT_ACTIVE": 1062,
        "WSAEADDRINUSE": 10048,
        "DNS_ERROR_RCODE_NAME_ERROR": 9003,
        "E_ACCESSDENIED": -2147024891,
        "FACILITY_WIN32": 7,
        "FORMAT_MESSAGE_FROM_SYSTEM": 0x1000,
        "EVENTLOG_ERROR_TYPE": 1,
        "ERROR_BOOLEAN_SENTINEL": True,
    }
    messages = {
        5: "Access is denied.\r\n",
        10048: "Only one usage of each socket address is normally permitted.\r\n",
    }
    return WindowsErrorCatalog.from_constants(
        constants,
        message_resolver=lambda code: messages.get(code),
        source=WindowsErrorSource(
            catalog_provider="fixture.winerror",
            catalog_version="1",
            message_provider="fixture FormatMessage replay",
            os_version="fixture Windows",
            runtime_observed=False,
        ),
    )


def test_typed_win32_lookup_returns_aliases_message_provenance_and_mapping(
    catalog: WindowsErrorCatalog,
) -> None:
    result = catalog.lookup_win32(10048)

    assert result is not None
    assert result.namespace is WindowsErrorNamespace.WIN32
    assert result.win32_code == 10048
    assert result.hresult is None
    assert result.constant_names == ("WSAEADDRINUSE",)
    assert result.message == "Only one usage of each socket address is normally permitted."
    assert result.knowledge_node_ids == ("kn_port_conflict",)
    assert "does not prove" in result.mechanism_note
    assert result.source.catalog_provider == "fixture.winerror"
    json.dumps(result.model_dump(mode="json"))


def test_hresult_from_win32_maps_only_exact_facility_seven_values(
    catalog: WindowsErrorCatalog,
) -> None:
    result = catalog.lookup_hresult("0x80070005")

    assert result is not None
    assert result.namespace is WindowsErrorNamespace.HRESULT
    assert result.win32_code == 5
    assert result.hresult == "0x80070005"
    assert result.constant_names == ("E_ACCESSDENIED", "ERROR_ACCESS_DENIED")
    assert catalog.lookup_hresult("0x80004005") is None
    assert catalog.lookup_hresult("0x00070005") is None
    assert catalog.lookup_hresult("80070005") is None


def test_symbol_lookup_accepts_exact_error_symbols_and_rejects_flags(
    catalog: WindowsErrorCatalog,
) -> None:
    assert catalog.lookup_symbol("ERROR_ACCESS_DENIED") is not None
    alias = catalog.lookup_symbol("E_ACCESSDENIED")
    assert alias is not None
    assert alias.namespace is WindowsErrorNamespace.HRESULT
    assert catalog.lookup_symbol("FACILITY_WIN32") is None
    assert catalog.lookup_symbol("FORMAT_MESSAGE_FROM_SYSTEM") is None
    assert catalog.lookup_symbol("error_access_denied") is None
    assert catalog.lookup_symbol("ERROR_BOOLEAN_SENTINEL") is None


def test_text_retrieval_requires_explicit_typed_namespaces(catalog: WindowsErrorCatalog) -> None:
    text = (
        "Win32 error 5 followed HRESULT 0x80070005 and WSAEADDRINUSE. "
        "Event ID 2, PnP problem code 5, hardware 0x80070005, and bare 10048 are unrelated."
    )

    results = catalog.reference_for_text(text, max_items=4)

    assert [(item.namespace, item.win32_code) for item in results] == [
        (WindowsErrorNamespace.WIN32, 5),
        (WindowsErrorNamespace.HRESULT, 5),
        (WindowsErrorNamespace.WIN32, 10048),
    ]


@pytest.mark.parametrize(
    "text",
    [
        "error 5",
        "5",
        "0x80070005",
        "Event ID 5",
        "PnP problem code 5",
        r"PCI\\VEN_10DE&DEV_2684 returned 0x80070005",
        "Win32 error 0x5",
        "HRESULT 80070005",
    ],
)
def test_unknown_or_ambiguous_text_formats_are_not_interpreted(
    catalog: WindowsErrorCatalog, text: str
) -> None:
    assert catalog.reference_for_text(text) == ()


def test_alias_mentions_are_deduplicated_in_first_appearance_order(
    catalog: WindowsErrorCatalog,
) -> None:
    results = catalog.reference_for_text(
        "ERROR_ACCESS_DENIED then Win32 error 5 then ERROR_ACCESS_DENIED; WSAEADDRINUSE",
        max_items=2,
    )

    assert [(item.namespace, item.win32_code) for item in results] == [
        (WindowsErrorNamespace.WIN32, 5),
        (WindowsErrorNamespace.WIN32, 10048),
    ]


def test_empty_runtime_catalog_is_safe_for_non_windows_replay() -> None:
    catalog = WindowsErrorCatalog.from_constants(
        {},
        message_resolver=None,
        source=WindowsErrorSource(
            catalog_provider="unavailable",
            catalog_version=None,
            message_provider="unavailable",
            os_version="Linux fixture",
            runtime_observed=False,
        ),
    )

    assert catalog.code_count == 0
    assert catalog.symbol_count == 0
    assert catalog.lookup_win32(5) is None
    assert catalog.reference_for_text("Win32 error 5") == ()


def test_message_provider_failure_is_recorded_as_unavailable() -> None:
    def unavailable(_code: int) -> str | None:
        raise OSError("fixture message table unavailable")

    catalog = WindowsErrorCatalog.from_constants(
        {"ERROR_ACCESS_DENIED": 5},
        message_resolver=unavailable,
        source=WindowsErrorSource(
            catalog_provider="fixture.winerror",
            catalog_version="1",
            message_provider="fixture unavailable provider",
            os_version="fixture Windows",
            runtime_observed=False,
        ),
    )

    result = catalog.lookup_win32(5)

    assert result is not None
    assert result.message is None
    assert any("No local system message" in item for item in result.limitations)


def test_bounds_reject_unbounded_inputs(catalog: WindowsErrorCatalog) -> None:
    with pytest.raises(ValueError, match="max_items"):
        catalog.reference_for_text("Win32 error 5", max_items=0)
    with pytest.raises(ValueError, match="text"):
        catalog.reference_for_text("x" * 20_001)
