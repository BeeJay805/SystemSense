"""Bounded Windows error references derived from the installed runtime catalog.

The module does not bundle SDK headers or treat arbitrary numbers as Windows
errors.  It admits only explicitly namespaced codes or exact symbols present in
the installed ``pywin32`` constants and uses the local system message table.
"""

from __future__ import annotations

import importlib.metadata
import platform
import re
from collections import defaultdict
from collections.abc import Callable, Mapping
from enum import StrEnum
from functools import lru_cache
from typing import Final

from pydantic import Field

from systemsense.domain.evidence import FrozenModel

FORMAT_MESSAGE_DOC: Final = (
    "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessage"
)
SYSTEM_ERROR_DOC: Final = (
    "https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-"
)
HRESULT_FROM_WIN32_DOC: Final = (
    "https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-hresult_from_win32"
)

_MAX_TEXT_CHARS = 20_000
_MAX_RESULTS = 16
_MAX_ALIASES = 16
_CODE_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"ERROR_[A-Z0-9_]+",
        r"WSA(?:E|SYS|VER|NOT|HOST|TRY|NO_|_E_|_QOS_|SERVICE|TYPE)[A-Z0-9_]*",
        r"DNS_ERROR_[A-Z0-9_]+",
        r"RPC_[SX]_[A-Z0-9_]+",
        r"EPT_S_[A-Z0-9_]+",
    )
)
_SYMBOL_TOKEN = re.compile(r"(?<![A-Z0-9_])[A-Z][A-Z0-9_]{2,79}(?![A-Z0-9_])")
_WIN32_TEXT = re.compile(r"\bWin32\s+error\s+([0-9]{1,5})\b", re.IGNORECASE)
_HRESULT_TEXT = re.compile(r"\bHRESULT\s+(0x[0-9A-Fa-f]{8})\b", re.IGNORECASE)


class WindowsErrorNamespace(StrEnum):
    WIN32 = "win32"
    HRESULT = "hresult"


class WindowsErrorSource(FrozenModel):
    catalog_provider: str = Field(min_length=1, max_length=120)
    catalog_version: str | None = Field(default=None, max_length=80)
    message_provider: str = Field(min_length=1, max_length=160)
    os_version: str = Field(min_length=1, max_length=240)
    runtime_observed: bool
    format_message_documentation: str = FORMAT_MESSAGE_DOC
    system_error_documentation: str = SYSTEM_ERROR_DOC
    hresult_mapping_documentation: str = HRESULT_FROM_WIN32_DOC


class WindowsErrorReference(FrozenModel):
    """One runtime-backed code reference, never a causal finding."""

    reference_id: str = Field(min_length=1, max_length=80)
    namespace: WindowsErrorNamespace
    win32_code: int = Field(ge=0, le=65_535)
    hresult: str | None = Field(default=None, pattern=r"^0x[0-9A-F]{8}$")
    constant_names: tuple[str, ...] = Field(min_length=1, max_length=_MAX_ALIASES)
    message: str | None = Field(default=None, max_length=4096)
    mechanism_note: str = Field(min_length=20, max_length=1000)
    knowledge_node_ids: tuple[str, ...] = Field(default=(), max_length=8)
    source: WindowsErrorSource
    catalog_code_count: int = Field(ge=0)
    catalog_symbol_count: int = Field(ge=0)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=8)


_MessageResolver = Callable[[int], str | None]


class WindowsErrorCatalog:
    """Filtered view over installed Win32 code constants and message tables."""

    def __init__(
        self,
        *,
        aliases_by_code: Mapping[int, tuple[str, ...]],
        hresult_aliases_by_code: Mapping[int, tuple[str, ...]],
        message_resolver: _MessageResolver | None,
        source: WindowsErrorSource,
    ) -> None:
        self._aliases_by_code = dict(aliases_by_code)
        self._hresult_aliases_by_code = dict(hresult_aliases_by_code)
        self._message_resolver = message_resolver
        self._source = source
        self._symbols: dict[str, tuple[WindowsErrorNamespace, int]] = {}
        for code, names in self._aliases_by_code.items():
            self._symbols.update((name, (WindowsErrorNamespace.WIN32, code)) for name in names)
        for code, names in self._hresult_aliases_by_code.items():
            self._symbols.update((name, (WindowsErrorNamespace.HRESULT, code)) for name in names)

    @classmethod
    def from_constants(
        cls,
        constants: Mapping[str, int],
        *,
        message_resolver: _MessageResolver | None,
        source: WindowsErrorSource,
    ) -> WindowsErrorCatalog:
        """Build from caller-supplied runtime constants without persisting a header copy."""

        aliases: defaultdict[int, list[str]] = defaultdict(list)
        for name, value in constants.items():
            if _is_win32_code_symbol(name, value):
                aliases[value].append(name)

        hresult_aliases: defaultdict[int, list[str]] = defaultdict(list)
        admitted_codes = set(aliases)
        for name, value in constants.items():
            code = _win32_code_from_hresult(value)
            if (
                code is not None
                and code in admitted_codes
                and name.isupper()
                and len(name) <= 80
                and not name.startswith(("FACILITY_", "SEVERITY_"))
            ):
                hresult_aliases[code].append(name)

        return cls(
            aliases_by_code={
                code: tuple(sorted(set(names), key=_win32_alias_sort_key)[:_MAX_ALIASES])
                for code, names in aliases.items()
            },
            hresult_aliases_by_code={
                code: tuple(sorted(set(names))[:_MAX_ALIASES])
                for code, names in hresult_aliases.items()
            },
            message_resolver=message_resolver,
            source=source,
        )

    @classmethod
    def from_runtime(cls) -> WindowsErrorCatalog:
        """Load installed pywin32 metadata; return an empty catalog when unavailable."""

        try:
            import winerror
        except ImportError:
            return cls.from_constants(
                {},
                message_resolver=None,
                source=_unavailable_source(),
            )

        constants = {
            name: value
            for name, value in vars(winerror).items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        resolver: _MessageResolver | None = None
        message_provider = "unavailable"
        try:
            import win32api

            def resolve_message(code: int) -> str | None:
                try:
                    return str(win32api.FormatMessage(code))
                except Exception:
                    return None

            resolver = resolve_message
            message_provider = "win32api.FormatMessage local system message table"
        except ImportError:
            pass

        try:
            catalog_version = importlib.metadata.version("pywin32")
        except importlib.metadata.PackageNotFoundError:
            catalog_version = None
        return cls.from_constants(
            constants,
            message_resolver=resolver,
            source=WindowsErrorSource(
                catalog_provider="pywin32.winerror runtime constants",
                catalog_version=catalog_version,
                message_provider=message_provider,
                os_version=platform.platform(),
                runtime_observed=True,
            ),
        )

    @property
    def code_count(self) -> int:
        return len(self._aliases_by_code)

    @property
    def symbol_count(self) -> int:
        return len(self._symbols)

    @property
    def source(self) -> WindowsErrorSource:
        return self._source

    def lookup_win32(self, code: int) -> WindowsErrorReference | None:
        if isinstance(code, bool) or code not in self._aliases_by_code:
            return None
        return self._reference(WindowsErrorNamespace.WIN32, code)

    def lookup_hresult(self, value: int | str) -> WindowsErrorReference | None:
        unsigned = _parse_hresult(value)
        if unsigned is None:
            return None
        code = _win32_code_from_hresult(unsigned)
        if code is None or code not in self._aliases_by_code:
            return None
        return self._reference(WindowsErrorNamespace.HRESULT, code)

    def lookup_symbol(self, name: str) -> WindowsErrorReference | None:
        match = self._symbols.get(name)
        if match is None:
            return None
        namespace, code = match
        return self._reference(namespace, code)

    def reference_for_text(
        self, text: str, max_items: int = 4
    ) -> tuple[WindowsErrorReference, ...]:
        if not 1 <= max_items <= _MAX_RESULTS:
            raise ValueError(f"max_items must be between 1 and {_MAX_RESULTS}")
        if len(text) > _MAX_TEXT_CHARS:
            raise ValueError(f"text must not exceed {_MAX_TEXT_CHARS} characters")

        candidates: list[tuple[int, WindowsErrorNamespace, int]] = []
        for match in _WIN32_TEXT.finditer(text):
            candidates.append((match.start(), WindowsErrorNamespace.WIN32, int(match.group(1))))
        for match in _HRESULT_TEXT.finditer(text):
            unsigned = _parse_hresult(match.group(1))
            code = _win32_code_from_hresult(unsigned) if unsigned is not None else None
            if code is not None:
                candidates.append((match.start(), WindowsErrorNamespace.HRESULT, code))
        for match in _SYMBOL_TOKEN.finditer(text):
            symbol = self._symbols.get(match.group(0))
            if symbol is not None:
                candidates.append((match.start(), symbol[0], symbol[1]))

        results: list[WindowsErrorReference] = []
        seen: set[tuple[WindowsErrorNamespace, int]] = set()
        for _position, namespace, code in sorted(candidates, key=lambda item: item[0]):
            key = (namespace, code)
            if key in seen:
                continue
            reference = self._reference(namespace, code)
            if reference is None:
                continue
            seen.add(key)
            results.append(reference)
            if len(results) == max_items:
                break
        return tuple(results)

    def _reference(
        self, namespace: WindowsErrorNamespace, code: int
    ) -> WindowsErrorReference | None:
        win32_names = self._aliases_by_code.get(code)
        if win32_names is None:
            return None
        hresult = (
            f"0x{0x80070000 | code:08X}" if namespace is WindowsErrorNamespace.HRESULT else None
        )
        names = win32_names
        if namespace is WindowsErrorNamespace.HRESULT:
            names = tuple(
                dict.fromkeys((*self._hresult_aliases_by_code.get(code, ()), *win32_names))
            )[:_MAX_ALIASES]
        message = _resolve_message(self._message_resolver, code)
        limitations = [
            "The namespace is explicit; event IDs and PnP problem codes are not interpreted here.",
            "A reported error condition does not by itself establish incident causality.",
        ]
        if message is None:
            limitations.append("No local system message was available for this code.")
        return WindowsErrorReference(
            reference_id=f"windows-error:{namespace.value}:{hresult or code}",
            namespace=namespace,
            win32_code=code,
            hresult=hresult,
            constant_names=names,
            message=message,
            mechanism_note=_MECHANISM_NOTES.get(code, _GENERIC_MECHANISM_NOTE),
            knowledge_node_ids=_KNOWLEDGE_NODE_IDS.get(code, ()),
            source=self._source,
            catalog_code_count=self.code_count,
            catalog_symbol_count=self.symbol_count,
            limitations=tuple(limitations),
        )


_GENERIC_MECHANISM_NOTE: Final = (
    "Windows reported this API-level status. The local message describes the condition, but the "
    "code alone does not identify the failing component or prove the incident's root cause."
)
_MECHANISM_NOTES: Final[dict[int, str]] = {
    5: (
        "Windows reported an access-denied result. It does not identify which authorization layer "
        "denied access or prove the incident's root cause."
    ),
    39: (
        "Windows reported that a disk handle had no remaining space. Confirm current capacity and "
        "the affected target; the code alone does not prove incident causality."
    ),
    112: (
        "Windows reported that a disk was full. Confirm the affected volume and observation time; "
        "the code alone does not prove incident causality."
    ),
    1053: (
        "The Service Control Manager operation timed out. This does not establish why the service "
        "failed to respond or prove a broader root cause."
    ),
    1060: (
        "Windows reported that the named service was not installed. This describes service lookup "
        "state, not the cause of a broader incident."
    ),
    1062: (
        "Windows reported that the service was not active. This does not establish why it stopped "
        "or whether it caused the broader symptom."
    ),
    10048: (
        "Winsock reported that the requested local address was already in use. Exact listener "
        "ownership is needed to distinguish a port conflict; this code does not prove causality."
    ),
    9003: (
        "DNS reported that the queried name did not exist. Confirm the exact query and observation "
        "time; this does not prove why an application failed."
    ),
    11001: (
        "Winsock name resolution reported that the host was not found. Confirm DNS observations; "
        "the code alone does not prove the underlying cause."
    ),
}
_KNOWLEDGE_NODE_IDS: Final[dict[int, tuple[str, ...]]] = {
    5: ("kn_security_block",),
    39: ("kn_disk_capacity",),
    112: ("kn_disk_capacity",),
    1053: ("kn_service_timeout",),
    1060: ("kn_service_failure",),
    1062: ("kn_service_failure",),
    9003: ("kn_dns_resolution",),
    10048: ("kn_port_conflict",),
    11001: ("kn_dns_resolution",),
}


def reference_for_text(text: str, max_items: int = 4) -> tuple[WindowsErrorReference, ...]:
    """Retrieve only explicit, typed Windows errors from bounded text."""

    return _runtime_catalog().reference_for_text(text, max_items=max_items)


@lru_cache(maxsize=1)
def _runtime_catalog() -> WindowsErrorCatalog:
    return WindowsErrorCatalog.from_runtime()


def _is_win32_code_symbol(name: str, value: int) -> bool:
    return (
        not isinstance(value, bool)
        and name.isupper()
        and len(name) <= 80
        and 0 <= value <= 65_535
        and any(pattern.fullmatch(name) for pattern in _CODE_PATTERNS)
    )


def _win32_code_from_hresult(value: int) -> int | None:
    unsigned = value & 0xFFFFFFFF
    if unsigned & 0xFFFF0000 != 0x80070000:
        return None
    return unsigned & 0xFFFF


def _parse_hresult(value: int | str) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        if re.fullmatch(r"0x[0-9A-Fa-f]{8}", value) is None:
            return None
        return int(value, 16)
    if not -(1 << 31) <= value <= 0xFFFFFFFF:
        return None
    return value & 0xFFFFFFFF


def _win32_alias_sort_key(name: str) -> tuple[int, str]:
    prefixes = ("ERROR_", "WSAE", "WSA", "DNS_ERROR_", "RPC_", "EPT_S_")
    return next(
        (index for index, prefix in enumerate(prefixes) if name.startswith(prefix)), 99
    ), name


def _clean_message(message: str | None) -> str | None:
    if message is None:
        return None
    cleaned = " ".join(message.split())
    return cleaned[:4096] or None


def _resolve_message(resolver: _MessageResolver | None, code: int) -> str | None:
    if resolver is None:
        return None
    try:
        return _clean_message(resolver(code))
    except Exception:
        return None


def _unavailable_source() -> WindowsErrorSource:
    return WindowsErrorSource(
        catalog_provider="unavailable",
        catalog_version=None,
        message_provider="unavailable",
        os_version=platform.platform(),
        runtime_observed=False,
    )
