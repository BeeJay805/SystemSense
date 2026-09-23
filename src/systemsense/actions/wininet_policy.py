"""Conservative, read-only policy gate for a current-user WinINet proxy write.

These fixed registry locations are documented by Microsoft for the IE
DisableProxyChange policy and the per-machine proxy mode. An ordinary proxy
setting is *not* proof of policy. Other values under the fixed policy subtree
are treated as unclassified management and denied, not called enforced policy.

This is not an inventory of every MDM, Group Policy Preference, VPN, WinHTTP,
or application-specific proxy control. A green result is necessary for this
native writer, not proof that every relevant policy surface is unmanaged.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Protocol, cast

_CONTROL_PANEL = r"Software\Policies\Microsoft\Internet Explorer\Control Panel"
_INTERNET_POLICY = r"Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
_UNCLASSIFIED_PROXY_VALUES = (
    "ProxyEnable",
    "ProxyServer",
    "ProxyOverride",
    "AutoConfigURL",
    "AutoDetect",
)
_REG_DWORD = 4

type PolicyValue = tuple[object, int] | None
type PolicyReader = Callable[[str, str, str], PolicyValue]


class _Registry(Protocol):
    HKEY_LOCAL_MACHINE: int
    HKEY_CURRENT_USER: int
    KEY_READ: int

    def OpenKey(
        self, root: int, path: str, reserved: int, access: int
    ) -> AbstractContextManager[object]: ...
    def QueryValueEx(self, key: object, name: str) -> tuple[object, int]: ...


def _read_policy_value(root: str, path: str, name: str) -> PolicyValue:
    """Query only a fixed caller-selected policy value; missing means absent.

    Windows shares these Software\\Policies locations across WOW64 registry
    views. Do not inspect ordinary Internet Settings as policy.
    """
    if sys.platform != "win32":
        raise OSError("WinINet policy inspection is Windows-only")
    registry = cast(_Registry, importlib.import_module("winreg"))
    hive = registry.HKEY_LOCAL_MACHINE if root == "HKLM" else registry.HKEY_CURRENT_USER
    try:
        with registry.OpenKey(hive, path, 0, registry.KEY_READ) as key:
            try:
                return registry.QueryValueEx(key, name)
            except FileNotFoundError:
                return None
    except FileNotFoundError:
        return None


def _permitted_switch(value: PolicyValue, *, denied_value: int) -> bool:
    if value is None:
        return True
    data, data_type = value
    return type(data) is int and data_type == _REG_DWORD and data == 1 - denied_value


def current_user_proxy_policy_allows_write(
    read_value: PolicyReader = _read_policy_value,
) -> bool:
    """Deny known restrictions, ambiguous policy data, or failed policy reads.

    This is reevaluated for every native read and immediately before a write.
    It cannot make the policy check and the WinINet update atomic.
    """
    try:
        for root in ("HKLM", "HKCU"):
            if not _permitted_switch(read_value(root, _CONTROL_PANEL, "Proxy"), denied_value=1):
                return False
            # The automatic-configuration control is related, but its exact
            # effective semantics are not established by the policy mapping
            # used here. Any presence is therefore unclassified and denied.
            if read_value(root, _CONTROL_PANEL, "Autoconfig") is not None:
                return False
        if not _permitted_switch(
            read_value("HKLM", _INTERNET_POLICY, "ProxySettingsPerUser"), denied_value=0
        ):
            return False
        # ProxySettingsPerUser is documented as a device policy, not a user
        # policy. An HKCU policy value is ambiguous and therefore denied.
        if read_value("HKCU", _INTERNET_POLICY, "ProxySettingsPerUser") is not None:
            return False
        for root in ("HKLM", "HKCU"):
            for name in _UNCLASSIFIED_PROXY_VALUES:
                if read_value(root, _INTERNET_POLICY, name) is not None:
                    return False
    except (OSError, ImportError):
        return False
    return True
