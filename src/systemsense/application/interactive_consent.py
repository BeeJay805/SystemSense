"""One-use interactive review evidence for a fixed current-user repair.

The broker owns a process-local pending witness. It is never a network/API
credential; only a trusted in-process presenter and OS identity reader may
create one. The application route consumes it before any durable claim.
"""

from __future__ import annotations

import importlib
import json
import re
import secrets
import sys
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
from typing import Protocol, cast

from systemsense.actions.contracts import ActionAuthorizationError, RepairProposal
from systemsense.domain.time import ensure_utc, utc_now


@dataclass(frozen=True, slots=True)
class WindowsPrincipal:
    sid: str
    logon_id: int
    session_id: int

    def __post_init__(self) -> None:
        if (
            re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2,}[0-9]+", self.sid) is None
            or self.logon_id <= 0
            or self.session_id <= 0
            or self.session_id == 0xFFFFFFFF
        ):
            raise ActionAuthorizationError("interactive Windows principal is invalid")


@dataclass(frozen=True, slots=True)
class ReviewWitness:
    reference: str
    proposal_digest: str
    principal: WindowsPrincipal
    reviewed_at: datetime


type ConsentPresenter = Callable[[dict[str, object], float], bool]
type IdentityReader = Callable[[], WindowsPrincipal]


class _TokenHandle(Protocol):
    def Close(self) -> None: ...


class _SecurityModule(Protocol):
    TokenUser: int
    TokenStatistics: int
    TokenSessionId: int
    TokenType: int
    TokenPrimary: int

    def OpenProcessToken(self, process: object, access: int) -> _TokenHandle: ...
    def GetTokenInformation(self, token: _TokenHandle, information_class: int) -> object: ...
    def ConvertSidToStringSid(self, sid: object) -> str: ...


class _ApiModule(Protocol):
    def GetCurrentProcess(self) -> object: ...


class _ConModule(Protocol):
    TOKEN_QUERY: int


def _native_token_identity() -> WindowsPrincipal:
    if sys.platform != "win32":
        raise ActionAuthorizationError("interactive Windows identity is unavailable")
    security = cast(_SecurityModule, importlib.import_module("win32security"))
    api = cast(_ApiModule, importlib.import_module("win32api"))
    con = cast(_ConModule, importlib.import_module("win32con"))
    token = security.OpenProcessToken(api.GetCurrentProcess(), con.TOKEN_QUERY)
    try:
        user = cast(tuple[object, ...], security.GetTokenInformation(token, security.TokenUser))
        statistics = cast(
            dict[str, object], security.GetTokenInformation(token, security.TokenStatistics)
        )
        session_id = security.GetTokenInformation(token, security.TokenSessionId)
        token_type = security.GetTokenInformation(token, security.TokenType)
        logon_id = statistics.get("AuthenticationId")
        if (
            not user
            or type(logon_id) is not int
            or type(session_id) is not int
            or token_type != security.TokenPrimary
        ):
            raise ActionAuthorizationError("interactive Windows token is invalid")
        sid = security.ConvertSidToStringSid(user[0])
        return WindowsPrincipal(sid, logon_id, session_id)
    finally:
        token.Close()


class WindowsInteractiveIdentityReader:
    """Require the active primary process token to remain the same user."""

    def __init__(
        self,
        *,
        active_sid: Callable[[], str] | None = None,
        token_identity: IdentityReader = _native_token_identity,
    ) -> None:
        if active_sid is None:
            from systemsense.actions.wininet_native import interactive_current_sid

            active_sid = interactive_current_sid
        self._active_sid = active_sid
        self._token_identity = token_identity

    def __call__(self) -> WindowsPrincipal:
        try:
            before = self._active_sid()
            principal = self._token_identity()
            after = self._active_sid()
        except (OSError, RuntimeError, ValueError) as error:
            raise ActionAuthorizationError("interactive Windows identity is unavailable") from error
        if before != after or principal.sid != before:
            raise ActionAuthorizationError("interactive Windows identity changed")
        return principal


def format_review(record: Mapping[str, object]) -> str:
    """Display the entire canonical proposal and fresh approval challenge."""

    return json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True)


class TkConsentPresenter:
    """Local desktop dialog; not a secure desktop or anti-malware boundary."""

    def __call__(self, record: dict[str, object], timeout: float) -> bool:
        if sys.platform != "win32" or threading.current_thread() is not threading.main_thread():
            raise ActionAuthorizationError("native review requires the interactive main thread")
        import tkinter as tk

        root = tk.Tk()
        approved = False
        try:
            root.title("SystemSense repair approval")
            root.geometry("880x620")
            root.attributes("-topmost", True)  # pyright: ignore[reportUnknownMemberType]
            tk.Label(
                root,
                text="Review the exact repair, target, risk, and verification before approving.",
                font=("Segoe UI", 12),
                wraplength=820,
            ).pack(padx=20, pady=16)
            frame = tk.Frame(root)
            frame.pack(fill="both", expand=True, padx=20)
            scroll = tk.Scrollbar(frame)
            scroll.pack(side="right", fill="y")
            details = tk.Text(frame, wrap="word", yscrollcommand=scroll.set, font=("Consolas", 10))
            details.insert("1.0", format_review(record))
            details.configure(state="disabled")
            details.pack(side="left", fill="both", expand=True)
            scroll.configure(command=details.yview)  # pyright: ignore[reportUnknownMemberType,reportUnknownArgumentType]
            controls = tk.Frame(root)
            controls.pack(padx=20, pady=16, anchor="e")

            def confirm() -> None:
                nonlocal approved
                approved = True
                root.destroy()

            tk.Button(controls, text="Cancel", command=root.destroy, width=16).pack(
                side="left", padx=8
            )
            tk.Button(controls, text="Approve this repair", command=confirm, width=22).pack(
                side="left"
            )
            root.protocol("WM_DELETE_WINDOW", root.destroy)
            root.after(max(1, int(timeout * 1000)), root.destroy)
            root.grab_set()
            root.mainloop()
            return approved
        finally:
            if root.winfo_exists():
                root.destroy()


def windows_consent_broker(*, clock: Callable[[], datetime] = utc_now) -> InteractiveConsentBroker:
    """Build the only native per-user consent composition; never mount it in HTTP."""

    return InteractiveConsentBroker(
        identity=WindowsInteractiveIdentityReader(), presenter=TkConsentPresenter(), clock=clock
    )


class InteractiveConsentBroker:
    """Bind a positive local prompt response to one proposal and OS session."""

    def __init__(
        self,
        *,
        identity: IdentityReader,
        presenter: ConsentPresenter,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._identity = identity
        self._presenter = presenter
        self._clock = clock
        self._pending: dict[str, ReviewWitness] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _target_sid(proposal: RepairProposal) -> str:
        locators = {operation.target.locator for operation in proposal.operations}
        if len(locators) != 1:
            raise ActionAuthorizationError("interactive review has ambiguous targets")
        locator = next(iter(locators))
        if not locator.startswith("wininet_proxy:"):
            raise ActionAuthorizationError("interactive review target is unsupported")
        return locator.split(":", 1)[1]

    def current_principal(self) -> WindowsPrincipal:
        try:
            return self._identity()
        except (OSError, RuntimeError, ValueError) as error:
            raise ActionAuthorizationError("interactive Windows identity is unavailable") from error

    def confirm(self, proposal: RepairProposal) -> ReviewWitness:
        now = ensure_utc(self._clock())
        if now < proposal.created_at or now >= proposal.expires_at:
            raise ActionAuthorizationError("interactive review is expired")
        before = self.current_principal()
        if before.sid != self._target_sid(proposal):
            raise ActionAuthorizationError("interactive reviewer does not own repair target")
        reference = f"consent_{secrets.token_hex(16)}"
        record: dict[str, object] = {
            "proposal": proposal.model_dump(mode="json"),
            "proposal_digest": proposal.digest(),
            "challenge": reference,
        }
        try:
            approved = self._presenter(
                record, min(120.0, (proposal.expires_at - now).total_seconds())
            )
        except Exception as error:
            raise ActionAuthorizationError("interactive review was unavailable") from error
        after = self.current_principal()
        reviewed_at = ensure_utc(self._clock())
        if before != after or reviewed_at < now or reviewed_at >= proposal.expires_at:
            raise ActionAuthorizationError("interactive review session or time changed")
        if approved is not True:
            raise ActionAuthorizationError("interactive review was declined")
        witness = ReviewWitness(reference, proposal.digest(), after, reviewed_at)
        with self._lock:
            self._pending[reference] = witness
        return witness

    def consume(self, witness: ReviewWitness, proposal: RepairProposal) -> str:
        with self._lock:
            issued = self._pending.pop(witness.reference, None)
        if issued is not witness:
            raise ActionAuthorizationError("interactive review is missing or already used")
        now = ensure_utc(self._clock())
        if (
            witness.proposal_digest != proposal.digest()
            or witness.principal.sid != self._target_sid(proposal)
            or self.current_principal() != witness.principal
            or now < witness.reviewed_at
            or now >= proposal.expires_at
        ):
            raise ActionAuthorizationError("interactive review no longer matches repair")
        identity = witness.principal
        digest = sha256(
            f"{identity.sid}|{identity.logon_id}|{identity.session_id}".encode()
        ).hexdigest()
        return f"human:windows_{digest[:32]}"
