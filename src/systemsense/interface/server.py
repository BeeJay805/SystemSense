"""Hardened loopback HTTP transport for the local SystemSense interface."""

# The self-contained document intentionally keeps CSS and JavaScript in this module so the
# transport exposes no extra asset routes. Those languages do not benefit from Python's E501.
# ruff: noqa: E501

from __future__ import annotations

import hmac
import json
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Protocol, cast, runtime_checkable
from urllib.parse import urlsplit

from systemsense.application.targets import TargetSelectionError

__all__ = ["ApplicationAPI", "LocalApplicationServer", "serve"]

_BODY_LIMIT = 16_384
_CASE_ROUTE = re.compile(r"^/api/cases/(case_[0-9a-f]{32})$")
_ACTION_ROUTE = re.compile(r"^/api/cases/(case_[0-9a-f]{32})/(cancel|resume)$")
_EXPORT_ROUTE = re.compile(r"^/api/cases/(case_[0-9a-f]{32})/export$")
_PROCESS_TARGET_ROUTE = re.compile(r"^/api/cases/(case_[0-9a-f]{32})/process-target$")
_CANDIDATE_ID = re.compile(r"^proc_[0-9a-f]{32}$")
_SESSION_LIMIT = 128
_SESSION_TTL_SECONDS = 8 * 60 * 60


@runtime_checkable
class ApplicationAPI(Protocol):
    """JSON-only application boundary supplied by the durable case coordinator."""

    def list_cases(self) -> dict[str, object]: ...

    def get_case(self, case_id: str) -> dict[str, object]: ...

    def start_case(self, objective: str, budget_ms: int, max_rounds: int) -> dict[str, object]: ...

    def cancel_case(self, case_id: str) -> dict[str, object]: ...

    def resume_case(self, case_id: str) -> dict[str, object]: ...

    def select_process_target(self, case_id: str, candidate_id: str) -> dict[str, object]: ...

    def export_case(self, case_id: str) -> dict[str, object]: ...

    def capabilities(self) -> dict[str, object]: ...

    def recorder_status(self) -> dict[str, object]: ...

    def start_recorder(self, interval_seconds: int, max_cycles: int) -> dict[str, object]: ...

    def stop_recorder(self) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class _Session:
    csrf_token: str
    touched_at: float


class LocalApplicationServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying only the neutral application adapter."""

    daemon_threads = True

    def __init__(self, api: ApplicationAPI, port: int) -> None:
        self.api = api
        self._session_lock = threading.Lock()
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        super().__init__(("127.0.0.1", port), _RequestHandler)

    def new_session(self) -> tuple[str, str]:
        now = time.monotonic()
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        with self._session_lock:
            expired_before = now - _SESSION_TTL_SECONDS
            expired = [
                key
                for key, session in self._sessions.items()
                if session.touched_at < expired_before
            ]
            for key in expired:
                del self._sessions[key]
            while len(self._sessions) >= _SESSION_LIMIT:
                self._sessions.popitem(last=False)
            self._sessions[session_id] = _Session(csrf_token=csrf_token, touched_at=now)
        return session_id, csrf_token

    def valid_csrf(self, session_id: str, csrf_token: str) -> bool:
        now = time.monotonic()
        with self._session_lock:
            session = self._sessions.get(session_id)
            if session is None or session.touched_at < now - _SESSION_TTL_SECONDS:
                self._sessions.pop(session_id, None)
                return False
            if not hmac.compare_digest(session.csrf_token, csrf_token):
                return False
            self._sessions.move_to_end(session_id)
            self._sessions[session_id] = _Session(
                csrf_token=session.csrf_token,
                touched_at=now,
            )
            return True


def serve(api: ApplicationAPI, port: int) -> LocalApplicationServer:
    """Create a loopback-only server; the caller owns its serving lifecycle."""

    if isinstance(port, bool) or not 0 <= port <= 65_535:
        raise ValueError("port must be an integer from 0 through 65535")
    return LocalApplicationServer(api, port)


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SystemSense"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5.0)

    def do_GET(self) -> None:
        if not self._validate_request(require_origin=False):
            return
        split = urlsplit(self.path)
        if split.query or split.fragment:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Route not found")
            return
        path = split.path
        if path == "/":
            self._document()
            return
        if path == "/api/cases":
            self._adapter_json(lambda: self._local_server.api.list_cases())
            return
        if path == "/api/capabilities":
            self._adapter_json(lambda: self._local_server.api.capabilities())
            return
        if path == "/api/recorder":
            self._adapter_json(lambda: self._local_server.api.recorder_status())
            return
        case_match = _CASE_ROUTE.fullmatch(path)
        if case_match is not None:
            case_id = case_match.group(1)
            self._adapter_json(lambda: self._local_server.api.get_case(case_id))
            return
        export_match = _EXPORT_ROUTE.fullmatch(path)
        if export_match is not None:
            case_id = export_match.group(1)
            self._adapter_json(
                lambda: self._local_server.api.export_case(case_id),
                attachment=f"{case_id}.json",
            )
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found", "Route not found")

    def do_POST(self) -> None:
        if not self._validate_request(require_origin=True) or not self._validate_csrf():
            return
        split = urlsplit(self.path)
        if split.query or split.fragment:
            self._error(HTTPStatus.NOT_FOUND, "not_found", "Route not found")
            return
        path = split.path
        if path in {"/api/recorder/start", "/api/recorder/stop"}:
            payload = self._read_json()
            if payload is None:
                return
            if path.endswith("/stop") and not payload:
                self._adapter_json(lambda: self._local_server.api.stop_recorder())
                return
            interval = payload.get("interval_seconds", 30)
            cycles = payload.get("max_cycles", 120)
            if (
                path.endswith("/start")
                and set(payload) <= {"interval_seconds", "max_cycles"}
                and type(interval) is int
                and type(cycles) is int
                and 5 <= interval <= 3600
                and 1 <= cycles <= 288
            ):
                self._adapter_json(lambda: self._local_server.api.start_recorder(interval, cycles))
                return
            self._error(
                HTTPStatus.BAD_REQUEST, "invalid_request", "Invalid bounded recorder settings"
            )
            return
        if path == "/api/cases":
            payload = self._read_json()
            if payload is None:
                return
            parsed = _parse_start_case(payload)
            if parsed is None:
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "Expected objective, budget_ms, and max_rounds within supported bounds",
                )
                return
            objective, budget_ms, max_rounds = parsed
            self._adapter_json(
                lambda: self._local_server.api.start_case(objective, budget_ms, max_rounds),
                status=HTTPStatus.CREATED,
            )
            return
        target_match = _PROCESS_TARGET_ROUTE.fullmatch(path)
        if target_match is not None:
            payload = self._read_json()
            if payload is None:
                return
            candidate_id = payload.get("candidate_id")
            if (
                set(payload) != {"candidate_id"}
                or not isinstance(candidate_id, str)
                or _CANDIDATE_ID.fullmatch(candidate_id) is None
            ):
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "Expected one process candidate identifier",
                )
                return
            case_id = target_match.group(1)
            self._adapter_json(
                lambda: self._local_server.api.select_process_target(case_id, candidate_id)
            )
            return
        action_match = _ACTION_ROUTE.fullmatch(path)
        if action_match is not None:
            payload = self._read_json()
            if payload is None:
                return
            if payload:
                self._error(
                    HTTPStatus.BAD_REQUEST,
                    "invalid_request",
                    "This action accepts only an empty JSON object",
                )
                return
            case_id, action = action_match.groups()
            if action == "cancel":
                self._adapter_json(lambda: self._local_server.api.cancel_case(case_id))
            else:
                self._adapter_json(lambda: self._local_server.api.resume_case(case_id))
            return
        self._error(HTTPStatus.NOT_FOUND, "not_found", "Route not found")

    def do_PUT(self) -> None:
        self._reject_method()

    def do_PATCH(self) -> None:
        self._reject_method()

    def do_DELETE(self) -> None:
        self._reject_method()

    def do_OPTIONS(self) -> None:
        self._reject_method()

    def do_TRACE(self) -> None:
        self._reject_method()

    def do_CONNECT(self) -> None:
        self._reject_method()

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    @property
    def _local_server(self) -> LocalApplicationServer:
        return cast("LocalApplicationServer", self.server)

    def _validate_request(self, *, require_origin: bool) -> bool:
        host = self.headers.get("Host", "")
        port = self._local_server.server_address[1]
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if host not in allowed_hosts:
            self._error(HTTPStatus.FORBIDDEN, "forbidden", "Local host required")
            return False
        origin = self.headers.get("Origin")
        if require_origin and origin is None:
            self._error(HTTPStatus.FORBIDDEN, "forbidden", "Same-origin request required")
            return False
        if origin is not None and origin != f"http://{host}":
            self._error(HTTPStatus.FORBIDDEN, "forbidden", "Cross-origin request rejected")
            return False
        return True

    def _validate_csrf(self) -> bool:
        try:
            cookie = SimpleCookie()
            cookie.load(self.headers.get("Cookie", ""))
        except CookieError:
            cookie = SimpleCookie()
        morsel = cookie.get("systemsense_session")
        csrf_token = self.headers.get("X-CSRF-Token", "")
        if (
            morsel is None
            or not csrf_token
            or not self._local_server.valid_csrf(morsel.value, csrf_token)
        ):
            self._error(HTTPStatus.FORBIDDEN, "forbidden", "Valid local session required")
            return False
        return True

    def _read_json(self) -> dict[str, object] | None:
        content_type = self.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            self._error(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Content-Type must be application/json",
            )
            return None
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError:
            length = -1
        if length < 0:
            self._error(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length required")
            return None
        if length > _BODY_LIMIT:
            self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body_too_large", "Body too large")
            return None
        try:
            decoded: object = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_json", "Body must be valid JSON")
            return None
        if not isinstance(decoded, dict):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", "Body must be a JSON object")
            return None
        mapping = cast("dict[object, object]", decoded)
        if any(not isinstance(key, str) for key in mapping):
            self._error(HTTPStatus.BAD_REQUEST, "invalid_request", "Object keys must be strings")
            return None
        return cast("dict[str, object]", decoded)

    def _adapter_json(
        self,
        operation: Callable[[], dict[str, object]],
        *,
        status: HTTPStatus = HTTPStatus.OK,
        attachment: str | None = None,
    ) -> None:
        try:
            payload = operation()
            encoded = json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except TargetSelectionError as error:
            self._error(HTTPStatus.CONFLICT, "process_target_unavailable", str(error))
            return
        except ValueError:
            self._error(
                HTTPStatus.BAD_REQUEST,
                "invalid_state",
                "Case or settings are unavailable. Start a new case for a completed investigation.",
            )
            return
        except RuntimeError:
            self._error(
                HTTPStatus.CONFLICT,
                "busy",
                "This workspace is busy or closed. Wait for active work or cancel it first.",
            )
            return
        except Exception:
            self._error(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "The local application could not complete the request",
            )
            return
        extra = (
            None
            if attachment is None
            else {"Content-Disposition": f'attachment; filename="{attachment}"'}
        )
        self._send(status, encoded, "application/json; charset=utf-8", extra_headers=extra)

    def _document(self) -> None:
        session_id, csrf_token = self._local_server.new_session()
        nonce = secrets.token_urlsafe(24)
        document = _render_document(csrf_token=csrf_token, nonce=nonce).encode("utf-8")
        self._send(
            HTTPStatus.OK,
            document,
            "text/html; charset=utf-8",
            csp=(
                "default-src 'none'; "
                f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "connect-src 'self'; img-src 'self' data:; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            ),
            extra_headers={
                "Set-Cookie": (
                    f"systemsense_session={session_id}; Path=/; HttpOnly; SameSite=Strict"
                )
            },
        )

    def _error(self, status: HTTPStatus, code: str, message: str) -> None:
        self.close_connection = True
        encoded = json.dumps(
            {"error": {"code": code, "message": message}}, separators=(",", ":")
        ).encode("utf-8")
        self._send(status, encoded, "application/json; charset=utf-8")

    def _method_not_allowed(self, allowed: str) -> None:
        self.close_connection = True
        self._send(
            HTTPStatus.METHOD_NOT_ALLOWED,
            b'{"error":{"code":"method_not_allowed","message":"Method not allowed"}}',
            "application/json; charset=utf-8",
            extra_headers={"Allow": allowed},
        )

    def _reject_method(self) -> None:
        if self._validate_request(require_origin=False):
            self._method_not_allowed("GET, POST")

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        csp: str = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if extra_headers is not None:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


def _parse_start_case(payload: dict[str, object]) -> tuple[str, int, int] | None:
    if set(payload) != {"objective", "budget_ms", "max_rounds"}:
        return None
    objective = payload.get("objective")
    budget_ms = payload.get("budget_ms")
    max_rounds = payload.get("max_rounds")
    if not isinstance(objective, str):
        return None
    objective = objective.strip()
    if not 1 <= len(objective) <= 2_000:
        return None
    if isinstance(budget_ms, bool) or not isinstance(budget_ms, int):
        return None
    if isinstance(max_rounds, bool) or not isinstance(max_rounds, int):
        return None
    if not 100 <= budget_ms <= 600_000 or not 1 <= max_rounds <= 12:
        return None
    return objective, budget_ms, max_rounds


def _render_document(*, csrf_token: str, nonce: str) -> str:
    return f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{csrf_token}">
<title>SystemSense local investigator</title>
<style nonce="{nonce}">
:root {{ color-scheme: light; font-family: Inter, "Segoe UI", sans-serif; font-size: 16px; color: #172127; background: #edf1f2; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; line-height: 1.55; }}
button, input, textarea {{ font: inherit; }}
button {{ min-height: 44px; border: 0; border-radius: 8px; padding: .65rem 1rem; background: #245a63; color: white; cursor: pointer; font-weight: 650; }}
button.secondary {{ color: #245a63; background: #dbe7e9; }}
button:disabled {{ cursor: not-allowed; opacity: .48; }}
input, textarea {{ width: 100%; border: 1px solid #9baaad; border-radius: 8px; padding: .7rem; color: #172127; background: white; }}
textarea {{ min-height: 96px; resize: vertical; }}
label {{ display: block; font-weight: 650; margin-bottom: .35rem; }}
h1 {{ margin: 0; font-size: clamp(1.75rem, 4vw, 2.5rem); line-height: 1.15; }}
h2 {{ margin: 0 0 .75rem; font-size: 1.35rem; }}
h3 {{ margin: 0 0 .25rem; font-size: 1rem; }}
p {{ margin: .25rem 0; }}
.top {{ padding: 1.5rem max(1rem, calc((100vw - 1180px)/2)); background: #183a41; color: #f7fbfb; }}
.top p {{ color: #d5e3e5; }}
.shell {{ max-width: 1180px; margin: 0 auto; padding: 1.25rem; display: grid; gap: 1rem; }}
.card {{ background: white; border: 1px solid #d3dcde; border-radius: 12px; padding: 1.15rem; box-shadow: 0 2px 8px #162b3010; }}
.new-case {{ display: grid; gap: .8rem; }}
.limits {{ display: grid; grid-template-columns: repeat(2, minmax(130px, 220px)); gap: .75rem; }}
.actions {{ display: flex; flex-wrap: wrap; gap: .65rem; align-items: center; }}
.disclosure {{ border-left: 4px solid #5d878e; padding-left: .8rem; color: #3d5054; }}
.workspace {{ display: grid; grid-template-columns: minmax(220px, 310px) minmax(0, 1fr); gap: 1rem; align-items: start; }}
.history {{ display: grid; gap: .5rem; }}
.history button {{ width: 100%; text-align: left; color: #172127; background: #eef3f3; font-weight: 500; }}
.case-head {{ display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; align-items: start; }}
.status {{ display: inline-block; background: #e4eeee; border-radius: 99px; padding: .25rem .7rem; font-weight: 700; }}
.sections {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; margin-top: 1rem; }}
.section {{ min-height: 150px; }}
.items {{ display: grid; gap: .65rem; }}
.item {{ padding: .7rem; border: 1px solid #d9e1e2; border-radius: 8px; overflow-wrap: anywhere; }}
.muted {{ color: #5e6d70; }}
.error {{ color: #8a2727; font-weight: 650; }}
.wide {{ grid-column: 1 / -1; }}
details {{ margin-top: .75rem; }}
summary {{ cursor: pointer; font-weight: 650; padding: .5rem 0; }}
pre {{ white-space: pre-wrap; overflow-wrap: anywhere; font: .95rem/1.5 Consolas, monospace; }}
.answer {{ margin: 1.2rem 0; padding: 1rem; background: #edf5f2; border-left: 4px solid #367765; }}
.answer p {{ font-size: 1.1rem; }}
.item:target {{ outline: 3px solid #367765; }}
a {{ color: #245a63; }}
@media (max-width: 800px) {{ .workspace, .sections {{ grid-template-columns: 1fr; }} .limits {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<header class="top">
  <h1>Read-only investigation</h1>
  <p>Follow one case from objective to cited evidence. SystemSense cannot repair or change this computer.</p>
</header>
<main class="shell">
  <section class="card" aria-labelledby="new-title">
    <h2 id="new-title">Start a case</h2>
    <form id="case-form" class="new-case">
      <div><label for="objective">What should SystemSense investigate?</label><textarea id="objective" name="objective" maxlength="2000" required></textarea></div>
      <details><summary>Collection limits</summary><div class="limits">
        <div><label for="budget">Time budget (seconds)</label><input id="budget" name="budget" type="number" min="1" max="600" value="180" required></div>
        <div><label for="rounds">Maximum rounds</label><input id="rounds" name="rounds" type="number" min="1" max="12" value="6" required></div>
      </div><p class="muted">Incident window defaults to 15 minutes before this case and 5 minutes after. These limits control collection, not the incident time.</p></details>
      <div class="actions"><button type="submit">Start investigation</button><span id="request-state" class="muted" aria-live="polite"></span></div>
    </form>
  </section>
  <section class="card disclosure" aria-label="Capability disclosure">
    <strong id="inference-mode">Inference mode: loading</strong>
    <p id="capability-note">Loading local capabilities. Repairs remain disabled.</p>
    <details><summary>Capture context for an intermittent problem</summary>
      <p>Record resource snapshots and registered Event Logs every 30 seconds for up to 120 samples. Stops when this application closes. Older unreferenced passive samples are pruned; case evidence is preserved.</p>
      <div class="actions"><button id="record-start" class="secondary" type="button">Start context recording</button><button id="record-stop" class="secondary" type="button" disabled>Stop recording</button></div>
      <p id="recorder-state" class="muted" aria-live="polite">Recording is off.</p>
    </details>
  </section>
  <div class="workspace">
    <aside class="card">
      <h2>Case history</h2>
      <div id="history" class="history"><p class="muted">Loading cases</p></div>
    </aside>
    <section class="card" aria-labelledby="case-title">
      <div class="case-head">
        <div><h2 id="case-title">No case selected</h2><p id="case-detail" class="muted">Start a case or choose one from history.</p></div>
        <span id="case-status" class="status">Idle</span>
      </div>
      <div class="actions">
        <button id="cancel" class="secondary" type="button" disabled>Cancel</button>
        <button id="resume" class="secondary" type="button" disabled>Resume</button>
        <button id="export" class="secondary" type="button" disabled>Export redacted report</button>
      </div>
      <p id="case-error" class="error" role="alert"></p>
      <section id="process-target-panel" class="card" aria-labelledby="process-target-title" hidden>
        <h2 id="process-target-title">Choose a process to inspect</h2>
        <p>Choose the observed process you meant. SystemSense will not infer a target from its name. This selection permits read-only process checks, not a repair.</p>
        <p id="process-target-coverage" class="muted"></p>
        <div id="process-target-candidates" class="items"></div>
      </section>
      <section class="answer" aria-live="polite"><h2>Current assessment</h2><p id="finding-explanation"></p><p id="assessment">No investigation yet.</p><p id="outcome" class="muted"></p></section>
      <div id="warnings" class="muted"></div>
      <p id="attention-progress" class="muted"></p>
      <div class="sections">
        <section class="section wide"><h2>Possible explanations</h2><div id="hypotheses" class="items"></div></section>
        <section class="section wide"><h2>Next step</h2><div id="next-action" class="items"></div></section>
      </div>
      <details open><summary>Evidence and coverage</summary><p id="retrieval-note" class="muted"></p>
        <details><summary>Coverage by collector</summary><div id="coverage" class="items"></div></details>
        <div id="evidence" class="items"></div>
      </details>
      <details><summary>Investigation timeline</summary><div id="timeline" class="items"></div></details>
      <details><summary>Explicit relationships and citations</summary><div id="relationships" class="items"></div><div id="citations" class="items"></div></details>
      <details><summary>Local brain calls and attention</summary><div id="brain-calls" class="items"></div></details>
      <details><summary>Sourced reference knowledge, not machine observations</summary><div id="reference-knowledge" class="items"></div></details>
    </section>
  </div>
</main>
<script nonce="{nonce}">
"use strict";
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const byId = (id) => document.getElementById(id);
let selectedCaseId = null;
let selectedStatus = "";
let capabilities = {{}};
let pollHandle = null;

function text(value) {{
  if (value === null || value === undefined) return "Not reported";
  if (Array.isArray(value)) return value.map(text).join("; ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}}

function itemNode(item) {{
  const card = document.createElement("article");
  card.className = "item";
  if (item === null || typeof item !== "object") {{ card.textContent = text(item); return card; }}
  const title = item.summary ?? item.statement ?? item.event ?? item.title ?? item.name ?? item.category ?? item.status ?? item.type ?? item.evidence_id ?? item.id ?? "Record";
  const heading = document.createElement("h3");
  heading.textContent = text(title);
  card.append(heading);
  if (item.evidence_id) card.id = "evidence-" + item.evidence_id;
  if (item.citation_evidence_id) {{
    const line = document.createElement("p"); line.className = "muted";
    if (item.citation_available) {{
      const link = document.createElement("a"); link.href = "#evidence-" + encodeURIComponent(item.citation_evidence_id); link.textContent = item.citation_evidence_id;
      link.addEventListener("click", () => {{ const target = document.getElementById("evidence-" + item.citation_evidence_id); if (target) {{ let parent = target.parentElement; while (parent) {{ if (parent.tagName === "DETAILS") parent.open = true; parent = parent.parentElement; }} }} }});
      line.append("evidence: ", link);
    }} else {{
      line.textContent = "evidence unavailable in this authorized bounded report: " + item.citation_evidence_id;
    }}
    card.append(line);
  }}
  const preferred = ["status", "detail", "message", "reason", "rationale", "description", "confidence", "case_id", "source_id", "source_type", "category", "collector_id", "statement_kind", "execution_id", "historical", "fact_view", "relationship", "source_entity_id", "target_entity_id", "valid_from", "valid_until", "occurred_at", "observed_at", "captured_at", "probe_id", "probe_ids", "evidence_ids", "supporting_evidence_ids", "contradicting_evidence_ids", "missing_evidence_ids", "distinguishing_probe_ids", "limitations"];
  for (const key of preferred) {{
    if (Array.isArray(item[key]) && item[key].length === 0) continue;
    if (Object.hasOwn(item, key) && item[key] !== null && item[key] !== "") {{
      const line = document.createElement("p");
      line.className = "muted";
      if (key.endsWith("evidence_ids") && Array.isArray(item[key])) {{
        if (item[key].length === 0) continue;
        line.textContent = key.replaceAll("_", " ") + ": ";
        for (const id of item[key]) {{ const link = document.createElement("a"); link.href = "#evidence-" + encodeURIComponent(id); link.textContent = id; link.addEventListener("click", () => {{ const target = document.getElementById("evidence-" + id); if (target) {{ let parent = target.parentElement; while (parent) {{ if (parent.tagName === "DETAILS") parent.open = true; parent = parent.parentElement; }} }} }}); line.append(link, " "); }}
      }} else {{
        const value = key.endsWith("_at") || key.startsWith("valid_") ? new Date(item[key]).toLocaleString() : text(item[key]);
        line.textContent = key.replaceAll("_", " ") + ": " + value;
      }}
      card.append(line);
    }}
  }}
  if (item.facts && Object.keys(item.facts).length) {{
    const details = document.createElement("details"); const label = document.createElement("summary"); label.textContent = "Inspect collected facts";
    const facts = document.createElement("pre"); facts.textContent = JSON.stringify(item.facts, null, 2); details.append(label, facts); card.append(details);
  }}
  return card;
}}

function renderCollection(id, value, emptyText) {{
  const target = byId(id);
  const signature = JSON.stringify(value);
  if (target.dataset.signature === signature) return;
  target.dataset.signature = signature;
  target.replaceChildren();
  const values = Array.isArray(value) ? value : (value === null || value === undefined ? [] : [value]);
  if (values.length === 0) {{
    const empty = document.createElement("p"); empty.className = "muted"; empty.textContent = emptyText; target.append(empty); return;
  }}
  for (const valueItem of values) target.append(itemNode(valueItem));
}}

function unwrapCase(payload) {{ return payload && typeof payload.case === "object" ? payload.case : payload; }}

function citedEvidence(value) {{
  const citations = Array.isArray(value.citations) ? [...value.citations] : [];
  const ids = Array.isArray(value.assessment?.evidence_ids) ? [...value.assessment.evidence_ids] : [];
  if (!Array.isArray(value.citations) && Array.isArray(value.hypotheses)) {{
    for (const hypothesis of value.hypotheses) {{
      for (const field of ["supporting_evidence_ids", "contradicting_evidence_ids"]) {{
        if (Array.isArray(hypothesis[field])) ids.push(...hypothesis[field]);
      }}
    }}
  }}
  const available = new Set((value.evidence ?? []).map(item => item?.evidence_id).filter(Boolean));
  const cited = new Set(citations.map(item => item.citation_evidence_id));
  const uncited = [...new Set(ids)].filter(id => !cited.has(id));
  return [...citations, ...uncited.map(id => ({{summary: "Evidence citation", citation_evidence_id: id, citation_available: available.has(id)}}))];
}}

function nextActions(value) {{
  if (value.next_action !== null && value.next_action !== undefined) return value.next_action;
  if (value.summary?.next_action !== null && value.summary?.next_action !== undefined) return value.summary.next_action;
  if (!Array.isArray(value.pending_probe_ids)) return [];
  return value.pending_probe_ids.map((probeId) => ({{probe_id: probeId, status: "pending"}}));
}}

function renderProcessTargets(value) {{
  const panel = byId("process-target-panel");
  const target = byId("process-target-candidates");
  panel.hidden = selectedStatus !== "awaiting_target";
  target.replaceChildren();
  if (panel.hidden) return;
  const inventory = value.process_target_inventory ?? {{}};
  const candidates = Array.isArray(inventory.candidates) ? inventory.candidates : [];
  const omitted = Number.isInteger(inventory.omitted_process_count) ? inventory.omitted_process_count : 0;
  byId("process-target-coverage").textContent = inventory.unavailable_reason
    ? "Candidate inventory unavailable: " + text(inventory.unavailable_reason) + ". Start a new investigation to collect a fresh snapshot."
    : "Snapshot " + text(inventory.collection_started_at) + " to " + text(inventory.collection_completed_at) + ". " + omitted + " processes omitted; inventory " + (inventory.inventory_complete ? "complete" : "incomplete") + ".";
  if (candidates.length === 0) {{
    const line = document.createElement("p"); line.className = "muted"; line.textContent = "No fresh process candidates are available."; target.append(line); return;
  }}
  for (const candidate of candidates) {{
    const card = document.createElement("article"); card.className = "item";
    const heading = document.createElement("h3"); heading.textContent = text(candidate.name) + " · PID " + text(candidate.pid); card.append(heading);
    const provenance = document.createElement("p"); provenance.className = "muted";
    provenance.textContent = "Created " + text(candidate.creation_time) + " · source " + text(candidate.evidence_id) + " · " + text(candidate.omitted_process_count) + " processes omitted"; card.append(provenance);
    const choose = document.createElement("button"); choose.type = "button"; choose.textContent = "Select this process";
    choose.addEventListener("click", async () => {{
      choose.disabled = true;
      try {{ renderCase(await mutate("/api/cases/" + encodeURIComponent(selectedCaseId) + "/process-target", {{candidate_id: candidate.candidate_id}})); await loadHistory(); byId("case-error").textContent = ""; }}
      catch (error) {{ choose.disabled = false; byId("case-error").textContent = error.message; }}
    }});
    card.append(choose); target.append(card);
  }}
}}

function renderCase(payload) {{
  const value = unwrapCase(payload);
  if (!value || typeof value !== "object") return;
  selectedCaseId = typeof value.case_id === "string" ? value.case_id : selectedCaseId;
  selectedStatus = typeof value.status === "string" ? value.status : "unknown";
  byId("case-title").textContent = text(value.objective ?? value.symptom ?? selectedCaseId ?? "Selected case");
  const rounds = Number.isInteger(value.round_count) && Number.isInteger(value.max_rounds) ? " · collection round " + (value.round_count - (value.run_start_round ?? 0)) + " of " + value.max_rounds : "";
  byId("case-detail").textContent = value.progress?.message ? text(value.progress.message) : "Case " + text(selectedCaseId) + rounds;
  byId("case-status").textContent = selectedStatus;
  renderProcessTargets(value);
  const disposition = value.assessment?.disposition;
  const observedFinding = disposition === "supported_observed_finding" ? value.assessment?.explanation : null;
  byId("finding-explanation").textContent = observedFinding ? "Observed finding: " + text(observedFinding) : "";
  const reasoningSummary = text(value.summary ?? "Awaiting observations.");
  byId("assessment").textContent = observedFinding ? "Reasoning summary: " + reasoningSummary : reasoningSummary;
  let outcome = text(value.outcome ?? selectedStatus).replaceAll("_", " ");
  if (disposition === "supported_observed_finding") {{
    outcome = "Observed finding; cause unresolved. Outcome: " + outcome + ".";
    if (value.stop_reason) outcome += " Stop reason: " + text(value.stop_reason);
  }}
  else if (disposition === "supported_observed_explanation") outcome = "Observed answer supported; root cause not proven";
  byId("outcome").textContent = outcome;
  renderCollection("warnings", [...(value.assessment?.limitations ?? []), ...(value.warnings ?? [])], "");
  const retrieval = value.retrieval ?? {{}};
  byId("retrieval-note").textContent = retrieval.truncated ? "This evidence view is bounded. Some records or facts were omitted; conclusions must account for this coverage gap." : "Observed and captured times are separate. Historical samples are labeled and may be stale.";
  renderCollection("timeline", value.timeline, "No timeline entries reported yet.");
  renderCollection("evidence", value.evidence, "No evidence reported yet.");
  renderCollection("coverage", value.coverage, "Coverage has not been reported.");
  renderCollection("hypotheses", value.hypotheses, "No hypotheses reported yet.");
  renderCollection("citations", citedEvidence(value), "No citations reported yet.");
  renderCollection("next-action", nextActions(value), "No next action reported.");
  renderCollection("relationships", value.relationships, "No directly observed relationships in this evidence packet.");
  byId("attention-progress").textContent = "Attention touched " + (value.considered_evidence_count ?? 0) + " evidence records through bounded excerpts; " + (value.focused_evidence_ids?.length ?? 0) + " in the deep brain's latest focused map. " + (value.attention_notes ?? []).join(" · ");
  renderCollection("brain-calls", (value.provider_calls ?? []).map(call => ({{summary: call.role === "fast_decision" ? "Fast attention brain" : "Deep reasoning brain", detail: call.provider_id + " · " + (Number(call.elapsed_ms) / 1000).toFixed(2) + " seconds", status: call.degraded ? "Fallback used" : "Response validated", reason: call.detail === "ready" ? null : call.detail}})), "No model calls yet.");
  const reference = (value.reference_knowledge ?? []).flatMap(packet => (packet.relations ?? []).map(relation => ({{summary: relation.mechanism, detail: "Conditional reference: " + (relation.conditions ?? []).join("; ") + " Sources: " + (packet.sources ?? []).filter(source => (relation.source_ids ?? []).includes(source.source_id)).map(source => source.url).join(" "), limitations: relation.limitations}})));
  const errorReferences = (value.error_references ?? []).map(entry => ({{summary: (entry.constant_names ?? []).join(" / "), detail: (entry.hresult ?? "Win32 error " + entry.win32_code) + ": " + (entry.message ?? "No local message available"), reason: entry.mechanism_note, source_type: entry.source?.catalog_provider, limitations: entry.limitations}}));
  renderCollection("reference-knowledge", [...reference, ...errorReferences], "No matching reference relationships or explicit error codes.");
  const active = ["queued", "collecting", "running", "cancelling", "resuming", "awaiting_target"].includes(selectedStatus);
  byId("cancel").disabled = !selectedCaseId || !active;
  byId("resume").disabled = !selectedCaseId || !["cancelled", "interrupted", "failed"].includes(selectedStatus);
  byId("export").disabled = !selectedCaseId || capabilities.export?.available === false;
  schedulePoll(active);
}}

function schedulePoll(active) {{
  if (pollHandle !== null) window.clearTimeout(pollHandle);
  pollHandle = active && selectedCaseId ? window.setTimeout(loadSelected, 1200) : null;
}}

async function api(path, options = {{}}) {{
  const response = await fetch(path, {{credentials: "same-origin", ...options}});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload?.error?.message ?? "Local request failed");
  return payload;
}}

async function loadHistory() {{
  const payload = await api("/api/cases");
  const cases = Array.isArray(payload.cases) ? payload.cases : (Array.isArray(payload.items) ? payload.items : []);
  const history = byId("history"); history.replaceChildren();
  if (cases.length === 0) {{ const empty = document.createElement("p"); empty.className = "muted"; empty.textContent = "No saved cases."; history.append(empty); return; }}
  for (const caseItem of cases) {{
    const button = document.createElement("button"); button.type = "button";
    button.textContent = text(caseItem.objective ?? caseItem.symptom ?? caseItem.case_id ?? "Case");
    button.addEventListener("click", () => selectCase(caseItem.case_id)); history.append(button);
  }}
}}

async function selectCase(caseId) {{ selectedCaseId = caseId; await loadSelected(); }}
async function loadSelected() {{
  if (!selectedCaseId) return;
  try {{ renderCase(await api("/api/cases/" + encodeURIComponent(selectedCaseId))); byId("case-error").textContent = ""; }}
  catch (error) {{ byId("case-error").textContent = error.message; schedulePoll(false); }}
}}

async function mutate(path, body) {{
  return api(path, {{method: "POST", headers: {{"Content-Type": "application/json", "X-CSRF-Token": csrf}}, body: JSON.stringify(body)}});
}}

byId("case-form").addEventListener("submit", async (event) => {{
  event.preventDefault(); byId("request-state").textContent = "Starting case";
  try {{
    const payload = await mutate("/api/cases", {{objective: byId("objective").value, budget_ms: Number(byId("budget").value) * 1000, max_rounds: Number(byId("rounds").value)}});
    renderCase(payload); await loadHistory(); byId("request-state").textContent = "Case started";
  }} catch (error) {{ byId("request-state").textContent = error.message; }}
}});

byId("cancel").addEventListener("click", async () => {{ try {{ renderCase(await mutate("/api/cases/" + encodeURIComponent(selectedCaseId) + "/cancel", {{}})); await loadHistory(); }} catch (error) {{ byId("case-error").textContent = error.message; }} }});
byId("resume").addEventListener("click", async () => {{ try {{ renderCase(await mutate("/api/cases/" + encodeURIComponent(selectedCaseId) + "/resume", {{}})); await loadHistory(); }} catch (error) {{ byId("case-error").textContent = error.message; }} }});
byId("export").addEventListener("click", async () => {{
  try {{
    const payload = await api("/api/cases/" + encodeURIComponent(selectedCaseId) + "/export");
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], {{type: "application/json"}}));
    const link = document.createElement("a"); link.href = url; link.download = selectedCaseId + ".json"; link.click(); URL.revokeObjectURL(url);
  }} catch (error) {{ byId("case-error").textContent = error.message; }}
}});

async function initialize() {{
  try {{
    capabilities = await api("/api/capabilities");
    const inference = capabilities.inference && typeof capabilities.inference === "object" ? capabilities.inference : {{}};
    const mode = inference.mode ?? capabilities.inference_mode ?? "not reported";
    byId("inference-mode").textContent = "Inference mode: " + text(mode);
    const availability = inference.enabled === false ? " Model inference is off; deterministic evidence checks remain available." : " Configured local inference is advisory and not diagnostically qualified.";
    const providers = [inference.decision_provider, inference.decision_model, inference.reasoning_model].filter(Boolean);
    const providerNote = providers.length ? " Advisory providers: " + providers.join(", ") + "." : "";
    byId("capability-note").textContent = "Repairs are disabled. Investigations are read-only." + availability + providerNote;
    await loadHistory();
    await refreshRecorder();
  }} catch (error) {{ byId("request-state").textContent = error.message; }}
}}
async function refreshRecorder() {{
  try {{
    const status = await api("/api/recorder");
    byId("record-start").disabled = !status.available || status.active;
    byId("record-stop").disabled = !status.active;
    byId("recorder-state").textContent = (status.active ? "Recording context. " : "Recording is off. ") + (status.cycles_completed ?? 0) + " samples; " + (status.failure_count ?? 0) + " collection gaps." + (status.error ? " " + status.error : "");
    if (status.active) window.setTimeout(refreshRecorder, 3000);
  }} catch (error) {{ byId("recorder-state").textContent = error.message; }}
}}
byId("record-start").addEventListener("click", async () => {{ try {{ await mutate("/api/recorder/start", {{interval_seconds: 30, max_cycles: 120}}); await refreshRecorder(); }} catch (error) {{ byId("recorder-state").textContent = error.message; }} }});
byId("record-stop").addEventListener("click", async () => {{ try {{ await mutate("/api/recorder/stop", {{}}); await refreshRecorder(); }} catch (error) {{ byId("recorder-state").textContent = error.message; }} }});
initialize();
</script>
</body>
</html>'''
