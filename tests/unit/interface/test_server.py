from __future__ import annotations

import http.client
import json
import re
import threading
from collections.abc import Generator
from contextlib import contextmanager
from http.cookies import SimpleCookie
from typing import cast

import pytest

from systemsense.interface.server import ApplicationAPI, serve


class FakeAPI:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.case: dict[str, object] = {
            "case_id": "case_0123456789abcdef0123456789abcdef",
            "objective": "Explain the freeze <img src=x onerror=alert(1)>",
            "status": "collecting",
            "timeline": [],
            "evidence": [],
            "coverage": [],
            "hypotheses": [],
            "citations": [],
            "next_action": None,
        }

    def list_cases(self) -> dict[str, object]:
        self.calls.append(("list_cases",))
        return {"cases": [self.case]}

    def get_case(self, case_id: str) -> dict[str, object]:
        self.calls.append(("get_case", case_id))
        return self.case

    def start_case(self, objective: str, budget_ms: int, max_rounds: int) -> dict[str, object]:
        self.calls.append(("start_case", objective, budget_ms, max_rounds))
        return self.case

    def cancel_case(self, case_id: str) -> dict[str, object]:
        self.calls.append(("cancel_case", case_id))
        return {**self.case, "status": "cancelled"}

    def resume_case(self, case_id: str) -> dict[str, object]:
        self.calls.append(("resume_case", case_id))
        return {**self.case, "status": "collecting"}

    def export_case(self, case_id: str) -> dict[str, object]:
        self.calls.append(("export_case", case_id))
        return {"schema_version": 1, "redacted": True, "case": self.case}

    def capabilities(self) -> dict[str, object]:
        self.calls.append(("capabilities",))
        return {
            "read_only": True,
            "inference": {"mode": "deterministic", "available": True},
            "export": {"available": True, "redacted": True},
        }

    def recorder_status(self) -> dict[str, object]:
        return {"active": False, "available": True}

    def start_recorder(self, interval_seconds: int, max_cycles: int) -> dict[str, object]:
        self.calls.append(("start_recorder", interval_seconds, max_cycles))
        return {"active": True}

    def stop_recorder(self) -> dict[str, object]:
        self.calls.append(("stop_recorder",))
        return {"active": False}


@contextmanager
def running_server(api: ApplicationAPI) -> Generator[tuple[str, int], None, None]:
    server = serve(api, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = cast("tuple[str, int]", server.server_address)
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    response_body = response.read()
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    connection.close()
    return response.status, response_headers, response_body


def browser_session(port: int) -> tuple[str, str]:
    status, headers, body = request(port, "GET", "/")
    assert status == 200
    cookies = SimpleCookie()
    cookies.load(headers["set-cookie"])
    session_cookie = cookies["systemsense_session"].OutputString()
    token_match = re.search(rb'<meta name="csrf-token" content="([A-Za-z0-9_-]+)">', body)
    assert token_match is not None
    return session_cookie, token_match.group(1).decode("ascii")


def mutation_headers(port: int, cookie: str, token: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "Cookie": cookie,
        "Origin": f"http://127.0.0.1:{port}",
        "X-CSRF-Token": token,
    }


def test_serve_binds_only_ipv4_loopback() -> None:
    api = FakeAPI()
    server = serve(api, 0)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_document_is_self_contained_accessible_and_hardened() -> None:
    with running_server(FakeAPI()) as (_, port):
        status, headers, body = request(port, "GET", "/")

    document = body.decode("utf-8")
    assert status == 200
    assert "default-src 'none'" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert "HttpOnly" in headers["set-cookie"]
    assert "SameSite=Strict" in headers["set-cookie"]
    assert "font-size: 16px" in document
    assert "Read-only investigation" in document
    for label in (
        "Investigation timeline",
        "Evidence",
        "Coverage",
        "Possible explanations",
        "Explicit relationships and citations",
        "Next step",
        "Case history",
        "Inference mode",
    ):
        assert label in document
    assert "innerHTML" not in document
    assert "http://" not in document
    assert "https://" not in document
    assert "supporting_evidence_ids" in document
    assert "citation_evidence_id" in document
    for provenance_field in (
        "case_id",
        "source_id",
        "category",
        "collector_id",
        "statement_kind",
        "execution_id",
    ):
        assert provenance_field in document
    assert "pending_probe_ids" in document
    assert "decision_model" in document


def test_get_routes_preserve_adapter_json_and_export_is_an_attachment() -> None:
    api = FakeAPI()
    case_id = cast("str", api.case["case_id"])
    with running_server(api) as (_, port):
        status, _, body = request(port, "GET", "/api/cases")
        assert status == 200
        assert json.loads(body) == {"cases": [api.case]}

        status, _, body = request(port, "GET", f"/api/cases/{case_id}")
        assert status == 200
        assert json.loads(body) == api.case

        status, _, body = request(port, "GET", "/api/capabilities")
        assert status == 200
        assert json.loads(body)["read_only"] is True

        status, headers, body = request(port, "GET", f"/api/cases/{case_id}/export")
        assert status == 200
        assert headers["content-disposition"] == f'attachment; filename="{case_id}.json"'
        assert json.loads(body)["redacted"] is True

    assert api.calls == [
        ("list_cases",),
        ("get_case", case_id),
        ("capabilities",),
        ("export_case", case_id),
    ]


def test_case_lifecycle_mutations_require_session_origin_and_csrf() -> None:
    api = FakeAPI()
    case_id = cast("str", api.case["case_id"])
    payload = json.dumps(
        {"objective": "Explain the recurring freeze", "budget_ms": 30_000, "max_rounds": 6}
    ).encode()
    with running_server(api) as (_, port):
        cookie, token = browser_session(port)
        valid_headers = mutation_headers(port, cookie, token)

        status, _, _ = request(
            port,
            "POST",
            "/api/cases",
            body=payload,
            headers={"Content-Type": "application/json"},
        )
        assert status == 403
        status, _, _ = request(
            port,
            "POST",
            "/api/cases",
            body=payload,
            headers={**valid_headers, "Origin": "https://attacker.invalid"},
        )
        assert status == 403
        status, _, _ = request(
            port,
            "POST",
            "/api/cases",
            body=payload,
            headers={**valid_headers, "X-CSRF-Token": "wrong"},
        )
        assert status == 403

        status, _, body = request(port, "POST", "/api/cases", body=payload, headers=valid_headers)
        assert status == 201
        assert json.loads(body) == api.case
        for action in ("cancel", "resume"):
            status, _, _ = request(
                port,
                "POST",
                f"/api/cases/{case_id}/{action}",
                body=b"{}",
                headers=valid_headers,
            )
            assert status == 200

    assert ("start_case", "Explain the recurring freeze", 30_000, 6) in api.calls
    assert ("cancel_case", case_id) in api.calls
    assert ("resume_case", case_id) in api.calls


@pytest.mark.parametrize(
    ("payload", "content_type"),
    [
        (
            {"objective": "x", "budget_ms": 1000, "max_rounds": 2, "command": "whoami"},
            "application/json",
        ),
        ({"objective": "x", "budget_ms": True, "max_rounds": 2}, "application/json"),
        ({"objective": "x", "budget_ms": 99, "max_rounds": 2}, "application/json"),
        ({"objective": "x", "budget_ms": 600_001, "max_rounds": 2}, "application/json"),
        ({"objective": " ", "budget_ms": 1000, "max_rounds": 2}, "application/json"),
        ({"objective": "x", "budget_ms": 1000, "max_rounds": 0}, "application/json"),
        ({"objective": "x", "budget_ms": 1000, "max_rounds": 13}, "application/json"),
        ({"objective": "x", "budget_ms": 1000, "max_rounds": 2}, "text/plain"),
    ],
)
def test_start_case_rejects_invalid_or_expansive_input(
    payload: dict[str, object], content_type: str
) -> None:
    api = FakeAPI()
    with running_server(api) as (_, port):
        cookie, token = browser_session(port)
        headers = mutation_headers(port, cookie, token)
        headers["Content-Type"] = content_type
        status, _, body = request(
            port,
            "POST",
            "/api/cases",
            body=json.dumps(payload).encode(),
            headers=headers,
        )

    assert status in {400, 415}
    assert "start_case" not in {call[0] for call in api.calls}
    assert set(json.loads(body)) == {"error"}


def test_transport_rejects_oversized_bodies_bad_hosts_routes_and_methods() -> None:
    api = FakeAPI()
    with running_server(api) as (_, port):
        cookie, token = browser_session(port)
        headers = mutation_headers(port, cookie, token)
        status, _, _ = request(
            port, "POST", "/api/cases", body=b"{" + (b"x" * 16_384), headers=headers
        )
        assert status == 413
        status, _, _ = request(port, "GET", "/api/cases?path=C:%5CWindows")
        assert status == 404
        status, _, _ = request(port, "GET", "/api/cases/not-a-case")
        assert status == 404
        status, _, _ = request(port, "PUT", "/api/cases")
        assert status == 405
        status, headers, body = request(port, "OPTIONS", "/api/cases")
        assert status == 405
        assert headers["content-type"].startswith("application/json")
        assert json.loads(body)["error"]["code"] == "method_not_allowed"
        status, _, _ = request(port, "GET", "/api/cases", headers={"Host": "attacker.invalid"})
        assert status == 403


def test_untrusted_case_text_is_only_returned_as_json_not_interpolated_into_html() -> None:
    api = FakeAPI()
    with running_server(api) as (_, port):
        _, _, document = request(port, "GET", "/")
        _, headers, body = request(port, "GET", "/api/cases")

    attack = "<img src=x onerror=alert(1)>"
    assert attack not in document.decode("utf-8")
    assert attack in body.decode("utf-8")
    assert headers["content-type"].startswith("application/json")


def test_start_case_accepts_coordinator_upper_bounds() -> None:
    api = FakeAPI()
    payload = {"objective": "Bounded investigation", "budget_ms": 600_000, "max_rounds": 12}
    with running_server(api) as (_, port):
        cookie, token = browser_session(port)
        status, _, _ = request(
            port,
            "POST",
            "/api/cases",
            body=json.dumps(payload).encode(),
            headers=mutation_headers(port, cookie, token),
        )

    assert status == 201
    assert ("start_case", "Bounded investigation", 600_000, 12) in api.calls


def test_recorder_uses_same_permission_boundary_and_strict_budgets() -> None:
    api = FakeAPI()
    with running_server(api) as (_, port):
        cookie, token = browser_session(port)
        headers = mutation_headers(port, cookie, token)
        assert request(port, "GET", "/api/recorder")[0] == 200
        assert request(port, "POST", "/api/recorder/start", body=b"{}")[0] == 403
        for payload in (
            {"interval_seconds": True},
            {"interval_seconds": 1},
            {"max_cycles": 289},
            {"command": "anything"},
        ):
            assert (
                request(
                    port,
                    "POST",
                    "/api/recorder/start",
                    body=json.dumps(payload).encode(),
                    headers=headers,
                )[0]
                == 400
            )
        assert (
            request(
                port,
                "POST",
                "/api/recorder/start",
                body=b'{"interval_seconds":30,"max_cycles":2}',
                headers=headers,
            )[0]
            == 200
        )
        assert (
            request(
                port,
                "POST",
                "/api/recorder/stop",
                body=b"{}",
                headers=headers,
            )[0]
            == 200
        )
    assert ("start_recorder", 30, 2) in api.calls
    assert ("stop_recorder",) in api.calls
