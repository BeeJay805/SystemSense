"""Bounded replay of a source-bound health GET, never a general URL client."""

from __future__ import annotations

import http.client

from systemsense.domain.ids import JsonValue
from systemsense.domain.time import utc_now
from systemsense.packs.runtime import LoopbackReplayParametersV1


def collect_loopback_replay(parameters: dict[str, JsonValue]) -> dict[str, JsonValue]:
    target = LoopbackReplayParametersV1.model_validate(parameters)
    started = utc_now()
    status: int | None = None
    nonce_match: bool | None = None
    error_type: str | None = None
    outcome = "request_error"
    connection = http.client.HTTPConnection("127.0.0.1", target.port, timeout=2)
    try:
        connection.request("GET", f"/health/{target.nonce}", headers={"Cache-Control": "no-store"})
        response = connection.getresponse()
        status = response.status
        if status == 200:
            nonce_match = response.read(65) == (target.nonce + "\n").encode("ascii")
            outcome = "http_200_nonce_match" if nonce_match else "wrong_response"
        else:
            outcome = "http_503" if status == 503 else "http_other_status"
    except ConnectionRefusedError:
        outcome, error_type = "connection_refused", "ConnectionRefusedError"
    except TimeoutError:
        outcome, error_type = "timeout", "TimeoutError"
    except OSError as error:
        error_type = type(error).__name__
    finally:
        connection.close()
    finished = utc_now()
    return {
        "summary": f"The exact health GET replay ended in {outcome}.",
        "observed_at": finished.isoformat(),
        "captured_at": finished.isoformat(),
        "time_quality": "bounded_interval",
        "facts": {
            "loopback_replay": {
                "target_handle": f"127.0.0.1:{target.port}",
                "action": f"GET /health/{target.nonce}",
                "outcome": outcome,
                "http_status": status,
                "nonce_match": nonce_match,
                "error_type": error_type,
                "request_started_at": started.isoformat(),
                "request_finished_at": finished.isoformat(),
            }
        },
        "limitations": [
            "This later request tests recurrence; it cannot establish an earlier request's cause.",
            "No redirects, proxy, DNS, response content, or alternate targets were inspected.",
        ],
    }
