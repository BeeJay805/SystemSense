"""Tiny local application used only by the port-conflict canary."""

from __future__ import annotations

import argparse
import http.server
import socket


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/health":
            self.send_error(404)
            return
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args
        return


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-bind", action="store_true")
    args = parser.parse_args()
    if args.check_bind:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 8000))
        return 0
    with http.server.ThreadingHTTPServer(("127.0.0.1", 8000), HealthHandler) as server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
