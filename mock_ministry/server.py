"""Standard-library HTTP receiver for local ministry-side mock checks."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from .recorder import FileRecorder


ACCEPTED_RESPONSE = {"statusCode": 0, "statusText": "mock accepted", "rspMsgCnt": ""}
POST_PATHS = {"/ministry/receive", "/ministry/file"}


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_handler(recorder: FileRecorder | None = None) -> type[BaseHTTPRequestHandler]:
    class MinistryMockHandler(BaseHTTPRequestHandler):
        server_version = "MinistryMock/0.1"

        def do_GET(self) -> None:
            parsed_path = urlparse(self.path).path
            if parsed_path == "/health":
                payload = {"status": "ok"}
                self._record("", payload, 200)
                self._send_json(200, payload)
                return

            payload = {"statusCode": 404, "statusText": "not found", "rspMsgCnt": ""}
            self._record("", payload, 404)
            self._send_json(404, payload)

        def do_POST(self) -> None:
            parsed_path = urlparse(self.path).path
            body = self._read_body()

            if parsed_path in POST_PATHS:
                payload = dict(ACCEPTED_RESPONSE)
                self._record(body.decode("utf-8", errors="replace"), payload, 200)
                self._send_json(200, payload)
                return

            payload = {"statusCode": 404, "statusText": "not found", "rspMsgCnt": ""}
            self._record(body.decode("utf-8", errors="replace"), payload, 404)
            self._send_json(404, payload)

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _read_body(self) -> bytes:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            return self.rfile.read(content_length) if content_length else b""

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _record(self, body: str, payload: dict[str, Any], status: int) -> None:
            if recorder is None:
                return

            recorder.record(
                method=self.command,
                path=self.path,
                headers={key: value for key, value in self.headers.items()},
                body=body,
                response={
                    "status": status,
                    "headers": {"Content-Type": "application/json; charset=utf-8"},
                    "body": payload,
                },
            )

    return MinistryMockHandler


def create_server(
    host: str = "127.0.0.1",
    port: int = 18080,
    recorder: FileRecorder | None = None,
) -> ThreadingHTTPServer:
    active_recorder = recorder or FileRecorder()
    server = ThreadingHTTPServer((host, port), make_handler(active_recorder))
    server.recorder = active_recorder  # type: ignore[attr-defined]
    return server


def serve(host: str = "127.0.0.1", port: int = 18080, recorder: FileRecorder | None = None) -> None:
    server = create_server(host=host, port=port, recorder=recorder)
    try:
        server.serve_forever()
    finally:
        server.server_close()
