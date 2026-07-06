"""HTTP server for the protocol-level ministry platform mock."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from mock_ministry.recorder import FileRecorder

from .contracts import (
    FEATURE_INTERFACE_COVERAGE,
    LEGACY_PLATFORM_FILE_UPLOAD_PATH,
    PLATFORM_FILE_PATH,
    PLATFORM_POST_PATHS,
    PLATFORM_RECEIVE_PATH,
)
from .envelope import inspect_file_request, inspect_receive_body
from .responses import build_protocol_response


ACCEPTED_RESPONSE = {"statusCode": 0, "statusText": "mock accepted", "rspMsgCnt": ""}


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_handler(
    recorder: FileRecorder | None = None,
    *,
    scenario: str = "success",
) -> type[BaseHTTPRequestHandler]:
    class ProtocolMinistryPlatformHandler(BaseHTTPRequestHandler):
        server_version = "ProtocolMinistryPlatformMock/0.2"

        def do_GET(self) -> None:
            parsed_path = urlparse(self.path).path
            if parsed_path == "/health":
                payload = {"status": "ok", "mock": "protocol-ministry-platform"}
                self._record("", payload, 200, None)
                self._send_json(200, payload)
                return

            if parsed_path == "/contracts":
                payload = {
                    "mock": "protocol-ministry-platform",
                    "coverage": FEATURE_INTERFACE_COVERAGE,
                }
                self._record("", payload, 200, None)
                self._send_json(200, payload)
                return

            payload = {"statusCode": 404, "statusText": "not found", "rspMsgCnt": ""}
            self._record("", payload, 404, None)
            self._send_json(404, payload)

        def do_POST(self) -> None:
            parsed_path = urlparse(self.path).path
            body = self._read_body()
            headers = {key: value for key, value in self.headers.items()}

            if parsed_path == PLATFORM_RECEIVE_PATH:
                observation = inspect_receive_body(raw_body=body, headers=headers, path=parsed_path)
                response = build_protocol_response(observation, scenario=scenario)
                self._record(body.decode("utf-8", errors="replace"), response.body, response.http_status, observation.to_record())
                self._send_json(response.http_status, response.body)
                return

            if parsed_path in {PLATFORM_FILE_PATH, LEGACY_PLATFORM_FILE_UPLOAD_PATH}:
                observation = inspect_file_request(path=parsed_path, headers=headers, raw_body=body)
                response = build_protocol_response(observation, scenario=scenario)
                self._record(body.decode("utf-8", errors="replace"), response.body, response.http_status, observation.to_record())
                self._send_json(response.http_status, response.body)
                return

            if parsed_path in PLATFORM_POST_PATHS:
                payload = dict(ACCEPTED_RESPONSE)
                self._record(body.decode("utf-8", errors="replace"), payload, 200, None)
                self._send_json(200, payload)
                return

            payload = {"statusCode": 404, "statusText": "not found", "rspMsgCnt": ""}
            self._record(body.decode("utf-8", errors="replace"), payload, 404, None)
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

        def _record(self, body: str, payload: dict[str, Any], status: int, meta: dict[str, Any] | None) -> None:
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
                meta=meta,
            )

    return ProtocolMinistryPlatformHandler


def create_server(
    host: str = "127.0.0.1",
    port: int = 18080,
    recorder: FileRecorder | None = None,
    *,
    scenario: str = "success",
) -> ThreadingHTTPServer:
    active_recorder = recorder or FileRecorder()
    server = ThreadingHTTPServer((host, port), make_handler(active_recorder, scenario=scenario))
    server.recorder = active_recorder  # type: ignore[attr-defined]
    return server


def serve(
    host: str = "127.0.0.1",
    port: int = 18080,
    recorder: FileRecorder | None = None,
    *,
    scenario: str = "success",
) -> None:
    server = create_server(host=host, port=port, recorder=recorder, scenario=scenario)
    try:
        server.serve_forever()
    finally:
        server.server_close()

