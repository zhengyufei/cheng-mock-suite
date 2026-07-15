"""HTTP server for the protocol-level ministry platform mock."""

from __future__ import annotations

import json
import os
import threading
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
    SUPPORTED_SCENARIOS,
)
from .crypto import ProtocolCrypto, ProtocolKeys
from .envelope import inspect_file_request, inspect_receive_body
from .file_state import FileTransferStateStore
from .responses import build_protocol_response, encrypt_protocol_response


ACCEPTED_RESPONSE = {"statusCode": 0, "statusText": "success.", "rspMsgCnt": ""}
AUTH_REQUEST_KEYS = frozenset({"orgCode", "ispCode", "publicKey", "ip", "domain"})
AUTH_RESPONSE = {"accessToken": "mock-ministry-access-token", "expiresIn": 3600}
MAX_REQUEST_BYTES = 9 * 1024 * 1024
MAX_CONCURRENT_REQUESTS = 8


class RequestBodyError(ValueError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class RequestConcurrencyLimiter:
    def __init__(self, maximum: int) -> None:
        if type(maximum) is not int or maximum < 1:
            raise ValueError("maximum concurrent requests must be a positive integer")
        self._semaphore = threading.BoundedSemaphore(maximum)

    def acquire(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release(self) -> None:
        self._semaphore.release()


class ScenarioController:
    def __init__(self, scenario: str) -> None:
        if scenario != "success":
            raise ValueError("HTTP failure injection requires a route-scoped control target")
        self._arms: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._lock = threading.Lock()

    def configure(
        self,
        scenario: str,
        remaining: int = 0,
        *,
        path: str | None = None,
        order_id: str | None = None,
        route_type: int | None = None,
        route_subtype: int | None = None,
        request_key: str | None = None,
    ) -> dict[str, Any]:
        if scenario not in SUPPORTED_SCENARIOS:
            raise ValueError(f"unsupported scenario: {scenario}")
        if type(remaining) is not int or remaining < 0:
            raise ValueError("remaining must be a non-negative int")
        with self._lock:
            if scenario == "success":
                self._arms.clear()
                return self._status_locked()
            if remaining < 1:
                raise ValueError("failure injection remaining must be positive")
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValueError("failure injection path must be an absolute route")
            if not isinstance(order_id, str) or not order_id:
                raise ValueError("failure injection orderID must be non-empty")
            if type(route_type) is not int or type(route_subtype) is not int:
                raise ValueError("failure injection routeType/routeSubType must be integers")
            if request_key is not None and (not isinstance(request_key, str) or not request_key):
                raise ValueError("failure injection requestKey must be a non-empty string")
            target = {
                "path": path,
                "orderID": order_id,
                "routeType": route_type,
                "routeSubType": route_subtype,
                "requestKey": request_key,
            }
            arm = {"scenario": scenario, "remaining": remaining, "target": target}
            self._arms[self._target_key(target)] = arm
            return self._status_locked(selected=arm)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self._status_locked()

    @staticmethod
    def _target_key(target: dict[str, Any]) -> tuple[Any, ...]:
        return (
            target["path"],
            target["orderID"],
            target["routeType"],
            target["routeSubType"],
            target["requestKey"],
        )

    @staticmethod
    def _public_arm(arm: dict[str, Any]) -> dict[str, Any]:
        return {
            "scenario": arm["scenario"],
            "remaining": arm["remaining"],
            "target": dict(arm["target"]),
        }

    def _status_locked(self, *, selected: dict[str, Any] | None = None) -> dict[str, Any]:
        armed = [self._public_arm(arm) for arm in self._arms.values()]
        active = selected or (next(iter(self._arms.values())) if len(self._arms) == 1 else None)
        if active is None:
            scenario = "success" if not armed else "multiple"
            remaining = 0 if not armed else sum(arm["remaining"] for arm in armed)
            target = None
        else:
            scenario = active["scenario"]
            remaining = active["remaining"]
            target = dict(active["target"])
        return {
            "scenario": scenario,
            "remaining": remaining,
            "target": target,
            "armed": armed,
            "armedCount": len(armed),
        }

    def consume(self, observation: Any, *, request_key: str | None = None) -> str:
        with self._lock:
            for key, arm in tuple(self._arms.items()):
                expected = arm["target"]
                if (
                    observation.path != expected["path"]
                    or observation.order_id != expected["orderID"]
                    or observation.order_type != expected["routeType"]
                    or observation.sub_type != expected["routeSubType"]
                    or (
                        expected["requestKey"] is not None
                        and request_key != expected["requestKey"]
                    )
                ):
                    continue
                scenario = arm["scenario"]
                arm["remaining"] -= 1
                if arm["remaining"] == 0:
                    del self._arms[key]
                return scenario
            return "success"


class UploadBarrierController:
    """可控上传屏障，用于证明业务 ACK 与后台文件上传解耦。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._release = threading.Event()
        self._release.set()
        self._armed = False
        self._entered = 0
        self._timeout_seconds = 30.0

    def configure(self, action: str, *, timeout_seconds: float | None = None) -> dict[str, Any]:
        with self._lock:
            if action == "arm":
                if timeout_seconds is not None:
                    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
                        raise ValueError("timeoutSeconds must be positive")
                    self._timeout_seconds = float(timeout_seconds)
                self._entered = 0
                self._armed = True
                self._release.clear()
            elif action == "release":
                self._armed = False
                self._release.set()
            else:
                raise ValueError("upload barrier action must be arm or release")
            return self._status_locked()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return self._status_locked()

    def _status_locked(self) -> dict[str, Any]:
        return {
            "armed": self._armed,
            "entered": self._entered,
            "released": self._release.is_set(),
            "timeoutSeconds": self._timeout_seconds,
        }

    def wait_if_armed(self) -> None:
        with self._lock:
            if not self._armed:
                return
            self._entered += 1
            timeout_seconds = self._timeout_seconds
        if not self._release.wait(timeout_seconds):
            raise TimeoutError("upload barrier timed out before release")


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_handler(
    recorder: FileRecorder | None = None,
    *,
    scenario: str = "success",
    crypto: ProtocolCrypto | None = None,
    strict_crypto: bool = False,
    file_state: FileTransferStateStore | None = None,
    scenarios: ScenarioController | None = None,
    upload_barrier: UploadBarrierController | None = None,
    request_limiter: RequestConcurrencyLimiter | None = None,
) -> type[BaseHTTPRequestHandler]:
    class ProtocolMinistryPlatformHandler(BaseHTTPRequestHandler):
        server_version = "ProtocolMinistryPlatformMock/0.2"

        def do_GET(self) -> None:
            self._handle_bounded(self._handle_get)

        def do_POST(self) -> None:
            self._handle_bounded(self._handle_post)

        def _handle_bounded(self, callback: Any) -> None:
            if request_limiter is not None and not request_limiter.acquire():
                payload = {
                    "statusCode": 503,
                    "statusText": "request concurrency limit reached",
                    "rspMsgCnt": "",
                }
                self._send_json(503, payload)
                return
            try:
                callback()
            finally:
                if request_limiter is not None:
                    request_limiter.release()

        def _handle_get(self) -> None:
            parsed_path = urlparse(self.path).path
            if parsed_path == "/__control/upload-barrier":
                payload = (upload_barrier or UploadBarrierController()).status()
                self._send_json(200, payload)
                return
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

        def _handle_post(self) -> None:
            parsed_path = urlparse(self.path).path
            try:
                body = self._read_body()
            except RequestBodyError as exc:
                payload = {"statusCode": exc.status, "statusText": str(exc), "rspMsgCnt": ""}
                self._record(b"", payload, exc.status, {"resourceLimit": str(exc)})
                self._send_json(exc.status, payload)
                return
            headers = {key: value for key, value in self.headers.items()}

            if parsed_path == "/__control/scenario":
                try:
                    command = json.loads(body.decode("utf-8"))
                    if not isinstance(command, dict):
                        raise ValueError("control body must be object")
                    payload = (scenarios or ScenarioController(scenario)).configure(
                        str(command.get("scenario", "")),
                        command.get("remaining", 0),
                        path=command.get("path"),
                        order_id=command.get("orderID"),
                        route_type=command.get("routeType"),
                        route_subtype=command.get("routeSubType"),
                        request_key=command.get("requestKey"),
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    self._send_json(400, {"statusCode": 400, "statusText": str(exc)})
                    return
                self._record(body.decode("utf-8"), payload, 200, {"control": "scenario"})
                self._send_json(200, payload)
                return

            if parsed_path == "/__control/file-transfer":
                try:
                    command = json.loads(body.decode("utf-8"))
                    if not isinstance(command, dict):
                        raise ValueError("control body must be object")
                    if command.get("action") != "reset":
                        raise ValueError("file-transfer control action must be reset")
                    order_id = command.get("orderID")
                    file_id = command.get("fileID")
                    if not isinstance(order_id, str) or not order_id:
                        raise ValueError("file-transfer control orderID must be non-empty")
                    if file_id is not None and (not isinstance(file_id, str) or not file_id):
                        raise ValueError("file-transfer control fileID must be non-empty")
                    removed = (
                        file_state.reset_transfer(order_id=order_id, file_id=file_id)
                        if file_state is not None
                        else 0
                    )
                    payload = {
                        "action": "reset",
                        "orderID": order_id,
                        "removed": removed,
                    }
                    if file_id is not None:
                        payload["fileID"] = file_id
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    self._send_json(400, {"statusCode": 400, "statusText": str(exc)})
                    return
                self._record(body.decode("utf-8"), payload, 200, {"control": "file-transfer"})
                self._send_json(200, payload)
                return

            if parsed_path == "/__control/upload-barrier":
                try:
                    command = json.loads(body.decode("utf-8"))
                    if not isinstance(command, dict):
                        raise ValueError("control body must be object")
                    payload = (upload_barrier or UploadBarrierController()).configure(
                        str(command.get("action", "")),
                        timeout_seconds=command.get("timeoutSeconds"),
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    self._send_json(400, {"statusCode": 400, "statusText": str(exc)})
                    return
                self._record(body.decode("utf-8"), payload, 200, {"control": "upload-barrier"})
                self._send_json(200, payload)
                return

            if parsed_path == PLATFORM_RECEIVE_PATH:
                try:
                    auth_request = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    auth_request = None
                if isinstance(auth_request, dict) and set(auth_request) == AUTH_REQUEST_KEYS:
                    response = dict(AUTH_RESPONSE)
                    self._record(body, response, 200, {"authentication": "token_refresh"})
                    self._send_json(200, response)
                    return
                observation = inspect_receive_body(
                    raw_body=body,
                    headers=headers,
                    path=parsed_path,
                    crypto=crypto,
                    strict_crypto=strict_crypto,
                )
                response = build_protocol_response(
                    observation,
                    scenario=(
                        scenarios.consume(
                            observation,
                            request_key=self.headers.get("X-Cheng-Request-Key"),
                        )
                        if scenarios is not None
                        else "success"
                    ),
                )
                if crypto is not None:
                    response = encrypt_protocol_response(response, observation, crypto)
                self._record(
                    body,
                    response.body,
                    response.http_status,
                    observation.to_record(),
                    response.headers,
                )
                self._send_json(response.http_status, response.body, response.headers)
                return

            if parsed_path in {PLATFORM_FILE_PATH, LEGACY_PLATFORM_FILE_UPLOAD_PATH}:
                try:
                    if upload_barrier is not None:
                        upload_barrier.wait_if_armed()
                except TimeoutError as exc:
                    payload = {"statusCode": 504, "statusText": str(exc), "rspMsgCnt": ""}
                    self._record(body, payload, 504, None)
                    self._send_json(504, payload)
                    return
                observation = inspect_file_request(
                    path=parsed_path,
                    headers=headers,
                    raw_body=body,
                    crypto=crypto,
                    state_store=file_state,
                    strict_crypto=strict_crypto,
                )
                selected_scenario = (
                    scenarios.consume(
                        observation,
                        request_key=self.headers.get("X-Cheng-Request-Key"),
                    )
                    if scenarios is not None
                    else "success"
                )
                if (
                    selected_scenario in {"file_failed", "unpack_failed"}
                    and file_state is not None
                    and observation.order_id is not None
                    and observation.file_id is not None
                    and not observation.errors
                ):
                    terminal = file_state.fail_transfer(
                        order_id=observation.order_id,
                        file_id=observation.file_id,
                        message=f"Injected terminal scenario: {selected_scenario}.",
                    )
                    observation.chunk_state = terminal.unpack_status
                    observation.received_chunks = list(terminal.received_chunks)
                    observation.unpack_message = terminal.unpack_message
                    observation.internal_files = list(terminal.internal_files)
                    observation.business_contents = list(terminal.business_contents)
                response = build_protocol_response(
                    observation,
                    scenario=selected_scenario,
                )
                if crypto is not None:
                    response = encrypt_protocol_response(response, observation, crypto)
                self._record(
                    body,
                    response.body,
                    response.http_status,
                    observation.to_record(),
                    response.headers,
                )
                self._send_json(response.http_status, response.body, response.headers)
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
            raw_length = self.headers.get("Content-Length", "0") or "0"
            try:
                content_length = int(raw_length)
            except ValueError as exc:
                raise RequestBodyError(400, "Content-Length must be an integer") from exc
            if content_length < 0:
                raise RequestBodyError(400, "Content-Length must be non-negative")
            if content_length > MAX_REQUEST_BYTES:
                raise RequestBodyError(
                    413,
                    f"request body exceeds {MAX_REQUEST_BYTES} bytes",
                )
            return self.rfile.read(content_length) if content_length else b""

        def _send_json(
            self,
            status: int,
            payload: dict[str, Any],
            headers: dict[str, str] | None = None,
        ) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _record(
            self,
            body: str | bytes,
            payload: dict[str, Any],
            status: int,
            meta: dict[str, Any] | None,
            response_headers: dict[str, str] | None = None,
        ) -> None:
            if recorder is None:
                return

            recorder.record(
                method=self.command,
                path=self.path,
                headers={key: value for key, value in self.headers.items()},
                body=body,
                response={
                    "status": status,
                    "headers": {
                        "Content-Type": "application/json; charset=utf-8",
                        **(response_headers or {}),
                    },
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
    max_concurrent_requests: int = MAX_CONCURRENT_REQUESTS,
) -> ThreadingHTTPServer:
    strict_crypto = os.environ.get("TEST_MODE", "").strip().lower() == "false"
    crypto = ProtocolCrypto(ProtocolKeys.from_env()) if strict_crypto else None
    active_recorder = recorder or FileRecorder()
    file_state = FileTransferStateStore(active_recorder.run_dir / "file-state")
    scenarios = ScenarioController(scenario)
    upload_barrier = UploadBarrierController()
    request_limiter = RequestConcurrencyLimiter(max_concurrent_requests)
    server = ThreadingHTTPServer(
        (host, port),
        make_handler(
            active_recorder,
            scenario=scenario,
            crypto=crypto,
            strict_crypto=strict_crypto,
            file_state=file_state,
            scenarios=scenarios,
            upload_barrier=upload_barrier,
            request_limiter=request_limiter,
        ),
    )
    server.recorder = active_recorder  # type: ignore[attr-defined]
    server.upload_barrier = upload_barrier  # type: ignore[attr-defined]
    server.file_state = file_state  # type: ignore[attr-defined]
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

