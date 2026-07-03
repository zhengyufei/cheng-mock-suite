from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from mock_ministry.mocks.protocol_ministry_platform.runner import run_refactor_check


class FakeBackendHandler(BaseHTTPRequestHandler):
    received_paths: list[str] = []

    def do_POST(self):
        FakeBackendHandler.received_paths.append(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        self.rfile.read(length)
        body = json.dumps({"statusCode": 0, "statusText": "fake backend accepted", "rspMsgCnt": ""}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def test_runner_sends_selected_fixture_to_running_backend(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="observe",
            send_cases=["policy_302"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    assert result["backend_calls"][0]["case"] == "policy_302"
    assert result["backend_calls"][0]["path"] == "/api/ministry/receive"
    assert result["backend_calls"][0]["status"] == 200
    assert FakeBackendHandler.received_paths == ["/api/ministry/receive"]
    assert Path(result["record_file"]).is_file()
    assert result["report"]["ok"] is True
    assert result["report"]["sections"]["backend"]["ok"] is True
    assert result["report"]["sections"]["evidence"]["skipped"] is True


def test_runner_cli_does_not_duplicate_explicit_send_case(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = subprocess.run(
            [
                sys.executable,
                "tools/run_protocol_refactor_check.py",
                "--backend-base-url",
                f"http://{host}:{port}",
                "--record-dir",
                str(tmp_path / "mock-server"),
                "--mock-port",
                "0",
                "--send-case",
                "policy_302",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert len(payload["backend_calls"]) == 1
    assert FakeBackendHandler.received_paths == ["/api/ministry/receive"]


def test_runner_reports_backend_connection_failure_without_raising(tmp_path) -> None:
    result = run_refactor_check(
        backend_base_url="http://127.0.0.1:1",
        record_dir=tmp_path / "mock-server",
        mode="observe",
        send_cases=["policy_302"],
        outbound_paths=[],
        mock_port=0,
    )

    assert result["report"]["ok"] is False
    assert result["report"]["sections"]["backend"]["ok"] is False
    assert "request failed" in result["backend_calls"][0]["body"]
