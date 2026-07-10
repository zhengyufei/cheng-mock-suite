from __future__ import annotations

import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from mock_ministry.mocks.protocol_ministry_platform.runner import (
    DEFAULT_SEND_CASES,
    run_refactor_check,
)


class FakeBackendHandler(BaseHTTPRequestHandler):
    received_paths: list[str] = []
    body = {
        "orderID": "2-302-2026070400000000001",
        "statusCode": 0,
        "statusText": "fake backend accepted",
        "rspMsgCnt": "cipher",
    }
    extra_headers: dict[str, str] = {
        "X-Enc-Key": "key",
        "X-Enc-Key-G": "group-key",
        "X-Enc-Nonce": "nonce",
        "X-Enc-Auth-Tag": "tag",
        "X-Enc-Auth-Tag-File": "file-tag",
    }

    def do_POST(self):
        FakeBackendHandler.received_paths.append(self.path)
        length = int(self.headers.get("Content-Length", "0") or "0")
        self.rfile.read(length)
        response_payload = (
            FakeBackendHandler.body(self.path)
            if callable(FakeBackendHandler.body)
            else FakeBackendHandler.body
        )
        response_body = (
            response_payload
            if isinstance(response_payload, str)
            else json.dumps(response_payload)
        )
        body = response_body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        for key, value in FakeBackendHandler.extra_headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def _set_backend_response(
    body,
    headers: dict[str, str] | None = None,
) -> None:
    FakeBackendHandler.body = body
    FakeBackendHandler.extra_headers = headers or {
        "X-Enc-Key": "key",
        "X-Enc-Key-G": "group-key",
        "X-Enc-Nonce": "nonce",
        "X-Enc-Auth-Tag": "tag",
        "X-Enc-Auth-Tag-File": "file-tag",
    }


def test_runner_sends_selected_fixture_to_running_backend(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-302-2026070500000000001",
            "statusCode": 0,
            "statusText": "fake backend accepted",
            "rspMsgCnt": "cipher",
        }
    )
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


def test_contract_runner_fails_on_http_200_business_error(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-302-2026070500000000001",
            "statusCode": 133,
            "statusText": "system exception",
            "rspMsgCnt": "cipher",
        }
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["policy_302"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    backend_report = result["report"]["sections"]["backend"]

    assert result["report"]["ok"] is False
    assert backend_report["ok"] is False
    assert "policy_302 returned business statusCode 133" in backend_report["failures"]


def test_contract_runner_accepts_unknown_subtype_status_one(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-399-2026070500000000001",
            "statusCode": 1,
            "statusText": "id not found",
            "rspMsgCnt": "cipher",
        }
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["unknown_subtype_399"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    assert result["report"]["ok"] is True
    assert result["report"]["sections"]["backend"]["ok"] is True


def test_contract_runner_sends_negative_case_with_expected_status(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-101-2026070500000000001",
            "statusCode": 6,
            "statusText": "missing required param",
            "rspMsgCnt": "cipher",
        }
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=[],
            negative_cases=["missing_tskRspParams"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    assert result["report"]["ok"] is True
    assert result["backend_calls"][0]["case"] == "missing_tskRspParams"
    assert result["backend_calls"][0]["fixture_case"] == "warning_task_8_callback"
    assert result["backend_calls"][0]["expected_business_status"] == 6
    assert FakeBackendHandler.received_paths == ["/api/ministry/receive"]


def test_contract_runner_rejects_307_negative_inner_business_success(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-307-2026070300000000001",
            "statusCode": 0,
            "statusText": "fake backend accepted",
            "rspMsgCnt": json.dumps({"tstResParams": {"tstProcRslt": 0}}),
        }
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=[],
            negative_cases=["missing_test_data_tst_type"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    backend_report = result["report"]["sections"]["backend"]

    assert result["report"]["ok"] is False
    assert backend_report["ok"] is False
    assert result["backend_calls"][0]["expected_business_result"] == -1
    assert (
        "missing_test_data_tst_type returned tstProcRslt 0, expected -1"
        in backend_report["failures"]
    )


def test_contract_runner_marks_encrypted_positive_307_result_for_persistence_verification(
    tmp_path,
) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-307-2026070500000000003",
            "statusCode": 0,
            "statusText": "encrypted backend response",
            "rspMsgCnt": "encrypted-ciphertext",
        }
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["test_data_307_tst_type_3"],
            negative_cases=[],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    backend_report = result["report"]["sections"]["backend"]

    assert backend_report["ok"] is True
    assert backend_report["unverified_business_results"] == 1
    assert backend_report["failures"] == []
    assert backend_report["warnings"] == [
        "test_data_307_tst_type_3 returned encrypted rspMsgCnt; "
        "verify tstProcRslt=-1 through the acceptance persistence probe"
    ]


@pytest.mark.parametrize(
    "body, headers, failure",
    [
        (
            {
                "orderID": "2-302-2026070500000000001",
                "statusCode": 0,
                "statusText": "ok",
            },
            None,
            "policy_302 returned missing rspMsgCnt",
        ),
        (
            {
                "orderID": "2-302-2026070500000000001",
                "statusCode": 0,
                "rspMsgCnt": "cipher",
            },
            None,
            "policy_302 returned missing or invalid statusText",
        ),
        (
            {
                "orderID": "wrong",
                "statusCode": 0,
                "statusText": "ok",
                "rspMsgCnt": "cipher",
            },
            None,
            "policy_302 returned orderID 'wrong', expected '2-302-2026070500000000001'",
        ),
        (
            {
                "orderID": "2-302-2026070500000000001",
                "statusCode": 0,
                "statusText": "ok",
                "rspMsgCnt": "cipher",
            },
            {"X-Enc-Key": "key", "X-Enc-Key-G": "group-key", "X-Enc-Nonce": "nonce"},
            "policy_302 missing response header X-Enc-Auth-Tag",
        ),
    ],
)
def test_contract_runner_rejects_incomplete_response_envelope(
    tmp_path, body, headers, failure
) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(body, headers=headers)
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["policy_302"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    backend_report = result["report"]["sections"]["backend"]

    assert result["report"]["ok"] is False
    assert backend_report["ok"] is False
    assert failure in backend_report["failures"]


def test_contract_runner_rejects_unknown_subtype_system_exception(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-399-2026070500000000001",
            "statusCode": 133,
            "statusText": "system exception",
            "rspMsgCnt": "cipher",
        }
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["unknown_subtype_399"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    backend_report = result["report"]["sections"]["backend"]

    assert result["report"]["ok"] is False
    assert backend_report["ok"] is False
    assert (
        "unknown_subtype_399 returned business statusCode 133"
        in backend_report["failures"]
    )


@pytest.mark.parametrize(
    "backend_body, failure",
    [
        ({}, "policy_302 returned missing business statusCode"),
        ("not-json", "policy_302 returned invalid JSON body"),
        (
            {"statusCode": "abc"},
            "policy_302 returned non-integer business statusCode abc",
        ),
        ({"statusCode": "0"}, "policy_302 returned non-integer business statusCode 0"),
        (
            {"statusCode": 0.0},
            "policy_302 returned non-integer business statusCode 0.0",
        ),
        (
            {"statusCode": 0.9},
            "policy_302 returned non-integer business statusCode 0.9",
        ),
        (
            {"statusCode": True},
            "policy_302 returned non-integer business statusCode True",
        ),
    ],
)
def test_contract_runner_rejects_missing_or_invalid_business_status(
    tmp_path, backend_body, failure
) -> None:
    FakeBackendHandler.received_paths = []
    FakeBackendHandler.body = backend_body
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["policy_302"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    backend_report = result["report"]["sections"]["backend"]

    assert result["report"]["ok"] is False
    assert backend_report["ok"] is False
    assert failure in backend_report["failures"]


def test_runner_cli_does_not_duplicate_explicit_send_case(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    FakeBackendHandler.body = {
        "statusCode": 0,
        "statusText": "fake backend accepted",
        "rspMsgCnt": "",
    }
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


def test_runner_default_send_cases_match_manifest() -> None:
    manifest = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "fixtures"
            / "protocol_ministry_platform"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )

    assert DEFAULT_SEND_CASES == manifest["send_to_backend"]["default_send_cases"]


def test_runner_cli_default_suite_uses_manifest_representative_cases(tmp_path) -> None:
    FakeBackendHandler.received_paths = []

    def response_for_path(path: str) -> dict:
        order_id = (
            "2-103-2026070300000000001"
            if path == "/api/ministry/file"
            else "2-302-2026070500000000001"
        )
        return {
            "orderID": order_id,
            "statusCode": 0,
            "statusText": "fake backend accepted",
            "rspMsgCnt": "cipher",
        }

    _set_backend_response(response_for_path)
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
                "--mode",
                "observe",
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
    assert [call["case"] for call in payload["backend_calls"]] == [
        "policy_302",
        "prod_vul_workorder_5_request",
    ]
    assert FakeBackendHandler.received_paths == [
        "/api/ministry/receive",
        "/api/ministry/receive",
    ]


def test_contract_runner_rejects_file_case_missing_file_auth_tag(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-103-2026070300000000001",
            "statusCode": 0,
            "statusText": "fake backend accepted",
            "rspMsgCnt": "cipher",
        },
        headers={
            "X-Enc-Key": "key",
            "X-Enc-Key-G": "group-key",
            "X-Enc-Nonce": "nonce",
            "X-Enc-Auth-Tag": "tag",
        },
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["file_103"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    backend_report = result["report"]["sections"]["backend"]

    assert result["report"]["ok"] is False
    assert backend_report["ok"] is False
    assert (
        "file_103 missing response header X-Enc-Auth-Tag-File"
        in backend_report["failures"]
    )


def test_contract_runner_sends_file_case_to_ministry_file_endpoint(tmp_path) -> None:
    FakeBackendHandler.received_paths = []
    _set_backend_response(
        {
            "orderID": "2-103-2026070300000000001",
            "statusCode": 0,
            "statusText": "fake backend accepted",
            "rspMsgCnt": "cipher",
        }
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 0), FakeBackendHandler)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = backend.server_address
        result = run_refactor_check(
            backend_base_url=f"http://{host}:{port}",
            record_dir=tmp_path / "mock-server",
            mode="contract",
            send_cases=["file_103"],
            outbound_paths=[],
            mock_port=0,
        )
    finally:
        backend.shutdown()
        thread.join(timeout=5)
        backend.server_close()

    assert result["report"]["ok"] is True
    assert result["backend_calls"][0]["path"] == "/api/ministry/file"
    assert result["backend_calls"][0]["case"] == "file_103"
    assert FakeBackendHandler.received_paths == ["/api/ministry/file"]


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
