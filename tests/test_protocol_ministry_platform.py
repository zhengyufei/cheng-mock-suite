from __future__ import annotations

import json
import threading
from urllib.request import Request, urlopen

from mock_ministry.mocks.protocol_ministry_platform.contracts import (
    BACKEND_FILE_PATH,
    BACKEND_RECEIVE_PATH,
    LEGACY_PLATFORM_FILE_UPLOAD_PATH,
    PLATFORM_FILE_PATH,
    PLATFORM_RECEIVE_PATH,
)
from mock_ministry.mocks.protocol_ministry_platform.envelope import (
    inspect_file_request,
    inspect_receive_body,
)
from mock_ministry.mocks.protocol_ministry_platform.responses import build_protocol_response
from mock_ministry.recorder import FileRecorder
from mock_ministry.server import create_server


def test_protocol_mock_paths_cover_current_feature_interfaces() -> None:
    assert BACKEND_RECEIVE_PATH == "/api/ministry/receive"
    assert BACKEND_FILE_PATH == "/api/ministry/file"
    assert PLATFORM_RECEIVE_PATH == "/ministry/receive"
    assert PLATFORM_FILE_PATH == "/ministry/file"
    assert LEGACY_PLATFORM_FILE_UPLOAD_PATH == "/api/v1/platformFileUpload"


def test_receive_inspector_extracts_data_subtype_from_plain_inner_message() -> None:
    body = {
        "orderID": "2-302-2026070300000000001",
        "orgCode": "MIIT",
        "ispCode": "CMCC",
        "ctxCode": 0,
        "reqMsgCnt": json.dumps(
            {"dataType": 2, "dataSubType": 302, "timeStamp": "20260703100000"},
            ensure_ascii=False,
        ),
    }

    observation = inspect_receive_body(
        raw_body=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    assert observation.is_valid
    assert observation.content_field == "reqMsgCnt"
    assert observation.order_id == "2-302-2026070300000000001"
    assert observation.order_type == 2
    assert observation.sub_type == 302
    assert observation.message_family == "data"
    assert not observation.encrypted_or_opaque


def test_receive_inspector_accepts_encrypted_response_with_orderid_fallback() -> None:
    body = {
        "orderID": "2-308-2026070300000000001",
        "statusCode": 0,
        "statusText": "success.",
        "rspMsgCnt": "opaque-ciphertext",
    }

    observation = inspect_receive_body(
        raw_body=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Enc-Key": "mock-key",
            "X-Enc-Key-G": "mock-key-g",
            "X-Enc-Nonce": "mock-nonce",
            "X-Enc-Auth-Tag": "mock-tag",
        },
    )

    assert observation.is_valid
    assert observation.content_field == "rspMsgCnt"
    assert observation.order_type == 2
    assert observation.sub_type == 308
    assert observation.message_family == "order"
    assert observation.encrypted_or_opaque
    assert observation.header_report["X-Enc-Key"] == "present"
    assert observation.header_report["X-Enc-Key-G"] == "present"


def test_unknown_subtype_returns_protocol_level_error_body() -> None:
    body = {
        "orderID": "2-999-2026070300000000001",
        "orgCode": "MIIT",
        "ispCode": "CMCC",
        "ctxCode": 0,
        "reqMsgCnt": json.dumps({"dataType": 2, "dataSubType": 999}, ensure_ascii=False),
    }
    observation = inspect_receive_body(
        raw_body=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

    response = build_protocol_response(observation)

    assert response.http_status == 200
    assert response.body["statusCode"] != 0
    assert "999" in response.body["statusText"]


def test_file_inspector_covers_protocol_and_current_legacy_file_paths() -> None:
    for path in (PLATFORM_FILE_PATH, LEGACY_PLATFORM_FILE_UPLOAD_PATH):
        observation = inspect_file_request(
            path=path,
            headers={"Content-Type": "multipart/form-data; boundary=mock"},
            raw_body=b"--mock\r\ncontent\r\n--mock--\r\n",
        )

        assert observation.is_valid
        assert observation.path == path
        assert observation.endpoint_role in {"platform_file", "legacy_platform_file"}


def test_server_records_protocol_metadata_for_receive_post(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="server")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        body = json.dumps(
            {
                "orderID": "2-301-2026070300000000001",
                "orgCode": "MIIT",
                "ispCode": "CMCC",
                "ctxCode": 0,
                "reqMsgCnt": json.dumps({"orderType": 2, "orderSubType": 301}),
            }
        ).encode("utf-8")
        request = Request(
            f"http://{host}:{port}{PLATFORM_RECEIVE_PATH}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200

        assert payload["statusCode"] == 0
        record = json.loads(recorder.path.read_text(encoding="utf-8").strip())
        assert record["path"] == PLATFORM_RECEIVE_PATH
        assert record["meta"]["mock"] == "protocol-ministry-platform"
        assert record["meta"]["endpoint_role"] == "platform_receive"
        assert record["meta"]["protocol"]["orderID"] == "2-301-2026070300000000001"
        assert record["meta"]["protocol"]["orderSubType"] == 301
        assert record["meta"]["validation"]["ok"] is True
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
