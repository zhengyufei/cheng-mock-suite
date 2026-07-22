from __future__ import annotations

import json

from mock_ministry.recorder import FileRecorder


def test_file_recorder_writes_jsonl(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="run")
    path = recorder.record(
        method="POST",
        path="/ministry/receive",
        headers={"Content-Type": "application/json"},
        body='{"hello":"world"}',
        response={"status": 200, "body": {"statusCode": 0}},
    )

    assert path == tmp_path / "run" / "requests.jsonl"
    assert path.is_file()
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["method"] == "POST"
    assert record["path"] == "/ministry/receive"
    assert record["response"]["status"] == 200


def test_recorder_redacts_credentials_and_crypto_headers_but_keeps_business_body(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="secure")
    recorder.record(
        method="POST",
        path="/ministry/receive",
        headers={
            "Authorization": "Bearer access-secret",
            "Cookie": "session=secret",
            "X-Enc-Key": "wrapped-secret",
            "X-Enc-Nonce": "nonce-secret",
            "X-Enc-Auth-Tag": "tag-secret",
            "X-Business": "visible",
        },
        body=json.dumps({"orderID": "2-104-2026071400000000001", "reqMsgCnt": "cipher"}),
        response={"status": 200, "body": {"statusCode": 0}},
        meta={"business": {"vulName": "keep-this-plaintext"}},
    )

    raw = recorder.path.read_text(encoding="utf-8")
    record = json.loads(raw)
    for secret in ("access-secret", "session=secret", "wrapped-secret", "nonce-secret", "tag-secret"):
        assert secret not in raw
    assert record["headers"]["X-Business"] == "visible"
    assert record["meta"]["business"]["vulName"] == "keep-this-plaintext"
    assert record["sequence"] == 1


def test_recorder_normalizes_sensitive_names_recursively_without_dropping_protocol_evidence(
    tmp_path,
) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="normalized")
    recorder.record(
        method="POST",
        path="/ministry/receive",
        headers={"X_Enc_Key": "outer-wrapped-key", "AUTH TAG": "outer-tag"},
        body=json.dumps(
            {
                "orderID": "2-307-2026071400000000060",
                "reqMsgCnt": "ciphertext-kept",
                "nested": [
                    {
                        "Access.Token": "access-secret",
                        "sm2 private_key": "sm2-secret",
                        "SM4-Session.Key": "sm4-secret",
                        "private_key": "generic-private-secret",
                        "ministry-private.key": "ministry-private-secret",
                        "privateKey": "camel-private-secret",
                        "privateKeyStatus": "business-visible",
                        "Nonce": "nonce-secret",
                    }
                ],
            }
        ),
        response={
            "statusCode": 0,
            "business": {"assetName": "keep asset", "Auth_Tag": "response-tag"},
        },
        meta={"business": {"vulInfoID": "keep-vulnerability"}},
    )

    raw = recorder.path.read_text(encoding="utf-8")
    record = json.loads(raw)
    for secret in (
        "outer-wrapped-key",
        "outer-tag",
        "access-secret",
        "sm2-secret",
        "sm4-secret",
        "generic-private-secret",
        "ministry-private-secret",
        "camel-private-secret",
        "nonce-secret",
        "response-tag",
    ):
        assert secret not in raw
    body = json.loads(record["body"])
    assert body["orderID"] == "2-307-2026071400000000060"
    assert body["reqMsgCnt"] == "ciphertext-kept"
    assert body["nested"][0]["privateKeyStatus"] == "business-visible"
    assert record["response"]["business"]["assetName"] == "keep asset"
    assert record["meta"]["business"]["vulInfoID"] == "keep-vulnerability"


def test_recorder_redacts_decrypted_nested_credentials_case_insensitively(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="decrypted-credentials")
    sentinels = {
        "ToKeN": "token-sentinel",
        "PASSWORD": "password-sentinel",
        "clientSecret": "secret-sentinel",
        "accessToken": "access-token-sentinel",
        "CoOkIe": "cookie-sentinel",
        "Auth": "auth-sentinel",
        "JWT": "jwt-exact-sentinel",
        "pipeline.JWT": "jwt-prefix-sentinel",
        "SM": "sm-exact-sentinel",
        "SM4Material": "sm-sentinel",
        "backend_SM2_GROUP_PUBLIC_KEY": "sm-prefix-sentinel",
        "X-Enc": "xenc-exact-sentinel",
        "X-Enc-Extra": "xenc-sentinel",
        "request_X-Enc-Auth-Tag-File": "xenc-prefix-sentinel",
    }
    recorder.record(
        method="POST",
        path="/ministry/receive",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"reqMsgCnt": "ciphertext"}),
        meta={
            "decrypted": {
                "business": {
                    "vulInfoID": "keep-vulnerability",
                    "nested": [sentinels],
                }
            }
        },
    )

    raw = recorder.path.read_text(encoding="utf-8")
    for sentinel in sentinels.values():
        assert sentinel not in raw
    record = json.loads(raw)
    assert record["meta"]["decrypted"]["business"]["vulInfoID"] == "keep-vulnerability"
