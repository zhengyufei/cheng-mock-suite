from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import tarfile
import threading
import time
from copy import deepcopy

import pytest
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from gmssl.sm2 import CryptSM2

from mock_ministry.mocks.protocol_ministry_platform.additional_fixtures import build_additional_fixture
from mock_ministry.mocks.protocol_ministry_platform.crypto import (
    ProtocolCrypto,
    ProtocolKeys,
    Sm4Gcm,
    derive_public_key,
    generate_protocol_sign,
)
from mock_ministry.mocks.protocol_ministry_platform import file_state as file_state_module
from mock_ministry.mocks.protocol_ministry_platform.file_state import FileTransferStateStore
from mock_ministry.mocks.protocol_ministry_platform.shared_fixtures import build_shared_fixture
from mock_ministry.recorder import FileRecorder
from mock_ministry.server import create_server

MINISTRY_PRIVATE_KEY = "1" * 64
PROVINCE_PRIVATE_KEY = "2" * 64
GROUP_PRIVATE_KEY = "3" * 64


def test_sm4_gcm_interoperates_with_cryptography() -> None:
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = b"ministry protocol interoperability"

    encryptor = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    assert Sm4Gcm(key).decrypt(nonce, ciphertext, encryptor.tag) == plaintext

    own_ciphertext, own_tag = Sm4Gcm(key).encrypt(nonce, plaintext)
    decryptor = Cipher(algorithms.SM4(key), modes.GCM(nonce, own_tag)).decryptor()
    assert decryptor.update(own_ciphertext) + decryptor.finalize() == plaintext


def _write_keys(monkeypatch, tmp_path) -> ProtocolKeys:
    ministry_private = tmp_path / "ministry-private.key"
    province_public = tmp_path / "province-public.key"
    group_public = tmp_path / "group-public.key"
    ministry_private.write_text(MINISTRY_PRIVATE_KEY, encoding="utf-8")
    province_public.write_text(derive_public_key(PROVINCE_PRIVATE_KEY), encoding="utf-8")
    group_public.write_text(derive_public_key(GROUP_PRIVATE_KEY), encoding="utf-8")
    monkeypatch.setenv("TEST_MODE", "false")
    monkeypatch.setenv("CHENG_MOCK_MINISTRY_PRIVATE_KEY_FILE", str(ministry_private))
    monkeypatch.setenv("CHENG_MOCK_PROVINCE_PUBLIC_KEY_FILE", str(province_public))
    monkeypatch.setenv("CHENG_MOCK_GROUP_PUBLIC_KEY_FILE", str(group_public))
    return ProtocolKeys.from_env()


@pytest.mark.parametrize("legacy_key_wrap", [False, True])
def test_strict_http_server_decrypts_verifies_and_encrypts_response(
    monkeypatch,
    tmp_path,
    legacy_key_wrap,
) -> None:
    keys = _write_keys(monkeypatch, tmp_path)
    crypto = ProtocolCrypto(keys)
    fixture = build_additional_fixture(11, "2026071400000000041")
    outer = {
        "orderID": fixture["orderID"],
        "orgCode": fixture["orgCode"],
        "ispCode": fixture["ispCode"],
        "ctxCode": fixture["ctxCode"],
        "reqMsgCnt": "",
    }
    fixture["inner"]["sign"] = generate_protocol_sign(outer, keys.province_public_key)
    encrypted = crypto.encrypt_payload(
        json.dumps(fixture["inner"], ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        recipient_public_key=keys.ministry_public_key,
        legacy_key_wrap=legacy_key_wrap,
    )
    outer["reqMsgCnt"] = encrypted.ciphertext

    recorder = FileRecorder(tmp_path, f"strict-http-{legacy_key_wrap}")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        response = requests.post(
            f"http://{host}:{port}/ministry/receive",
            json=outer,
            headers=encrypted.headers,
            timeout=5,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["statusCode"] == 0
    assert body["rspMsgCnt"] != ""
    response_crypto = ProtocolCrypto(
        ProtocolKeys(
            ministry_private_key=PROVINCE_PRIVATE_KEY,
            province_public_key=keys.ministry_public_key,
            group_public_key=keys.group_public_key,
        )
    )
    plaintext = response_crypto.decrypt_payload(body["rspMsgCnt"], response.headers)
    inner = json.loads(plaintext)
    assert set(inner) == {"orderType", "orderSubType", "timeStamp", "sign", "tskRspParams"}
    assert inner["orderType"] == 2
    assert inner["orderSubType"] == 104
    assert re.fullmatch(r"\d{10}|\d{14}", inner["timeStamp"])
    assert inner["tskRspParams"]["tskProcIndication"] == 100
    assert inner["tskRspParams"]["prcAstNum"] == 1
    signed_plaintext = CryptSM2(
        private_key=PROVINCE_PRIVATE_KEY,
        public_key=keys.province_public_key,
        mode=0,
    ).decrypt(base64.b64decode(inner["sign"], validate=True))
    assert signed_plaintext == (
        f'{body["orderID"]}{body["statusCode"]}{body["statusText"]}'.encode("utf-8")
    )

    record = json.loads(recorder.path.read_text(encoding="utf-8"))
    assert record["meta"]["business"]["orderSubType"] == 104
    assert record["meta"]["validation"]["ok"] is True
    assert fixture["inner"]["vulLst"]["keyLst"][0]["vulName"] in record["meta"]["business"]["vulLst"]["keyLst"][0]["vulName"]


def test_strict_http_server_rejects_bad_signature(monkeypatch, tmp_path) -> None:
    keys = _write_keys(monkeypatch, tmp_path)
    crypto = ProtocolCrypto(keys)
    fixture = build_additional_fixture(12, "2026071400000000042")
    fixture["inner"]["sign"] = "0" * 64
    encrypted = crypto.encrypt_payload(
        json.dumps(fixture["inner"], separators=(",", ":")).encode("utf-8"),
        recipient_public_key=keys.ministry_public_key,
        legacy_key_wrap=False,
    )
    outer = {
        "orderID": fixture["orderID"],
        "orgCode": fixture["orgCode"],
        "ispCode": fixture["ispCode"],
        "ctxCode": fixture["ctxCode"],
        "reqMsgCnt": encrypted.ciphertext,
    }
    server = create_server(host="127.0.0.1", port=0, recorder=FileRecorder(tmp_path, "bad-sign"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        response = requests.post(
            f"http://{host}:{port}/ministry/receive",
            json=outer,
            headers=encrypted.headers,
            timeout=5,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert response.status_code == 400
    assert response.json()["statusCode"] != 0


def _archive_bytes(file_id: str, business_name: str, *, valid_root: bool = True) -> bytes:
    stream = io.BytesIO()
    root = f"{file_id}_{business_name}" if valid_root else "wrong-root"
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        content = json.dumps(
            {
                "pwDictNum": 1,
                "pwLst": [
                    {
                        "pwDictID": 45,
                        "pwProto": "0",
                        "pwDTitle": "acceptance dictionary",
                        "pwDictType": 1,
                        "pwData": base64.b64encode(b"admin:password").decode("ascii"),
                    }
                ],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        member = tarfile.TarInfo(f"{root}/payload.json")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def _archive_with_member(root: str, member_name: str, *, member_type: bytes = tarfile.REGTYPE) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        member = tarfile.TarInfo(member_name)
        member.type = member_type
        if member_type in {tarfile.SYMTYPE, tarfile.LNKTYPE}:
            member.linkname = f"{root}/payload.json"
            archive.addfile(member)
        else:
            content = b"unsafe"
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def _business_json_archive(file_id: str, business_name: str, payload: object) -> bytes:
    root = f"{file_id}_{business_name}"
    content = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        member = tarfile.TarInfo(f"{root}/{business_name}")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def _system_vulnerability_file_payload(*, group_key: str = "vulID") -> dict:
    instance = deepcopy(
        build_shared_fixture(8, "2026071400000000066")["inner"]["vulInfoLst"]["comVulLst"][0][
            "instVulLst"
        ][0]
    )
    group_identifier = "MVM-2026-001" if group_key == "vulID" else "(32769:1)"
    return {
        "vulNum": 1,
        "engLst": {
            "engNum": 1,
            "engDevs": [{"engHash": "ACCEPTANCE-ENG-001", "engType": 32}],
        },
        "comVulLst": [
            {
                group_key: group_identifier,
                "assetNum": 1,
                "instVulLst": [instance],
            }
        ],
    }


def _encrypted_file_post(
    url: str,
    crypto: ProtocolCrypto,
    keys: ProtocolKeys,
    *,
    order_id: str,
    file_id: str,
    business_name: str,
    total: int,
    chunk_id: int,
    plaintext_chunk: bytes,
    bad_file_tag: bool = False,
    request_key: str | None = None,
):
    outer = {
        "orderID": order_id,
        "orgCode": "150000",
        "ispCode": "CM",
        "ctxCode": 2,
        "reqMsgCnt": "",
    }
    metadata = {
        "dataType": 0,
        "dataSubType": 0,
        "timeStamp": "1752500000",
        "sign": generate_protocol_sign(outer, keys.province_public_key),
    }
    encrypted = crypto.encrypt_payload(
        json.dumps(metadata, separators=(",", ":")).encode("utf-8"),
        recipient_public_key=keys.ministry_public_key,
        legacy_key_wrap=False,
    )
    file_ciphertext, file_tag = Sm4Gcm(encrypted.sm4_key).encrypt(encrypted.nonce, plaintext_chunk)
    headers = dict(encrypted.headers)
    headers["X-Enc-Auth-Tag-File"] = (
        "AAAAAAAAAAAAAAAAAAAAAA=="
        if bad_file_tag
        else base64.b64encode(file_tag).decode("ascii")
    )
    if request_key is not None:
        headers["X-Cheng-Request-Key"] = request_key
    outer["reqMsgCnt"] = encrypted.ciphertext
    return requests.post(
        url,
        data=outer,
        files={
            "fileChunk": (
                f"{file_id}_{business_name}_{total}_{chunk_id}.tar.gz.bin",
                file_ciphertext,
                "application/octet-stream",
            )
        },
        headers=headers,
        timeout=5,
    )


@pytest.mark.parametrize(
    ("scenario", "total_chunks", "expected_archive_digest"),
    [
        ("file_failed", 2, False),
        ("unpack_failed", 1, True),
    ],
)
def test_injected_terminal_file_failure_cleans_payload_before_response(
    monkeypatch,
    tmp_path,
    scenario: str,
    total_chunks: int,
    expected_archive_digest: bool,
) -> None:
    keys = _write_keys(monkeypatch, tmp_path)
    crypto = ProtocolCrypto(keys)
    recorder = FileRecorder(tmp_path, f"injected-{scenario}")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    order_id = f"0-0-20260714000000000{91 if total_chunks == 2 else 92}"
    file_id = ("d" if total_chunks == 2 else "e") * 32
    business_name = "password-dictionary.json"
    request_key = f"terminal-{scenario}"
    archive = _archive_bytes(file_id, business_name)
    plaintext_chunk = archive[: len(archive) // 2] if total_chunks == 2 else archive
    try:
        host, port = server.server_address
        base_url = f"http://{host}:{port}"
        configured = requests.post(
            f"{base_url}/__control/scenario",
            json={
                "scenario": scenario,
                "remaining": 1,
                "path": "/ministry/file",
                "orderID": order_id,
                "routeType": 0,
                "routeSubType": 0,
                "requestKey": request_key,
            },
            timeout=5,
        )
        response = _encrypted_file_post(
            f"{base_url}/ministry/file",
            crypto,
            keys,
            order_id=order_id,
            file_id=file_id,
            business_name=business_name,
            total=total_chunks,
            chunk_id=1,
            plaintext_chunk=plaintext_chunk,
            request_key=request_key,
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert configured.status_code == 200
    assert response.status_code == 200
    assert response.json()["statusCode"] != 0
    transfer_dirs = list((recorder.run_dir / "file-state").iterdir())
    assert len(transfer_dirs) == 1
    transfer_dir = transfer_dirs[0]
    payload_files = [
        path
        for path in transfer_dir.rglob("*")
        if path.is_file() and path.name != "state.json"
    ]
    assert payload_files == []
    state = json.loads((transfer_dir / "state.json").read_text(encoding="utf-8"))
    assert state["receivedBytes"] == 0
    assert state["discardedBytes"] == len(plaintext_chunk)
    assert state["chunkDigests"]["1"] == hashlib.sha256(plaintext_chunk).hexdigest()
    assert state["unpackStatus"] == "failed"
    assert scenario in state["unpackMessage"]
    assert state["internalFiles"] == []
    assert state["businessContents"] == []
    assert ("archiveSha256" in state) is expected_archive_digest


def _file_status(response) -> dict:
    return json.loads(response.json()["statusText"])


def test_strict_file_http_rejects_future_chunk_then_accepts_serial_chunks_and_replay(
    monkeypatch,
    tmp_path,
) -> None:
    keys = _write_keys(monkeypatch, tmp_path)
    crypto = ProtocolCrypto(keys)
    file_id = "f" * 32
    business_name = "password-dictionary.json"
    order_id = "0-0-2026071400000000046"
    archive = _archive_bytes(file_id, business_name)
    split = len(archive) // 2
    chunks = {1: archive[:split], 2: archive[split:]}
    recorder = FileRecorder(tmp_path, "strict-file")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        url = f"http://{host}:{port}/ministry/file"
        second = _encrypted_file_post(
            url,
            crypto,
            keys,
            order_id=order_id,
            file_id=file_id,
            business_name=business_name,
            total=2,
            chunk_id=2,
            plaintext_chunk=chunks[2],
        )
        first = _encrypted_file_post(
            url,
            crypto,
            keys,
            order_id=order_id,
            file_id=file_id,
            business_name=business_name,
            total=2,
            chunk_id=1,
            plaintext_chunk=chunks[1],
        )
        replay_first = _encrypted_file_post(
            url,
            crypto,
            keys,
            order_id=order_id,
            file_id=file_id,
            business_name=business_name,
            total=2,
            chunk_id=1,
            plaintext_chunk=chunks[1],
        )
        second_after_ack = _encrypted_file_post(
            url,
            crypto,
            keys,
            order_id=order_id,
            file_id=file_id,
            business_name=business_name,
            total=2,
            chunk_id=2,
            plaintext_chunk=chunks[2],
        )
        replay_completed = _encrypted_file_post(
            url,
            crypto,
            keys,
            order_id=order_id,
            file_id=file_id,
            business_name=business_name,
            total=2,
            chunk_id=2,
            plaintext_chunk=chunks[2],
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert second.status_code == first.status_code == replay_first.status_code == 200
    assert second.json()["statusCode"] != 0
    assert _file_status(second)["receivedChunks"] == []
    assert _file_status(first)["receivedChunks"] == [1]
    assert _file_status(first)["unpackStatus"] == "receiving"
    assert _file_status(replay_first) == _file_status(first)
    assert second_after_ack.json()["statusCode"] == 0
    assert _file_status(second_after_ack)["receivedChunks"] == [1, 2]
    assert _file_status(second_after_ack)["unpackStatus"] == "completed"
    assert replay_completed.json()["statusCode"] == 0
    assert _file_status(replay_completed) == _file_status(second_after_ack)
    assert second_after_ack.json()["rspMsgCnt"]
    assert second_after_ack.headers["X-Enc-Auth-Tag"]
    response_crypto = ProtocolCrypto(
        ProtocolKeys(
            ministry_private_key=PROVINCE_PRIVATE_KEY,
            province_public_key=keys.ministry_public_key,
            group_public_key=keys.group_public_key,
        )
    )
    file_inner = json.loads(
        response_crypto.decrypt_payload(
            second_after_ack.json()["rspMsgCnt"],
            second_after_ack.headers,
        )
    )
    assert set(file_inner) == {"dataType", "dataSubType", "timeStamp", "sign"}
    assert (file_inner["dataType"], file_inner["dataSubType"]) == (0, 0)
    signed_plaintext = CryptSM2(
        private_key=PROVINCE_PRIVATE_KEY,
        public_key=keys.province_public_key,
        mode=0,
    ).decrypt(base64.b64decode(file_inner["sign"], validate=True))
    file_outer = second_after_ack.json()
    assert signed_plaintext == (
        f'{file_outer["orderID"]}{file_outer["statusCode"]}{file_outer["statusText"]}'.encode("utf-8")
    )

    state_files = list((recorder.run_dir / "file-state").glob("*/state.json"))
    assert len(state_files) == 1
    state = json.loads(state_files[0].read_text(encoding="utf-8"))
    assert state["receivedChunks"] == [1, 2]
    assert state["unpackStatus"] == "completed"
    assert state["internalFiles"] == ["payload.json"]
    assert state["businessContents"] == [
        {
            "file": "payload.json",
            "kind": "password_dictionary",
            "recordCount": 1,
            "identifiers": ["45"],
            "protocolFields": ["pwDTitle", "pwData", "pwDictID", "pwDictType", "pwProto"],
        }
    ]
    assert re.fullmatch(r"[0-9a-f]{64}", state["archiveSha256"])
    assert re.fullmatch(r"[0-9a-f]{32}", state["archiveMd5"])
    assert (state_files[0].parent / "unpacked" / "payload.json").read_bytes().startswith(b"{")


@pytest.mark.parametrize(
    ("business_name", "content", "expected_kind", "expected_id"),
    [
        (
            "platform-log.json",
            b'1[{"logID":"ACCEPT-LOG-001","orderID":"2-104-2026071400000000066",'
            b'"timeStamp":"1752500000","devHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
            b'"logType":1080,"logLvl":1,"opCode":1,"opRslt":0,"content":{}}]',
            "platform_log",
            "ACCEPT-LOG-001",
        ),
    ],
)
def test_archive_business_content_is_decoded_and_summarized(
    tmp_path,
    business_name: str,
    content: bytes,
    expected_kind: str,
    expected_id: str,
) -> None:
    file_id = "9" * 32
    root = f"{file_id}_{business_name}"
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        member = tarfile.TarInfo(f"{root}/{business_name}")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="0-0-2026071400000000066",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=stream.getvalue(),
    )

    assert result.unpack_status == "completed", result.unpack_message
    assert len(result.business_contents) == 1
    assert result.business_contents[0]["kind"] == expected_kind
    assert result.business_contents[0]["recordCount"] == 1
    assert result.business_contents[0]["identifiers"] == [expected_id]


@pytest.mark.parametrize("group_key", ["vulID", "pwDictInstID"])
def test_system_vulnerability_file_accepts_grouped_vul_info_list(tmp_path, group_key: str) -> None:
    file_id = "7" * 32
    business_name = "system-vulnerabilities.json"
    payload = _system_vulnerability_file_payload(group_key=group_key)

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="2-307-2026071400000000066",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=_business_json_archive(file_id, business_name, payload),
    )

    assert result.unpack_status == "completed", result.unpack_message
    assert result.business_contents[0]["kind"] == "system_vulnerability"
    assert result.business_contents[0]["recordCount"] == 1
    assert result.business_contents[0]["identifiers"] == ["ACCEPT-SYS-2026071400000000066"]


def test_system_vulnerability_file_accepts_omitted_optional_instance_fields(tmp_path) -> None:
    file_id = "4" * 32
    business_name = "system-vulnerabilities.json"
    payload = _system_vulnerability_file_payload()
    instance = payload["comVulLst"][0]["instVulLst"][0]
    instance["vulInfoStat"] = 1
    for field in (
        "logIDLst",
        "lvRsn",
        "remedTime",
        "vulPort",
        "vulSvc",
        "vulInstCpe",
        "vulInstRunPath",
        "vulInstFilePath",
        "vulInstFileLoc",
        "vulInstOsCpe",
        "vulInstDevCpe",
        "assetOwnerinfo",
        "vulPriorMID",
    ):
        instance.pop(field, None)

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="2-307-2026071400000000064",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=_business_json_archive(file_id, business_name, payload),
    )

    assert result.unpack_status == "completed", result.unpack_message


def test_system_vulnerability_file_accepts_omitted_optional_engine_list(tmp_path) -> None:
    file_id = "2" * 32
    business_name = "system-vulnerabilities.json"
    payload = _system_vulnerability_file_payload()
    payload.pop("engLst")

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="1-203-2026071400000000062",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=_business_json_archive(file_id, business_name, payload),
    )

    assert result.unpack_status == "completed", result.unpack_message


def test_system_vulnerability_file_rejects_lv_reason_for_initial_state(tmp_path) -> None:
    file_id = "3" * 32
    business_name = "system-vulnerabilities.json"
    payload = _system_vulnerability_file_payload()
    instance = payload["comVulLst"][0]["instVulLst"][0]
    instance["vulInfoStat"] = 1
    instance["lvRsn"] = 101
    instance.pop("remedTime", None)

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="2-307-2026071400000000063",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=_business_json_archive(file_id, business_name, payload),
    )

    assert result.unpack_status == "failed"
    assert "lvRsn is only allowed" in result.unpack_message


def test_system_vulnerability_file_rejects_legacy_flat_rows(tmp_path) -> None:
    file_id = "6" * 32
    business_name = "system-vulnerabilities.json"
    payload = [
        {
            "vulInfoID": "ACCEPT-SYS-VUL-001",
            "vulID": "MVM-2026-001",
            "assetID": "ACCEPT-ASSET-001",
            "vulInfoStat": 1,
            "srcMethod": 1080,
            "transferTime": "1752500000",
        }
    ]

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="2-307-2026071400000000067",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=_business_json_archive(file_id, business_name, payload),
    )

    assert result.unpack_status == "failed"
    assert "VulInfoLst" in result.unpack_message


@pytest.mark.parametrize(
    ("invalid_case", "expected_message"),
    [
        ("vul_count", "vulNum"),
        ("engine_count", "engNum"),
        ("both_group_ids", "exactly one"),
        ("missing_group_id", "exactly one"),
        ("asset_count", "assetNum"),
        ("parent_id_in_instance", "vulID"),
    ],
)
def test_system_vulnerability_file_rejects_invalid_grouped_structure(
    tmp_path,
    invalid_case: str,
    expected_message: str,
) -> None:
    file_id = "5" * 32
    business_name = "system-vulnerabilities.json"
    payload = _system_vulnerability_file_payload()
    group = payload["comVulLst"][0]
    if invalid_case == "vul_count":
        payload["vulNum"] = 2
    elif invalid_case == "engine_count":
        payload["engLst"]["engNum"] = 2
    elif invalid_case == "both_group_ids":
        group["pwDictInstID"] = "(32769:1)"
    elif invalid_case == "missing_group_id":
        del group["vulID"]
    elif invalid_case == "asset_count":
        group["assetNum"] = 2
    elif invalid_case == "parent_id_in_instance":
        group["instVulLst"][0]["vulID"] = group["vulID"]

    result = FileTransferStateStore(tmp_path / invalid_case).accept_chunk(
        order_id="2-307-2026071400000000068",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=_business_json_archive(file_id, business_name, payload),
    )

    assert result.unpack_status == "failed"
    assert expected_message in result.unpack_message


def test_log_support_data_content_is_validated_and_summarized(tmp_path) -> None:
    file_id = "8" * 32
    business_name = "log-support-data.json"
    root = f"{file_id}_{business_name}"
    content = json.dumps(
        {
            "numLogIDs": 1,
            "numKeys": 3,
            "logInfo": [
                {"ACCEPT-LOG-001-target": "192.0.2.10"},
                {"ACCEPT-LOG-001-targetPort": "TCP:443"},
                {"ACCEPT-LOG-001-onlineAddr": "TCP:443@192.0.2.10"},
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        member = tarfile.TarInfo(f"{root}/{business_name}")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="0-0-2026071400000000066",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=stream.getvalue(),
    )

    assert result.unpack_status == "completed", result.unpack_message
    assert result.business_contents == (
        {
            "file": business_name,
            "kind": "log_support_data",
            "recordCount": 3,
            "identifiers": ["ACCEPT-LOG-001"],
            "protocolFields": ["logInfo", "numKeys", "numLogIDs"],
        },
    )


def test_system_vulnerability_inst_vul_with_missing_protocol_fields_fails_unpack(tmp_path) -> None:
    file_id = "8" * 32
    business_name = "system-vulnerabilities.json"
    payload = _system_vulnerability_file_payload()
    del payload["comVulLst"][0]["instVulLst"][0]["vulInfoID"]

    result = FileTransferStateStore(tmp_path / "state").accept_chunk(
        order_id="0-0-2026071400000000067",
        file_id=file_id,
        business_file_name=business_name,
        total_chunks=1,
        chunk_id=1,
        plaintext_chunk=_business_json_archive(file_id, business_name, payload),
    )

    assert result.unpack_status == "failed"
    assert "missing keys" in result.unpack_message


def test_upload_barrier_waits_until_control_release() -> None:
    from mock_ministry.mocks.protocol_ministry_platform.server import UploadBarrierController

    barrier = UploadBarrierController()
    barrier.configure("arm", timeout_seconds=1.0)
    completed = threading.Event()

    def upload() -> None:
        barrier.wait_if_armed()
        completed.set()

    thread = threading.Thread(target=upload)
    thread.start()
    try:
        deadline = time.monotonic() + 1.0
        while barrier.status()["entered"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert barrier.status()["entered"] == 1
        assert not completed.is_set()
        barrier.configure("release")
        thread.join(timeout=1.0)
        assert completed.is_set()
    finally:
        barrier.configure("release")
        thread.join(timeout=1.0)


def test_strict_file_http_rejects_bad_tag_and_invalid_tar_root(monkeypatch, tmp_path) -> None:
    keys = _write_keys(monkeypatch, tmp_path)
    crypto = ProtocolCrypto(keys)
    recorder = FileRecorder(tmp_path, "strict-file-errors")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        url = f"http://{host}:{port}/ministry/file"
        bad_tag = _encrypted_file_post(
            url,
            crypto,
            keys,
            order_id="0-0-2026071400000000047",
            file_id="a" * 32,
            business_name="data.json",
            total=1,
            chunk_id=1,
            plaintext_chunk=b"not-a-tar",
            bad_file_tag=True,
        )
        wrong_root = _encrypted_file_post(
            url,
            crypto,
            keys,
            order_id="0-0-2026071400000000048",
            file_id="b" * 32,
            business_name="data.json",
            total=1,
            chunk_id=1,
            plaintext_chunk=_archive_bytes("b" * 32, "data.json", valid_root=False),
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    assert bad_tag.status_code == 400
    assert bad_tag.json()["statusCode"] != 0
    assert wrong_root.status_code == 200
    assert wrong_root.json()["statusCode"] != 0
    assert _file_status(wrong_root)["unpackStatus"] == "failed"


def test_conflicting_duplicate_chunk_is_a_terminal_failure(tmp_path) -> None:
    store = FileTransferStateStore(tmp_path / "state")
    common = {
        "order_id": "0-0-2026071400000000049",
        "file_id": "c" * 32,
        "business_file_name": "data.json",
        "total_chunks": 2,
    }
    store.accept_chunk(**common, chunk_id=1, plaintext_chunk=b"original")
    conflict = store.accept_chunk(**common, chunk_id=1, plaintext_chunk=b"changed")
    later = store.accept_chunk(**common, chunk_id=2, plaintext_chunk=b"second")

    assert conflict.unpack_status == "failed"
    assert later.unpack_status == "failed"
    assert later.received_chunks == (1,)


def test_archive_rejects_windows_backslash_parent_traversal_before_writing(tmp_path) -> None:
    root = "d" * 32 + "_data.json"
    archive_path = tmp_path / "traversal.tar.gz"
    archive_path.write_bytes(
        _archive_with_member(root, f"{root}/nested\\..\\..\\escaped.txt")
    )

    with pytest.raises(ValueError, match="unsafe path"):
        FileTransferStateStore._validate_and_extract_archive(
            archive_path,
            expected_root=root,
            unpack_dir=tmp_path / "unpacked",
        )

    assert not (tmp_path / "escaped.txt").exists()


@pytest.mark.parametrize(
    "member_name",
    [
        "/absolute/payload.json",
        r"C:\payload.json",
        r"C:payload.json",
        r"\\server\share\payload.json",
    ],
)
def test_tar_member_normalization_rejects_absolute_drive_and_unc_names(member_name: str) -> None:
    normalizer = getattr(file_state_module, "_normalize_tar_member_name", None)
    assert callable(normalizer), "tar member names require one cross-platform normalizer"

    with pytest.raises(ValueError, match="unsafe path"):
        normalizer(member_name)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_archive_rejects_symbolic_and_hard_links(tmp_path, member_type: bytes) -> None:
    root = "e" * 32 + "_data.json"
    archive_path = tmp_path / "link.tar.gz"
    archive_path.write_bytes(_archive_with_member(root, f"{root}/link", member_type=member_type))

    with pytest.raises(ValueError, match="links are not allowed"):
        FileTransferStateStore._validate_and_extract_archive(
            archive_path,
            expected_root=root,
            unpack_dir=tmp_path / "unpacked",
        )
