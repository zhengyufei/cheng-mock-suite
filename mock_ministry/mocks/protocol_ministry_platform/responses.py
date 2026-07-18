"""Response policy for the protocol-level ministry platform mock."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from .contracts import KNOWN_PROTOCOL_SUBTYPES
from .crypto import ProtocolCrypto, generate_response_sign
from .envelope import ProtocolObservation


@dataclass(frozen=True)
class ProtocolResponse:
    http_status: int
    body: dict[str, Any]
    headers: dict[str, str] | None = None


def build_protocol_response(
    observation: ProtocolObservation,
    *,
    scenario: str = "success",
) -> ProtocolResponse:
    """Build a deterministic ministry-style response for one observation."""

    if not observation.is_valid:
        return ProtocolResponse(
            http_status=400,
            body={
                "statusCode": 400,
                "statusText": "; ".join(observation.errors),
                "rspMsgCnt": "",
            },
        )

    if observation.endpoint_role in {"platform_file", "legacy_platform_file"}:
        return _build_file_response(observation, scenario)

    if observation.sub_type is not None and observation.sub_type not in KNOWN_PROTOCOL_SUBTYPES:
        return ProtocolResponse(
            http_status=200,
            body={
                "statusCode": 404,
                "statusText": f"unsupported subtype {observation.sub_type}",
                "rspMsgCnt": "",
            },
        )

    if scenario == "reject":
        return ProtocolResponse(
            http_status=200,
            body={
                "statusCode": 1,
                "statusText": "mock rejected by configured scenario",
                "rspMsgCnt": "",
            },
        )

    injected = {
        "interface11_failure": (104, 200, 1, "configured interface 11 failure"),
        "interface12_failure": (105, 200, 1, "configured interface 12 failure"),
        "business201_failure": (201, 200, 1, "configured interface 201 failure"),
        "business202_failure": (202, 200, 1, "configured interface 202 failure"),
        "business203_failure": (203, 200, 1, "configured interface 203 failure"),
        "timeout": (None, 504, 504, "configured timeout"),
        "duplicate": (None, 200, 409, "duplicate request replay"),
    }.get(scenario)
    if injected is not None:
        subtype, http_status, status_code, status_text = injected
        if subtype is None or observation.sub_type == subtype:
            return ProtocolResponse(
                http_status=http_status,
                body={"statusCode": status_code, "statusText": status_text, "rspMsgCnt": ""},
            )

    return ProtocolResponse(
        http_status=200,
        body={"statusCode": 0, "statusText": "success.", "rspMsgCnt": ""},
    )


def encrypt_protocol_response(
    response: ProtocolResponse,
    observation: ProtocolObservation,
    crypto: ProtocolCrypto,
) -> ProtocolResponse:
    outer = {
        "orderID": observation.order_id or "",
        "statusCode": response.body.get("statusCode", 1),
        "statusText": response.body.get("statusText", "mock error"),
    }
    plaintext = _response_plaintext(observation, outer, crypto)
    encrypted = crypto.encrypt_payload(
        json.dumps(plaintext, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        legacy_key_wrap=True,
    )
    return ProtocolResponse(
        http_status=response.http_status,
        body={**outer, "rspMsgCnt": encrypted.ciphertext},
        headers=encrypted.headers,
    )


def _response_plaintext(
    observation: ProtocolObservation,
    outer: dict[str, Any],
    crypto: ProtocolCrypto,
) -> dict[str, Any]:
    if observation.endpoint_role in {"platform_file", "legacy_platform_file"}:
        plaintext: dict[str, Any] = {"dataType": 0, "dataSubType": 0}
    elif observation.message_family == "data":
        plaintext = {
            "dataType": observation.order_type,
            "dataSubType": observation.sub_type,
        }
    else:
        plaintext = {
            "orderType": observation.order_type,
            "orderSubType": observation.sub_type,
        }
    plaintext["timeStamp"] = str(int(time.time()))
    plaintext["sign"] = generate_response_sign(outer, crypto.keys.province_public_key)
    if observation.sub_type in {102, 103, 104, 105}:
        plaintext["tskRspParams"] = {
            "tskProcIndication": 100,
            "logNum": -1,
            "prcVulNum": -1,
            "prcPwNum": -1,
            "toPrcAstNum": 1,
            "prcAstNum": 1,
            "exRsnLst": [-1] * 8,
            "exRsnNumLst": [-1] * 8,
        }
    elif observation.sub_type == 308:
        engine_hash = "a" * 32
        if isinstance(observation.inner, dict):
            rows = observation.inner.get("engLst", {}).get("engDevs", [])
            if rows and isinstance(rows[0], dict):
                engine_hash = rows[0].get("engHash", engine_hash)
        plaintext["engRegParams"] = {
            "engNum": 1,
            "engRegInfo": [{"engHash": engine_hash, "regRslt": 0}],
        }
    elif observation.sub_type == 301:
        request = observation.inner.get("registerReqParams", {}) if isinstance(observation.inner, dict) else {}
        plaintext["registerResParams"] = {
            "devHash": request.get("devHash", "a" * 32),
            "devIp": request.get("devIp", "127.0.0.1"),
            "devType": "data_platform",
            "status": "0",
            "curVer": "mock-1.0",
            "vulVer": "mock-1.0",
            "updateTime": plaintext["timeStamp"],
        }
    return plaintext


def _build_file_response(observation: ProtocolObservation, scenario: str) -> ProtocolResponse:
    total = observation.file_total_chunks or 1
    chunk = observation.file_chunk_id or 1
    scenario_status = {
        "file_completed": (0, "completed", "Unpacking completed successfully."),
        "file_failed": (1, "failed", "File transfer failed."),
        "unpack_failed": (1, "failed", "File is damaged or has an invalid archive format."),
        "file_receiving": (0, "receiving", "Waiting for remaining chunks."),
        "file_partial": (1, "partial", "Only part of the file was received."),
    }
    if scenario in scenario_status:
        status_code, unpack_status, message = scenario_status[scenario]
    elif scenario == "success":
        unpack_status = observation.chunk_state or "receiving"
        status_code = 0 if unpack_status in {"receiving", "completed"} else 1
        message = observation.unpack_message or "Waiting for remaining chunks."
    elif scenario == "reject":
        status_code, unpack_status, message = 1, "failed", "File rejected by configured scenario."
    else:
        unpack_status = observation.chunk_state or "receiving"
        status_code = 0 if unpack_status in {"receiving", "completed"} else 1
        message = observation.unpack_message or "Mock file state accepted."

    received = list(observation.received_chunks)
    if unpack_status == "partial" and received:
        received = received[:-1]
    status_text = json.dumps(
        {
            "fileTotalChunk": total,
            "fileChunkID": chunk,
            "receivedChunks": received,
            "unpackStatus": unpack_status,
            "unpackMessage": message,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return ProtocolResponse(
        http_status=200,
        body={"statusCode": status_code, "statusText": status_text, "rspMsgCnt": ""},
    )

