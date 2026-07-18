"""Envelope inspection for the protocol-level ministry platform mock."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from typing import Any

from .contracts import (
    FILE_METADATA_KEYS,
    LEGACY_PLATFORM_FILE_UPLOAD_PATH,
    PLATFORM_CANONICAL_FILE_PATH,
    PLATFORM_FILE_PATH,
    PLATFORM_RECEIVE_SUBTYPE_INTERFACES,
    PROTOCOL_FILE_MAX_CHUNK_BYTES,
    TEST_DATA_SUBTYPE,
    TEST_TYPE_INTERFACES,
)
from .crypto import ProtocolCrypto, verify_protocol_sign
from .file_state import FileTransferStateStore
from .payloads import validate_business_payload


_ORDER_ID_RE = re.compile(r"^(?P<order_type>\d+)-(?P<sub_type>\d+)-(?P<sequence>\d{19})$")
_REQUEST_OUTER_KEYS = frozenset({"orderID", "orgCode", "ispCode", "ctxCode", "reqMsgCnt"})
_RESPONSE_OUTER_KEYS = frozenset({"orderID", "statusCode", "statusText", "rspMsgCnt"})
_ARCHIVE_NAME_RE = re.compile(
    r"^(?P<file_id>[0-9a-f]{32})_(?P<file_name>[^/\\]+)_"
    r"(?P<total>\d+)_(?P<chunk>\d+)\.tar\.gz\.bin$"
)
_ENCRYPT_HEADERS = ("X-Enc-Key", "X-Enc-Key-G", "X-Enc-Nonce", "X-Enc-Auth-Tag", "X-Enc-Auth-Tag-File")
_MAX_MULTIPART_PARTS = 32
_MAX_MULTIPART_FIELD_BYTES = 64 * 1024
_MAX_FILE_CHUNK_BYTES = PROTOCOL_FILE_MAX_CHUNK_BYTES


@dataclass
class ProtocolObservation:
    """Parsed protocol facts captured from one mock request."""

    endpoint_role: str
    path: str = ""
    order_id: str | None = None
    order_type: int | None = None
    sub_type: int | None = None
    message_family: str | None = None
    content_field: str | None = None
    encrypted_or_opaque: bool = False
    inner: dict[str, Any] | None = None
    file_name: str | None = None
    file_id: str | None = None
    business_file_name: str | None = None
    file_total_chunks: int | None = None
    file_chunk_id: int | None = None
    archive_directory: str | None = None
    chunk_state: str | None = None
    received_chunks: list[int] = field(default_factory=list)
    unpack_message: str | None = None
    internal_files: list[str] = field(default_factory=list)
    business_contents: list[dict[str, Any]] = field(default_factory=list)
    header_report: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def to_record(self) -> dict[str, Any]:
        return {
            "mock": "protocol-ministry-platform",
            "endpoint_role": self.endpoint_role,
            "protocol": {
                "orderID": self.order_id,
                "orderType": self.order_type,
                "orderSubType": self.sub_type,
                "messageFamily": self.message_family,
                "contentField": self.content_field,
                "encryptedOrOpaque": self.encrypted_or_opaque,
                "headers": self.header_report,
                "fileName": self.file_name,
                "fileID": self.file_id,
                "businessFileName": self.business_file_name,
                "fileTotalChunk": self.file_total_chunks,
                "fileChunkID": self.file_chunk_id,
                "archiveDirectory": self.archive_directory,
                "chunkState": self.chunk_state,
                "receivedChunks": self.received_chunks,
                "unpackMessage": self.unpack_message,
                "internalFiles": self.internal_files,
                "businessContents": self.business_contents,
            },
            "validation": {
                "ok": self.is_valid,
                "errors": self.errors,
                "warnings": self.warnings,
            },
            "business": self.inner,
        }


def _headers_report(headers: dict[str, str] | None) -> dict[str, str]:
    source = {key.lower(): value for key, value in (headers or {}).items()}
    report: dict[str, str] = {}
    for name in _ENCRYPT_HEADERS:
        value = source.get(name.lower(), "")
        report[name] = "present" if value else "missing"
    return report


def _parse_order_id(observation: ProtocolObservation, body: dict[str, Any]) -> None:
    order_id = body.get("orderID")
    if not order_id:
        observation.errors.append("missing orderID")
        return

    observation.order_id = str(order_id)
    match = _ORDER_ID_RE.match(observation.order_id)
    if not match:
        observation.errors.append(
            f"invalid orderID format; sequence must be exactly 19 digits: {observation.order_id}"
        )
        return

    observation.order_type = int(match.group("order_type"))
    observation.sub_type = int(match.group("sub_type"))


def _parse_inner_content(raw_content: Any, observation: ProtocolObservation) -> dict[str, Any] | None:
    if raw_content in (None, ""):
        return None

    if isinstance(raw_content, dict):
        return raw_content

    if not isinstance(raw_content, str):
        observation.encrypted_or_opaque = True
        observation.warnings.append("content is not a JSON string or object")
        return None

    stripped = raw_content.strip()
    if not stripped:
        return None

    if stripped[0] not in "{[":
        observation.encrypted_or_opaque = True
        return None

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        observation.encrypted_or_opaque = True
        observation.warnings.append("content looks like JSON but cannot be decoded")
        return None

    if isinstance(parsed, dict):
        return parsed

    observation.warnings.append("inner content JSON is not an object")
    return None


def _strict_route_value(observation: ProtocolObservation, value: Any, field: str) -> int | None:
    if type(value) is not int:
        observation.errors.append(f"invalid route field: {field}={value!r}")
        return None
    return value


def _matching_route_alias_value(
    observation: ProtocolObservation,
    inner: dict[str, Any],
    primary: str,
    secondary: str,
) -> int | None:
    primary_present = primary in inner and inner.get(primary) is not None
    secondary_present = secondary in inner and inner.get(secondary) is not None
    if not primary_present and not secondary_present:
        return None

    primary_value = _strict_route_value(observation, inner.get(primary), primary) if primary_present else None
    secondary_value = _strict_route_value(observation, inner.get(secondary), secondary) if secondary_present else None
    if primary_value is not None and secondary_value is not None and primary_value != secondary_value:
        observation.errors.append(
            f"conflicting route fields: {primary}={inner.get(primary)}, {secondary}={inner.get(secondary)}"
        )
        return None
    return primary_value if primary_value is not None else secondary_value


def _ensure_inner_route_matches_order_id(
    observation: ProtocolObservation,
    inner_type: int | None,
    inner_subtype: int | None,
) -> None:
    if (
        observation.order_type is not None
        and inner_type is not None
        and observation.order_type != inner_type
    ):
        observation.errors.append(
            f"payload route {inner_type}-{inner_subtype or observation.sub_type} "
            f"does not match orderID route {observation.order_type}-{observation.sub_type}"
        )
    if (
        observation.sub_type is not None
        and inner_subtype is not None
        and observation.sub_type != inner_subtype
    ):
        observation.errors.append(
            f"payload route {inner_type or observation.order_type}-{inner_subtype} "
            f"does not match orderID route {observation.order_type}-{observation.sub_type}"
        )


def _apply_inner_routing(observation: ProtocolObservation, inner: dict[str, Any] | None) -> None:
    if not inner:
        if observation.order_type is not None and observation.sub_type is not None:
            observation.message_family = "order"
        return

    if "dataType" in inner or "dataSubType" in inner:
        observation.message_family = "data"
    else:
        observation.message_family = "order"

    inner_type = _matching_route_alias_value(observation, inner, "orderType", "dataType")
    inner_subtype = _matching_route_alias_value(observation, inner, "orderSubType", "dataSubType")
    _ensure_inner_route_matches_order_id(observation, inner_type, inner_subtype)
    if inner_type is not None:
        observation.order_type = inner_type
    if inner_subtype is not None:
        observation.sub_type = inner_subtype


def _validate_additional_business_payload(
    observation: ProtocolObservation,
    inner: dict[str, Any] | None,
    *,
    ctx_code: int | None,
) -> None:
    if inner is None or observation.sub_type is None:
        return
    interface_no = PLATFORM_RECEIVE_SUBTYPE_INTERFACES.get(observation.sub_type)
    if observation.sub_type == TEST_DATA_SUBTYPE:
        params = inner.get("tstReqParams")
        if isinstance(params, dict):
            interface_no = TEST_TYPE_INTERFACES.get(params.get("tstType"))
    if interface_no is not None:
        observation.errors.extend(
            validate_business_payload(
                interface_no,
                inner,
                ctx_code=ctx_code,
                order_id=observation.order_id,
            )
        )


def inspect_receive_body(
    *,
    raw_body: bytes,
    headers: dict[str, str] | None,
    path: str = "/ministry/receive",
    crypto: ProtocolCrypto | None = None,
    strict_crypto: bool = False,
) -> ProtocolObservation:
    """Inspect a JSON envelope received by the protocol mock."""

    observation = ProtocolObservation(
        endpoint_role="platform_receive",
        path=path,
        header_report=_headers_report(headers),
    )

    try:
        body = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        observation.errors.append(f"invalid JSON body: {exc}")
        return observation

    if not isinstance(body, dict):
        observation.errors.append("JSON body must be an object")
        return observation

    content_field = "reqMsgCnt" if "reqMsgCnt" in body else "rspMsgCnt" if "rspMsgCnt" in body else None
    expected_outer = _REQUEST_OUTER_KEYS if content_field == "reqMsgCnt" else _RESPONSE_OUTER_KEYS
    missing_outer = expected_outer - set(body)
    extra_outer = set(body) - expected_outer
    if missing_outer:
        observation.errors.append(f"missing outer keys: {sorted(missing_outer)}")
    if extra_outer:
        observation.errors.append(f"unexpected outer keys: {sorted(extra_outer)}")
    if not isinstance(body.get("orderID"), str):
        observation.errors.append("orderID must be string")
    if content_field == "reqMsgCnt":
        for field in ("orgCode", "ispCode", "reqMsgCnt"):
            if not isinstance(body.get(field), str):
                observation.errors.append(f"{field} must be string")
        if type(body.get("ctxCode")) is not int:
            observation.errors.append("ctxCode must be int")
        expected_org_code = os.environ.get("CHENG_MOCK_EXPECTED_ORG_CODE", "").strip()
        if expected_org_code and body.get("orgCode") != expected_org_code:
            observation.errors.append(f"orgCode must match runner test code {expected_org_code}")
    elif content_field == "rspMsgCnt":
        if type(body.get("statusCode")) is not int:
            observation.errors.append("statusCode must be int")
        for field in ("statusText", "rspMsgCnt"):
            if not isinstance(body.get(field), str):
                observation.errors.append(f"{field} must be string")

    _parse_order_id(observation, body)

    if "reqMsgCnt" in body:
        observation.content_field = "reqMsgCnt"
    elif "rspMsgCnt" in body:
        observation.content_field = "rspMsgCnt"
    else:
        observation.errors.append("missing reqMsgCnt or rspMsgCnt")
        return observation

    raw_content = body.get(observation.content_field)
    if crypto is not None:
        try:
            raw_content = crypto.decrypt_payload(str(raw_content), headers or {}).decode("utf-8")
        except Exception as exc:
            observation.encrypted_or_opaque = True
            observation.errors.append(f"request decrypt failed: {exc}")
            return observation
    elif strict_crypto:
        observation.errors.append("strict crypto requires configured protocol keys")
        return observation
    inner = _parse_inner_content(raw_content, observation)
    observation.inner = inner
    if inner is None and body.get(observation.content_field) not in (None, ""):
        observation.errors.append("encrypted or opaque content could not be decrypted")
    _apply_inner_routing(observation, inner)
    _validate_additional_business_payload(observation, inner, ctx_code=body.get("ctxCode"))
    if crypto is not None and inner is not None and observation.content_field == "reqMsgCnt":
        if not verify_protocol_sign(inner, body, crypto.keys.province_public_key):
            observation.errors.append("business signature verification failed")
    return observation


def inspect_file_request(
    *,
    path: str,
    headers: dict[str, str] | None,
    raw_body: bytes,
    crypto: ProtocolCrypto | None = None,
    state_store: FileTransferStateStore | None = None,
    strict_crypto: bool = False,
) -> ProtocolObservation:
    """Inspect file-upload style requests accepted by the platform mock."""

    if path in {PLATFORM_FILE_PATH, PLATFORM_CANONICAL_FILE_PATH}:
        endpoint_role = "platform_file"
    elif path == LEGACY_PLATFORM_FILE_UPLOAD_PATH:
        endpoint_role = "legacy_platform_file"
    else:
        endpoint_role = "unknown_file"

    observation = ProtocolObservation(
        endpoint_role=endpoint_role,
        path=path,
        header_report=_headers_report(headers),
    )

    content_type = ""
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            content_type = value
            break

    if "multipart/form-data" not in content_type:
        observation.warnings.append("file request is not multipart/form-data")
    if not raw_body:
        observation.errors.append("empty file request body")
    if endpoint_role == "unknown_file":
        observation.errors.append(f"unsupported file path: {path}")

    if "multipart/form-data" not in content_type or not raw_body:
        return observation

    fields, file_name, file_content = _parse_multipart(content_type, raw_body, observation)
    if not fields and file_name is None:
        observation.errors.append("missing multipart fields and fileChunk")
        return observation

    observation.file_name = file_name
    required_form_fields = {"orderID", "orgCode", "ispCode", "ctxCode", "reqMsgCnt"}
    missing_fields = sorted(required_form_fields - set(fields))
    if missing_fields:
        observation.errors.append(f"missing multipart fields: {missing_fields}")

    for header in ("X-Enc-Auth-Tag", "X-Enc-Auth-Tag-File"):
        if observation.header_report.get(header) != "present":
            observation.errors.append(f"missing required header {header}")
    normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
    business_tag = normalized_headers.get("x-enc-auth-tag")
    file_tag = normalized_headers.get("x-enc-auth-tag-file")
    if business_tag and file_tag and business_tag == file_tag:
        observation.errors.append("X-Enc-Auth-Tag and X-Enc-Auth-Tag-File must be independent")

    if file_name is None:
        observation.errors.append("missing fileChunk multipart part")

    file_outer = dict(fields)
    if "ctxCode" in file_outer:
        try:
            file_outer["ctxCode"] = int(file_outer["ctxCode"])
        except (TypeError, ValueError):
            observation.errors.append("ctxCode must be int text")
    unexpected_fields = set(fields) - required_form_fields
    if unexpected_fields:
        observation.errors.append(f"unexpected multipart fields: {sorted(unexpected_fields)}")
    _parse_order_id(observation, fields)
    observation.content_field = "reqMsgCnt"
    raw_content: Any = fields.get("reqMsgCnt")
    plaintext_file = file_content
    if crypto is not None:
        try:
            raw_content = crypto.decrypt_payload(str(raw_content), headers or {}).decode("utf-8")
            plaintext_file = crypto.decrypt_file(file_content or b"", headers or {})
        except Exception as exc:
            observation.encrypted_or_opaque = True
            observation.errors.append(f"file request decrypt failed: {exc}")
            return observation
    elif strict_crypto:
        observation.errors.append("strict crypto requires configured protocol keys")
        return observation
    inner = _parse_inner_content(raw_content, observation)
    observation.inner = inner
    if inner is None:
        observation.errors.append("reqMsgCnt could not be decrypted into business JSON")
        return observation

    _validate_file_metadata(observation, inner, file_name)
    if crypto is not None and not verify_protocol_sign(inner, file_outer, crypto.keys.province_public_key):
        observation.errors.append("business signature verification failed")
    if (
        not observation.errors
        and state_store is not None
        and observation.order_id is not None
        and observation.file_id is not None
        and observation.business_file_name is not None
        and observation.file_total_chunks is not None
        and observation.file_chunk_id is not None
        and plaintext_file is not None
    ):
        state = state_store.accept_chunk(
            order_id=observation.order_id,
            file_id=observation.file_id,
            business_file_name=observation.business_file_name,
            total_chunks=observation.file_total_chunks,
            chunk_id=observation.file_chunk_id,
            plaintext_chunk=plaintext_file,
        )
        observation.received_chunks = list(state.received_chunks)
        observation.chunk_state = state.unpack_status
        observation.unpack_message = state.unpack_message
        observation.internal_files = list(state.internal_files)
        observation.business_contents = list(state.business_contents)
    elif observation.file_chunk_id is not None:
        observation.received_chunks = [observation.file_chunk_id]
    return observation


def _parse_multipart(
    content_type: str,
    raw_body: bytes,
    observation: ProtocolObservation,
) -> tuple[dict[str, str], str | None, bytes | None]:
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("ascii") + raw_body
    )
    if not message.is_multipart():
        observation.errors.append("invalid multipart body")
        return {}, None, None

    fields: dict[str, str] = {}
    file_name: str | None = None
    file_content: bytes | None = None
    for part_index, part in enumerate(message.iter_parts(), start=1):
        if part_index > _MAX_MULTIPART_PARTS:
            observation.errors.append(
                f"multipart part count exceeds {_MAX_MULTIPART_PARTS}"
            )
            break
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        content = part.get_payload(decode=True) or b""
        if name == "fileChunk":
            if len(content) > _MAX_FILE_CHUNK_BYTES:
                observation.errors.append(
                    f"fileChunk exceeds {_MAX_FILE_CHUNK_BYTES} bytes"
                )
                continue
            file_name = filename
            file_content = content
            if not content:
                observation.errors.append("empty fileChunk")
            continue
        try:
            if len(content) > _MAX_MULTIPART_FIELD_BYTES:
                observation.errors.append(
                    f"multipart field {name} exceeds {_MAX_MULTIPART_FIELD_BYTES} bytes"
                )
                continue
            fields[name] = content.decode(part.get_content_charset() or "utf-8")
        except UnicodeDecodeError:
            observation.errors.append(f"multipart field {name} is not UTF-8")
    return fields, file_name, file_content


def _validate_file_metadata(
    observation: ProtocolObservation,
    inner: dict[str, Any],
    file_name: str | None,
) -> None:
    missing = FILE_METADATA_KEYS - set(inner)
    extra = set(inner) - FILE_METADATA_KEYS
    if missing:
        observation.errors.append(f"file metadata missing keys: {sorted(missing)}")
    if extra:
        observation.errors.append(f"file metadata unexpected keys: {sorted(extra)}")
    if missing:
        return

    if inner.get("dataType") != 0 or type(inner.get("dataType")) is not int:
        observation.errors.append("file metadata dataType must be int 0")
    if inner.get("dataSubType") != 0 or type(inner.get("dataSubType")) is not int:
        observation.errors.append("file metadata dataSubType must be int 0")
    for name in ("sign", "timeStamp"):
        if not isinstance(inner.get(name), str) or not inner[name]:
            observation.errors.append(f"file metadata {name} must be non-empty string")

    if file_name is None:
        return
    match = _ARCHIVE_NAME_RE.fullmatch(file_name)
    if match is None:
        observation.errors.append(
            "archive name must match {32-char-fileID}_{fileName}_{fileTotalChunk}_{fileChunkID}.tar.gz.bin"
        )
        return

    observation.file_id = match.group("file_id")
    observation.business_file_name = match.group("file_name")
    observation.file_total_chunks = int(match.group("total"))
    observation.file_chunk_id = int(match.group("chunk"))
    observation.archive_directory = f"{observation.file_id}_{observation.business_file_name}"
    if observation.file_total_chunks < 1:
        observation.errors.append("fileTotalChunk must be positive int")
    if observation.file_chunk_id < 1:
        observation.errors.append("fileChunkID must be positive int")
    elif observation.file_chunk_id > observation.file_total_chunks:
        observation.errors.append("fileChunkID must not exceed fileTotalChunk")
    else:
        observation.chunk_state = "receiving"

