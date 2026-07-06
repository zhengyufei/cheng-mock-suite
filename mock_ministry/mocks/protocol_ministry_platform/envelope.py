"""Envelope inspection for the protocol-level ministry platform mock."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .contracts import LEGACY_PLATFORM_FILE_UPLOAD_PATH, PLATFORM_FILE_PATH


_ORDER_ID_RE = re.compile(r"^(?P<order_type>\d+)-(?P<sub_type>\d+)-(?P<sequence>[A-Za-z0-9]+)$")
_ENCRYPT_HEADERS = ("X-Enc-Key", "X-Enc-Key-G", "X-Enc-Nonce", "X-Enc-Auth-Tag", "X-Enc-Auth-Tag-File")


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
            },
            "validation": {
                "ok": self.is_valid,
                "errors": self.errors,
                "warnings": self.warnings,
            },
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
        observation.errors.append(f"invalid orderID format: {observation.order_id}")
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


def inspect_receive_body(
    *,
    raw_body: bytes,
    headers: dict[str, str] | None,
    path: str = "/ministry/receive",
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

    _parse_order_id(observation, body)

    if "reqMsgCnt" in body:
        observation.content_field = "reqMsgCnt"
    elif "rspMsgCnt" in body:
        observation.content_field = "rspMsgCnt"
    else:
        observation.errors.append("missing reqMsgCnt or rspMsgCnt")
        return observation

    inner = _parse_inner_content(body.get(observation.content_field), observation)
    observation.inner = inner
    _apply_inner_routing(observation, inner)
    return observation


def inspect_file_request(
    *,
    path: str,
    headers: dict[str, str] | None,
    raw_body: bytes,
) -> ProtocolObservation:
    """Inspect file-upload style requests accepted by the platform mock."""

    if path == PLATFORM_FILE_PATH:
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

    return observation

