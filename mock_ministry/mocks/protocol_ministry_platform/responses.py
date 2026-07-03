"""Response policy for the protocol-level ministry platform mock."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contracts import KNOWN_PROTOCOL_SUBTYPES
from .envelope import ProtocolObservation


@dataclass(frozen=True)
class ProtocolResponse:
    http_status: int
    body: dict[str, Any]


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

    return ProtocolResponse(
        http_status=200,
        body={"statusCode": 0, "statusText": "mock accepted", "rspMsgCnt": ""},
    )

