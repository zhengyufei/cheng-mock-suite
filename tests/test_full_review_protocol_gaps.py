from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from mock_ministry.mocks.protocol_ministry_platform import responses
from mock_ministry.mocks.protocol_ministry_platform.contracts import (
    ADDITIONAL_INTERFACE_DIRECTIONS,
    PLATFORM_RECEIVE_SUBTYPE_INTERFACES,
)
from mock_ministry.mocks.protocol_ministry_platform.envelope import ProtocolObservation
from mock_ministry.mocks.protocol_ministry_platform.payloads import validate_business_payload
from mock_ministry.mocks.protocol_ministry_platform.shared_fixtures import build_shared_fixture
from mock_ministry.mocks.protocol_ministry_platform.server import _is_valid_auth_request


SEQUENCE = "2026071800000000001"


def _mismatch_registration_device(inner: dict) -> None:
    registration = inner["engRegParams"]["engRegInfo"][0]
    registration["engDev"] = dict(registration["engDev"])
    registration["engDev"]["engHash"] = "other-device"


def test_interfaces_1_and_2_auth_oracle_requires_exact_nonblank_string_fields() -> None:
    valid = {
        "orgCode": "150000",
        "ispCode": "CM",
        "public_key": "a" * 128,
        "ip": "1.1.1.1",
        "domain": "province.example",
    }
    assert _is_valid_auth_request(valid)

    for field in valid:
        invalid = dict(valid)
        invalid[field] = " "
        assert not _is_valid_auth_request(invalid)
    assert not _is_valid_auth_request({**valid, "publicKey": valid["public_key"]})


@pytest.mark.parametrize(
    ("interface_no", "direction"),
    [
        (1, "ministry_to_province"),
        (2, "province_to_ministry"),
        (9, "ministry_to_province"),
        (10, "ministry_to_province"),
        (13, "ministry_to_province"),
        (14, "province_to_ministry"),
        (23, "province_to_ministry"),
        (25, "province_to_ministry"),
        (28, "bidirectional"),
        (31, "province_to_ministry"),
        (33, "bidirectional"),
    ],
)
def test_reviewed_interfaces_have_explicit_direction(interface_no: int, direction: str) -> None:
    assert ADDITIONAL_INTERFACE_DIRECTIONS[interface_no] == direction


@pytest.mark.parametrize(
    ("subtype", "interface_no"),
    [(106, 14), (1061, 14), (1062, 14), (1063, 14), (201, 25), (301, 28), (308, 23)],
)
def test_province_to_ministry_subtypes_route_to_strict_oracle(subtype: int, interface_no: int) -> None:
    assert PLATFORM_RECEIVE_SUBTYPE_INTERFACES[subtype] == interface_no


@pytest.mark.parametrize("subtype", [106, 1061, 1062, 1063])
def test_cross_level_task_oracle_accepts_each_protocol_subtype(subtype: int) -> None:
    fixture = build_shared_fixture(14, SEQUENCE)
    fixture["inner"]["orderSubType"] = subtype
    order_id = f"2-{subtype}-{SEQUENCE}"

    assert validate_business_payload(14, fixture["inner"], order_id=order_id) == []


def test_interface_14_requires_a_list_of_scanner_results() -> None:
    fixture = build_shared_fixture(14, SEQUENCE)
    assert isinstance(fixture["inner"]["vulInfoLst"], list)

    invalid = deepcopy(fixture["inner"])
    invalid["vulInfoLst"] = {"vulNum": 0, "comVulLst": []}

    assert any(
        "vulInfoLst must be list" in error
        for error in validate_business_payload(14, invalid, order_id=fixture["orderID"])
    )

    missing_scanner = deepcopy(fixture["inner"])
    missing_scanner["vulInfoLst"][0].pop("engLst")
    assert validate_business_payload(
        14, missing_scanner, order_id=fixture["orderID"]
    )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda inner: inner["engRegParams"]["engRegInfo"][0].update(reqAct=1),
        lambda inner: inner["engRegParams"]["engRegInfo"][0].update(engVulNum=-1),
        lambda inner: inner["engRegParams"]["engRegInfo"][0]["engDev"].update(engType=64),
        _mismatch_registration_device,
    ),
)
def test_interface_23_rejects_invalid_semantics_and_unmatched_device(mutate) -> None:
    fixture = build_shared_fixture(23, SEQUENCE)
    mutate(fixture["inner"])

    assert validate_business_payload(
        23, fixture["inner"], order_id=fixture["orderID"]
    )


@pytest.mark.parametrize("forbidden", ("factoryVersion", "curVer", "installTime", "version"))
def test_interface_23_registration_uses_exact_protocol_fields(forbidden: str) -> None:
    fixture = build_shared_fixture(23, SEQUENCE)
    registration = fixture["inner"]["engRegParams"]["engRegInfo"][0]
    expected = {
        "vendor", "engName", "engVer", "devIp", "rngIp", "plugInsVer", "timeStamp",
        "engVulNum", "plugIns", "pocs", "exps", "reqAct", "status", "engDev",
    }
    assert set(registration) == expected
    assert validate_business_payload(23, fixture["inner"], order_id=fixture["orderID"]) == []

    registration[forbidden] = "legacy"
    assert any(
        "unexpected keys" in error and forbidden in error
        for error in validate_business_payload(23, fixture["inner"], order_id=fixture["orderID"])
    )


@pytest.mark.parametrize(
    ("interface_no", "required_root"),
    [
        (9, "vulLst"),
        (10, "data"),
        (13, "engLst"),
        (14, "tskRspParams"),
        (23, "engRegParams"),
        (25, "staReqParams"),
        (28, "registerReqParams"),
    ],
)
def test_reviewed_business_fixture_is_strict_and_rejects_missing_root(
    interface_no: int,
    required_root: str,
) -> None:
    fixture = build_shared_fixture(interface_no, SEQUENCE)
    assert validate_business_payload(
        interface_no,
        fixture["inner"],
        ctx_code=fixture["ctxCode"],
        order_id=fixture["orderID"],
    ) == []

    invalid = deepcopy(fixture["inner"])
    invalid.pop(required_root)
    assert validate_business_payload(
        interface_no,
        invalid,
        ctx_code=fixture["ctxCode"],
        order_id=fixture["orderID"],
    )


def test_interface_31_inline_and_file_backed_modes_bind_to_outer_order_id() -> None:
    fixture = build_shared_fixture(31, SEQUENCE)
    order_id = fixture["orderID"]
    inline = fixture["inner"]
    assert validate_business_payload(31, inline, order_id=order_id) == []

    wrong_inline = deepcopy(inline)
    wrong_inline["logInfoReqParams"]["logInfo"][0]["orderID"] = "2-305-2026071800000000002"
    assert any(
        "orderID" in error
        for error in validate_business_payload(31, wrong_inline, order_id=order_id)
    )

    file_backed = deepcopy(inline)
    params = file_backed["logInfoReqParams"]
    params["dataFileID"] = order_id
    params["logInfo"] = []
    file_backed["data"] = {
        "numFiles": 1,
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": "platform-logs.json",
                "dataType": "json",
                "objectID": order_id,
                "svcType": 11,
                "reserved": "",
            }
        ],
    }
    assert validate_business_payload(31, file_backed, order_id=order_id) == []

    missing_data = deepcopy(file_backed)
    missing_data.pop("data")
    assert any(
        "file-backed interface 31 requires data" in error
        for error in validate_business_payload(31, missing_data, order_id=order_id)
    )

    file_backed["logInfoReqParams"]["dataFileID"] = "2-305-2026071800000000002"
    assert any(
        "dataFileID" in error
        for error in validate_business_payload(31, file_backed, order_id=order_id)
    )


@pytest.mark.parametrize(
    ("subtype", "business_key"),
    [(102, "tskRspParams"), (103, "tskRspParams"), (308, "engRegParams"), (301, "registerResParams")],
)
def test_mock_response_contains_protocol_business_result(
    monkeypatch: pytest.MonkeyPatch,
    subtype: int,
    business_key: str,
) -> None:
    monkeypatch.setattr(responses, "generate_response_sign", lambda *_: "a" * 64)
    observation = ProtocolObservation(
        endpoint_role="platform_receive",
        order_id=f"2-{subtype}-{SEQUENCE}",
        order_type=2,
        sub_type=subtype,
        message_family="order" if subtype in {102, 103} else "data",
    )
    crypto = SimpleNamespace(keys=SimpleNamespace(province_public_key="unused"))

    plaintext = responses._response_plaintext(observation, {"statusCode": 0}, crypto)

    assert business_key in plaintext
