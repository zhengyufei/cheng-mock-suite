from __future__ import annotations

from copy import deepcopy

import pytest

from mock_ministry.mocks.protocol_ministry_platform.additional_fixtures import (
    build_additional_fixture,
    build_work_order_request,
    build_work_order_response,
)
from mock_ministry.mocks.protocol_ministry_platform.contracts import (
    PASSWORD_DICTIONARY_SVC_TYPE,
    SYSTEM_VULNERABILITY_SVC_TYPE,
)
from mock_ministry.mocks.protocol_ministry_platform.payloads import validate_business_payload
from mock_ministry.mocks.protocol_ministry_platform.shared_fixtures import build_shared_fixture

ALL_INTERFACES = (3, 4, 5, 6, 7, 8, 11, 12, 15, 17, 18, 19, 21, 22, 24, 26, 27, 29, 30, 31, 32)
SHARED_INTERFACES = (5, 6, 7, 8, 15, 24, 29, 30, 31, 32)
SEQUENCE = "2026071400000000062"


def _fixture(interface_no: int) -> dict:
    if interface_no == 3:
        return build_work_order_request(31, SEQUENCE)
    if interface_no == 4:
        return build_work_order_response(31, SEQUENCE)
    if interface_no in SHARED_INTERFACES:
        return build_shared_fixture(interface_no, SEQUENCE)
    return build_additional_fixture(interface_no, SEQUENCE, ctx_code=0)


@pytest.mark.parametrize("interface_no", SHARED_INTERFACES)
def test_shared_fixture_is_exact_and_strictly_typed(interface_no: int) -> None:
    fixture = _fixture(interface_no)

    assert validate_business_payload(interface_no, fixture["inner"], ctx_code=fixture["ctxCode"]) == []


@pytest.mark.parametrize(("interface_no", "svc_type"), ((5, 1), (6, 3)))
def test_product_work_order_file_is_optional_and_uses_protocol_svc_type(
    interface_no: int,
    svc_type: int,
) -> None:
    inner = deepcopy(_fixture(interface_no)["inner"])
    inner.pop("data", None)
    assert validate_business_payload(interface_no, inner) == []

    inner["data"] = {
        "numFiles": 1,
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": "literal-poc.py",
                "dataType": "file",
                "objectID": "CVE-2026-0001",
                "svcType": svc_type,
                "reserved": "",
            }
        ],
    }
    assert validate_business_payload(interface_no, inner) == []

    inner["data"]["fileInfoLst"][0]["svcType"] = 3 if svc_type == 1 else 1
    errors = validate_business_payload(interface_no, inner)
    assert any("svcType" in error for error in errors), errors


@pytest.mark.parametrize("request_subtype", (11, 12))
def test_interface_5_accepts_both_product_work_order_request_subtypes(request_subtype: int) -> None:
    inner = deepcopy(_fixture(5)["inner"])
    inner["orderSubType"] = request_subtype

    assert validate_business_payload(5, inner) == []


@pytest.mark.parametrize("response_subtype", (21, 22))
def test_interface_6_accepts_typed_vulnerability_ids_for_both_response_subtypes(
    response_subtype: int,
) -> None:
    inner = deepcopy(_fixture(6)["inner"])
    inner["orderSubType"] = response_subtype
    inner["vulIdLst"] = {"idLst": ["MVM-2026-0001"], "vulNum": 1}

    assert validate_business_payload(6, inner) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dstVulStat", [0]),
        ("dstVulStat", [1, 1] + [-1] * 9),
        ("sucVulNum", [0]),
        ("sucVulNum", [-2] + [0] * 10),
        ("tktResult", 3),
        ("prcVulNum", -1),
    ],
)
def test_interface_6_rejects_invalid_result_slots_and_counts(field: str, value) -> None:
    inner = deepcopy(_fixture(6)["inner"])
    inner["vulTktRspParams"][field] = value

    assert validate_business_payload(6, inner)


@pytest.mark.parametrize(
    "unsafe_name",
    [".", "..", "../a.json", "..\\a.json", "C:a.json", "bad\nname"],
)
def test_file_metadata_rejects_unsafe_archive_business_names(unsafe_name: str) -> None:
    inner = deepcopy(_fixture(6)["inner"])
    inner["data"]["fileInfoLst"][0]["name"] = unsafe_name

    assert validate_business_payload(6, inner)


@pytest.mark.parametrize(
    ("subtype", "ids", "count"),
    [
        (23, ["MVM-2026-0001"], 1),
        (21, [{"vulID": "MVM-2026-0001"}], 1),
        (22, ["MVM-2026-0001"], 2),
        (21, [""], 1),
        (22, ["x" * 256], 1),
    ],
)
def test_interface_6_rejects_wrong_subtype_object_ids_and_count_mismatch(
    subtype: int,
    ids: list,
    count: int,
) -> None:
    inner = deepcopy(_fixture(6)["inner"])
    inner["orderSubType"] = subtype
    inner["vulIdLst"] = {"idLst": ids, "vulNum": count}

    assert validate_business_payload(6, inner)


def test_warning_callback_file_is_optional_and_uses_literal_svc_type_12() -> None:
    inner = deepcopy(_fixture(8)["inner"])
    inner.pop("data", None)
    assert validate_business_payload(8, inner) == []

    inner["data"] = {
        "numFiles": 1,
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": "literal-system-vulnerability.json",
                "dataType": "json",
                "objectID": "LOG-20260714",
                "svcType": 12,
                "reserved": "",
            }
        ],
    }
    assert validate_business_payload(8, inner) == []

    inner["data"]["fileInfoLst"][0]["svcType"] = 3
    errors = validate_business_payload(8, inner)
    assert any("svcType" in error for error in errors), errors


@pytest.mark.parametrize("svc_types", [(), (11,), (11, 13)])
def test_platform_log_file_data_uses_literal_conditional_sequence(svc_types: tuple[int, ...]) -> None:
    inner = deepcopy(_fixture(31)["inner"])
    inner.pop("data", None)
    if svc_types:
        inner["data"] = {
            "numFiles": len(svc_types),
            "numTgzs": 1,
            "fileInfoLst": [
                {
                    "name": f"literal-log-{svc_type}.json",
                    "dataType": "json",
                    "objectID": "2-305-2026071400000000062",
                    "svcType": svc_type,
                    "reserved": "",
                }
                for svc_type in svc_types
            ],
        }

    assert validate_business_payload(31, inner) == []


@pytest.mark.parametrize("svc_types", [(13,), (11, 12), (13, 11)])
def test_platform_log_rejects_non_protocol_file_sequences(svc_types: tuple[int, ...]) -> None:
    inner = deepcopy(_fixture(31)["inner"])
    inner["data"] = {
        "numFiles": len(svc_types),
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": f"invalid-log-{svc_type}.json",
                "dataType": "json",
                "objectID": "2-305-2026071400000000062",
                "svcType": svc_type,
                "reserved": "",
            }
            for svc_type in svc_types
        ],
    }

    errors = validate_business_payload(31, inner)

    assert any("svcType" in error for error in errors), errors


def test_interface_27_accepts_multiple_system_vulnerability_files() -> None:
    inner = deepcopy(build_additional_fixture(27, SEQUENCE, ctx_code=2)["inner"])
    duplicate = deepcopy(inner["data"]["fileInfoLst"][0])
    duplicate["name"] = "second-system-vulnerabilities.json"
    duplicate["objectID"] = "ledger-log-second"
    inner["data"]["fileInfoLst"].append(duplicate)
    inner["data"]["numFiles"] = len(inner["data"]["fileInfoLst"])

    assert validate_business_payload(27, inner, ctx_code=2) == []


def test_interface_27_rejects_non_system_vulnerability_file_among_repeated_files() -> None:
    inner = deepcopy(build_additional_fixture(27, SEQUENCE, ctx_code=2)["inner"])
    invalid = deepcopy(inner["data"]["fileInfoLst"][0])
    invalid["name"] = "password-dictionary.json"
    invalid["svcType"] = PASSWORD_DICTIONARY_SVC_TYPE
    inner["data"]["fileInfoLst"].append(invalid)
    inner["data"]["numFiles"] = len(inner["data"]["fileInfoLst"])

    errors = validate_business_payload(27, inner, ctx_code=2)

    assert any(
        f"svcType must contain only {SYSTEM_VULNERABILITY_SVC_TYPE}" in error
        for error in errors
    ), errors


@pytest.mark.parametrize(
    "svc_type,data_type",
    [
        (-1, "file"),
        (1, "file"),
        (3, "file"),
        (4, "file"),
        (5, "json"),
        (6, "file"),
        (8, "json"),
        (9, "txt"),
        (10, "json"),
        (11, "json"),
        (12, "json"),
        (13, "json"),
    ],
)
def test_platform_file_metadata_accepts_each_literal_common_svc_type(
    svc_type: int,
    data_type: str,
) -> None:
    inner = deepcopy(_fixture(32)["inner"])
    info = inner["data"]["fileInfoLst"][0]
    info.update(
        name="literal-platform-file.json",
        dataType=data_type,
        objectID="2-306-2026071400000000062",
        svcType=svc_type,
        reserved="platform-direct" if svc_type == -1 else "",
    )

    assert validate_business_payload(
        32,
        inner,
        order_id="2-306-2026071400000000062",
    ) == []


@pytest.mark.parametrize("svc_type,data_type", [(1, "json"), (5, "file"), (9, "xml"), (13, "txt")])
def test_platform_file_metadata_rejects_literal_svc_and_data_type_mismatch(
    svc_type: int,
    data_type: str,
) -> None:
    inner = deepcopy(_fixture(32)["inner"])
    info = inner["data"]["fileInfoLst"][0]
    info.update(
        objectID="2-306-2026071400000000062",
        svcType=svc_type,
        dataType=data_type,
    )

    errors = validate_business_payload(32, inner, order_id="2-306-2026071400000000062")

    assert any("dataType" in error for error in errors), errors


def test_target_deployment_requires_literal_bsxx_and_matching_object_id() -> None:
    order_id = "2-306-2026071400000000062"
    inner = deepcopy(_fixture(32)["inner"])
    info = inner["data"]["fileInfoLst"][0]
    info.update(
        name="literal-target-deployment.xlsx",
        dataType="file",
        objectID=order_id,
        svcType=-1,
        reserved="bsxx",
    )
    assert validate_business_payload(32, inner, order_id=order_id) == []

    info["reserved"] = ""
    errors = validate_business_payload(32, inner, order_id=order_id)
    assert any("reserved" in error for error in errors), errors

    info["reserved"] = "bsxx"
    info["objectID"] = "2-306-2026071400000000999"
    errors = validate_business_payload(32, inner, order_id=order_id)
    assert any("objectID" in error for error in errors), errors


@pytest.mark.parametrize("svc_type", [-2, 0, 2, 7, 14])
def test_platform_file_metadata_rejects_unknown_svc_type(svc_type: int) -> None:
    inner = deepcopy(_fixture(32)["inner"])
    info = inner["data"]["fileInfoLst"][0]
    info.update(objectID="2-306-2026071400000000062", svcType=svc_type)

    errors = validate_business_payload(32, inner, order_id="2-306-2026071400000000062")

    assert any("svcType" in error for error in errors), errors


@pytest.mark.parametrize("log_type", [2, "2", "02", 0, 99])
def test_test_data_query_accepts_literal_log_type_range(log_type: int | str) -> None:
    inner = deepcopy(_fixture(17)["inner"])
    inner["tstReqParams"]["logType"] = log_type

    assert validate_business_payload(17, inner) == []


@pytest.mark.parametrize("log_type", [-1, 100, "-1", "100", "not-a-number", True])
def test_test_data_query_rejects_out_of_range_or_non_numeric_log_type(log_type: object) -> None:
    inner = deepcopy(_fixture(17)["inner"])
    inner["tstReqParams"]["logType"] = log_type

    errors = validate_business_payload(17, inner)

    assert any("logType" in error for error in errors), errors


@pytest.mark.parametrize("interface_no", ALL_INTERFACES)
@pytest.mark.parametrize("negative", ("missing", "extra", "wrong_type"))
def test_each_interface_rejects_missing_extra_and_wrong_type(interface_no: int, negative: str) -> None:
    fixture = deepcopy(_fixture(interface_no))
    inner = fixture["inner"]
    if negative == "missing":
        inner.pop("timeStamp")
        expected = "missing keys"
    elif negative == "extra":
        inner["unexpectedProtocolField"] = True
        expected = "unexpected keys"
    else:
        inner["sign"] = 123
        expected = "sign must be str"

    errors = validate_business_payload(interface_no, inner, ctx_code=fixture["ctxCode"])

    assert any(expected in error for error in errors), errors
