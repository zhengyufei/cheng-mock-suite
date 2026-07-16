from __future__ import annotations

import base64
import importlib
import json
from pathlib import Path

import pytest
import requests


def _modules():
    contracts = importlib.import_module("mock_ministry.mocks.protocol_ministry_platform.contracts")
    fixtures = importlib.import_module("mock_ministry.mocks.protocol_ministry_platform.additional_fixtures")
    payloads = importlib.import_module("mock_ministry.mocks.protocol_ministry_platform.payloads")
    envelope = importlib.import_module("mock_ministry.mocks.protocol_ministry_platform.envelope")
    responses = importlib.import_module("mock_ministry.mocks.protocol_ministry_platform.responses")
    return contracts, fixtures, payloads, envelope, responses


def test_protocol_catalog_centralizes_additional_interface_routes() -> None:
    contracts, _, _, _, _ = _modules()

    assert contracts.WORK_ORDER_RESPONSE_SUBTYPES == {31: 41, 32: 42, 33: 43, 34: 44}
    assert contracts.TEST_DATA_SVC_TYPES == {
        1: (9,),
        2: (10,),
        3: (11, 13),
        5: (12,),
        6: (11, 13, 12),
    }
    assert contracts.TEST_DATA_OPTIONAL_SVC_TYPES == {}
    assert contracts.OUTBOUND_DATA_SUBTYPES == {26: 202, 27: 203}
    assert contracts.FILE_REQUIRED_CTX_CODES == frozenset({2, 5, 6})
    assert contracts.ADDITIONAL_INTERFACE_DIRECTIONS[26] == "province_to_ministry"
    assert contracts.ADDITIONAL_INTERFACE_DIRECTIONS[27] == "province_to_ministry"
    assert {"interface11_failure", "business203_failure", "timeout", "duplicate", "file_partial"} < set(
        contracts.SUPPORTED_SCENARIOS
    )


def test_manifest_does_not_misclassify_202_203_as_ministry_to_province() -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "fixtures" / "protocol_ministry_platform" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert {"202", "203"} <= set(manifest["receive_from_backend"]["subtypes"])
    assert "26" not in manifest["send_to_backend"]["fixture_cases"]
    assert "27" not in manifest["send_to_backend"]["fixture_cases"]
    assert "tas_stat_202" not in manifest["send_to_backend"]["regression_send_cases"]
    assert "sys_vul_stat_203" not in manifest["send_to_backend"]["regression_send_cases"]


@pytest.mark.parametrize(
    ("request_subtype", "response_subtype", "proc_method", "target_statuses"),
    [
        (31, 41, 1020, {1}),
        (32, 42, 1026, {2, 3, 8}),
        (33, 43, 1050, {5, 9}),
        (34, 44, 1060, {6, 7, 10}),
    ],
)
def test_interface_3_4_fixture_pairs_preserve_sequence(
    request_subtype: int,
    response_subtype: int,
    proc_method: int,
    target_statuses: set[int],
) -> None:
    _, fixtures, payloads, _, _ = _modules()
    sequence = "2026071400000000001"

    request = fixtures.build_work_order_request(request_subtype, sequence)
    response = fixtures.build_work_order_response(request_subtype, sequence)

    assert request["orderID"] == f"1-{request_subtype}-{sequence}"
    assert response["orderID"] == f"1-{response_subtype}-{sequence}"
    params = request["inner"]["vulInfoTktReqParams"]
    assert params["procMethod"] == proc_method
    assert {status for status in params["dstVulInfoStat"] if status != -1} == target_statuses
    assert response["inner"]["vulInfoLst"]["engLst"] == {
        "engNum": 1,
        "engDevs": [{"engHash": "ACCEPTANCE-ENG-001", "engType": 32}],
    }
    assert payloads.validate_business_payload(3, request["inner"]) == []
    assert payloads.validate_business_payload(4, response["inner"]) == []


def test_interface_4_accepts_only_non_null_optional_file_data() -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_response(31, "2026071400000000044")
    fixture["inner"]["data"] = {
        "numFiles": 1,
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": "interface-4-evidence.json",
                "dataType": "json",
                "objectID": "interface-4-evidence",
                "svcType": 4,
                "reserved": "",
            }
        ],
    }

    assert payloads.validate_business_payload(4, fixture["inner"]) == []

    fixture["inner"]["data"] = None
    errors = payloads.validate_business_payload(4, fixture["inner"])
    assert any("payload.data" in error for error in errors)


def test_interface_3_and_4_file_oracle_enforces_protocol_service_types() -> None:
    _, fixtures, payloads, _, _ = _modules()
    request = fixtures.build_work_order_request(31, "2026071400000000046")
    request["inner"]["data"] = {
        "numFiles": 1,
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": "request-poc.json",
                "dataType": "json",
                "objectID": "SYS-001",
                "svcType": 2,
                "reserved": "",
            }
        ],
    }
    response = fixtures.build_work_order_response(31, "2026071400000000046")
    response["inner"]["data"] = {
        "numFiles": 1,
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": "manual-evidence.json",
                "dataType": "json",
                "objectID": "SYS-001",
                "svcType": 4,
                "reserved": "",
            }
        ],
    }

    assert payloads.validate_business_payload(3, request["inner"]) == []
    assert payloads.validate_business_payload(4, response["inner"]) == []

    request["inner"]["data"]["fileInfoLst"][0]["svcType"] = 4
    response["inner"]["data"]["fileInfoLst"][0]["svcType"] = 12
    assert any(
        "only 2 or 5" in error
        for error in payloads.validate_business_payload(3, request["inner"])
    )
    assert any(
        "only 3, 4, 5, 11 or 13" in error
        for error in payloads.validate_business_payload(4, response["inner"])
    )


def _nonempty_interface_4_fixture(fixtures):
    fixture = fixtures.build_work_order_response(33, "2026071400000000045")
    instance = {
        "vulInfoID": "SYS-001",
        "srcMethod": 1050,
        "logIDLst": "LOG-001",
        "vulInfoStat": 5,
        "remedTime": "1日",
        "assetID": "ASSET-001",
        "assetLclId": "LOCAL-001",
        "assetName": "acceptance asset",
        "vulAddrType": 1,
        "vulNetAddr": "192.0.2.1",
        "vulTransProto": "TCP",
        "vulPort": 443,
        "vulSvc": "https",
        "transferTime": "1752500000",
        "isAccess": 0,
        "unitType": "0101",
        "vulInstCpe": "cpe:2.3:a:acceptance:service:1.0:*:*:*:*:*:*:*",
        "vulInstVendor": "acceptance",
        "vulInstClass": 2,
        "vulInstName": "service",
        "vulInstVer": "1.0",
        "vulInstRunPath": "/opt/service",
        "vulInstFilePath": "/opt/service/bin",
        "vulInstFileLoc": "1",
        "vulInstOsType": "linux",
        "vulInstOsNameVer": "Linux 1",
        "vulInstOsVendor": "acceptance",
        "vulInstOsCpe": "cpe:2.3:o:acceptance:linux:1:*:*:*:*:*:*:*",
        "vulInstDevNameVer": "device-1",
        "vulInstDevVendor": "acceptance",
        "vulInstDevCpe": "cpe:2.3:h:acceptance:device:1:*:*:*:*:*:*:*",
        "assetOwnerinfo": "owner@example.invalid,Owner,NA",
        "vulPriorVal": 5.0,
        "vulPriorLvl": 3,
        "vulPriorMID": "MODEL-001",
    }
    fixture["inner"]["vulInfoLst"].update(
        vulNum=1,
        comVulLst=[{"vulID": "MVM-001", "assetNum": 1, "instVulLst": [instance]}],
    )
    params = fixture["inner"]["vulInfoTktRspParams"]
    params.update(
        prcVulNum=1,
        toPrcAstNum=1,
        prcAstNum=1,
        dstVulInfoStat=[-1, -1, -1, -1, 5, -1, -1, -1, -1, -1],
        sucVulInfoNum=[-1, -1, -1, -1, 1, -1, -1, -1, -1, -1],
        tktResult=1,
    )
    return fixture


def test_interface_4_rejects_success_count_that_disagrees_with_actual_status():
    _, fixtures, payloads, _, _ = _modules()
    fixture = _nonempty_interface_4_fixture(fixtures)
    fixture["inner"]["vulInfoLst"]["comVulLst"][0]["instVulLst"][0][
        "vulInfoStat"
    ] = 6

    errors = payloads.validate_business_payload(4, fixture["inner"])

    assert any("sucVulInfoNum must match actual vulnerability statuses" in error for error in errors)


def test_interface_4_rejects_all_success_with_zero_derived_successes():
    _, fixtures, payloads, _, _ = _modules()
    fixture = _nonempty_interface_4_fixture(fixtures)
    fixture["inner"]["vulInfoLst"]["comVulLst"][0]["instVulLst"][0][
        "vulInfoStat"
    ] = 6
    fixture["inner"]["vulInfoTktRspParams"]["sucVulInfoNum"][4] = 0

    errors = payloads.validate_business_payload(4, fixture["inner"])

    assert any("all success requires every processed vulnerability" in error for error in errors)


def test_interface_4_rejects_group_asset_count_mismatch():
    _, fixtures, payloads, _, _ = _modules()
    fixture = _nonempty_interface_4_fixture(fixtures)
    fixture["inner"]["vulInfoLst"]["comVulLst"][0]["assetNum"] = 2

    errors = payloads.validate_business_payload(4, fixture["inner"])

    assert any("assetNum must equal instVulLst length" in error for error in errors)


@pytest.mark.parametrize(
    ("interface_no", "mutator", "fragment"),
    [
        (3, lambda body: body["timePerd"].update(extra=1), "timePerd unexpected keys"),
        (3, lambda body: body["vulInfoTktReqParams"].pop("tktInfo"), "vulInfoTktReqParams missing keys"),
        (4, lambda body: body["vulInfoLst"].update(extra=1), "vulInfoLst unexpected keys"),
        (4, lambda body: body["vulInfoTktRspParams"].update(tktResult="0"), "tktResult must be int"),
    ],
)
def test_interface_3_4_rejects_inexact_nested_contracts(interface_no, mutator, fragment: str) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = (
        fixtures.build_work_order_request(31, "2026071400000000043")
        if interface_no == 3
        else fixtures.build_work_order_response(31, "2026071400000000043")
    )
    mutator(fixture["inner"])

    errors = payloads.validate_business_payload(interface_no, fixture["inner"])

    assert any(fragment in error for error in errors)


@pytest.mark.parametrize("interface_no", [11, 12])
def test_104_105_fixtures_are_exact_typed_payloads(interface_no: int) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(interface_no, "2026071400000000002")

    assert payloads.validate_business_payload(interface_no, fixture["inner"]) == []
    assert not any(value is None for value in fixtures.walk_values(fixture["inner"]))


def test_interface_104_uses_exact_nested_product_vulnerability_shape_and_file_first() -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(11, "2026071400000000002")
    vulnerability = fixture["inner"]["vulLst"]["keyLst"][0]

    assert fixture["events"] == ["upload_file:6", "send_business:104"]
    assert set(vulnerability) == payloads.PRODUCT_VULNERABILITY_KEYS

    vulnerability["unexpected"] = "forbidden"
    assert any("unexpected keys" in error for error in payloads.validate_business_payload(11, fixture["inner"]))


def test_interface_104_poc_data_is_optional_and_uses_svc6_only_when_present() -> None:
    _, fixtures, payloads, _, _ = _modules()
    without_poc = fixtures.build_additional_fixture(
        11,
        "2026071400000000044",
        include_poc_file=False,
    )
    with_poc = fixtures.build_additional_fixture(
        11,
        "2026071400000000045",
        include_poc_file=True,
    )

    assert "data" not in without_poc["inner"]
    assert without_poc["events"] == ["send_business:104"]
    assert with_poc["inner"]["data"]["fileInfoLst"][0]["svcType"] == 6
    assert with_poc["events"] == ["upload_file:6", "send_business:104"]
    assert payloads.validate_business_payload(11, without_poc["inner"]) == []
    assert payloads.validate_business_payload(11, with_poc["inner"]) == []


def test_receive_inspector_rejects_invalid_additional_business_payload() -> None:
    _, fixtures, _, envelope, responses = _modules()
    fixture = fixtures.build_additional_fixture(11, "2026071400000000012")
    fixture["inner"]["vulLst"]["keyLst"][0]["unexpected"] = "forbidden"
    outer = {key: value for key, value in fixture.items() if key in {"orderID", "orgCode", "ispCode", "ctxCode"}}
    outer["reqMsgCnt"] = json.dumps(fixture["inner"], separators=(",", ":"))

    observation = envelope.inspect_receive_body(
        raw_body=json.dumps(outer).encode(),
        headers={"Content-Type": "application/json"},
    )
    response = responses.build_protocol_response(observation)

    assert not observation.is_valid
    assert any("unexpected keys" in error for error in observation.errors)
    assert response.http_status == 400


@pytest.mark.parametrize(
    ("interface_no", "request_subtype"),
    ((4, 31), (4, 32), (4, 33), (4, 34), (11, None), (12, None), (26, None), (27, None)),
)
def test_receive_inspector_runs_strict_validator_for_each_outbound_subtype(
    interface_no: int,
    request_subtype: int | None,
) -> None:
    _, fixtures, _, envelope, _ = _modules()
    sequence = "2026071400000000013"
    fixture = (
        fixtures.build_work_order_response(request_subtype, sequence)
        if interface_no == 4
        else fixtures.build_additional_fixture(interface_no, sequence)
    )
    outer = {key: value for key, value in fixture.items() if key in {"orderID", "orgCode", "ispCode", "ctxCode"}}
    outer["reqMsgCnt"] = json.dumps(fixture["inner"], separators=(",", ":"))

    observation = envelope.inspect_receive_body(
        raw_body=json.dumps(outer).encode(),
        headers={"Content-Type": "application/json"},
    )

    assert observation.is_valid, observation.errors


def test_receive_inspector_routes_307_validator_by_tst_type() -> None:
    _, fixtures, _, envelope, _ = _modules()
    fixture = fixtures.build_additional_fixture(22, "2026071400000000014")
    fixture["inner"].pop("procTime")
    outer = {key: value for key, value in fixture.items() if key in {"orderID", "orgCode", "ispCode", "ctxCode"}}
    outer["reqMsgCnt"] = json.dumps(fixture["inner"], separators=(",", ":"))

    observation = envelope.inspect_receive_body(
        raw_body=json.dumps(outer).encode(),
        headers={"Content-Type": "application/json"},
    )

    assert not observation.is_valid
    assert any("procTime" in error for error in observation.errors)


def test_interface_105_uses_exact_file_info_and_password_dictionary_json() -> None:
    contracts, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(12, "2026071400000000003")
    file_info = fixture["inner"]["data"]["fileInfoLst"][0]
    dictionary = fixtures.load_password_dictionary_fixture()

    assert set(file_info) == contracts.FILE_INFO_KEYS
    assert file_info["svcType"] == contracts.PASSWORD_DICTIONARY_SVC_TYPE == 8
    assert set(dictionary) == {"pwDictNum", "pwLst"}
    assert dictionary["pwDictNum"] == len(dictionary["pwLst"])
    assert payloads.validate_password_dictionary(dictionary) == []
    for row in dictionary["pwLst"]:
        decoded = base64.b64decode(row["pwData"], validate=True).decode("utf-8")
        assert decoded.strip()


def test_interface_105_rejects_pw_data_that_is_not_real_base64() -> None:
    _, fixtures, payloads, _, _ = _modules()
    dictionary = fixtures.load_password_dictionary_fixture()
    dictionary["pwLst"][0]["pwData"] = "admin admin"

    errors = payloads.validate_password_dictionary(dictionary)

    assert any("pwData must be valid Base64" in error for error in errors)


@pytest.mark.parametrize(
    ("mutator", "error_fragment"),
    [
        (lambda body: body.update(extra="forbidden"), "unexpected keys"),
        (lambda body: body.update(timeStamp=None), "null"),
        (lambda body: body.update(orderSubType="105"), "orderSubType must be int"),
        (lambda body: body["data"]["fileInfoLst"][0].update(fileName="alias"), "unexpected keys"),
    ],
)
def test_interface_105_rejects_null_extra_and_inexact_types(mutator, error_fragment: str) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(12, "2026071400000000004")
    mutator(fixture["inner"])

    errors = payloads.validate_business_payload(12, fixture["inner"])

    assert any(error_fragment in error for error in errors)


@pytest.mark.parametrize("interface_no,tst_type", [(17, 1), (18, 2), (19, 3), (21, 5), (22, 6)])
def test_307_fixtures_have_exact_route_ack_order_and_service_mapping(interface_no: int, tst_type: int) -> None:
    contracts, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(interface_no, "2026071400000000005")
    inner = fixture["inner"]

    assert inner["dataType"] == 2
    assert inner["dataSubType"] == 307
    assert "orderType" not in inner and "orderSubType" not in inner
    assert inner["tstReqParams"]["tstType"] == tst_type
    assert fixture["events"][0] == "business_ack"
    assert fixture["expected_ack"] == {
        "dataType": 2,
        "dataSubType": 307,
        "tstResParams": {"tstProcRslt": 0},
    }
    assert fixture["expected_svc_types"] == {
        1: (9,),
        2: (10,),
        3: (11, 13),
        5: (12,),
        6: (11, 13, 12),
    }[tst_type]
    if interface_no in {21, 22}:
        assert isinstance(inner["vulInfoRange"], str) and inner["vulInfoRange"]
    assert payloads.validate_business_payload(interface_no, inner) == []


def test_protocol_literal_uses_detailed_type_5_and_type_6_file_mapping() -> None:
    """V2.2 详细表 780/781：类型5=12，类型6=11+13+N个12。"""
    _, fixtures, _, _, _ = _modules()

    interface_21 = fixtures.build_additional_fixture(21, "2026071400000000063")
    interface_22 = fixtures.build_additional_fixture(22, "2026071400000000064")

    # 字面量来自详细表，不引用实现常量，防止共享错误常量让测试假阳性。
    assert interface_21["expected_svc_types"] == (12,)
    assert interface_22["expected_svc_types"][:2] == (11, 13)
    assert interface_22["expected_svc_types"][2:] and set(interface_22["expected_svc_types"][2:]) == {12}


@pytest.mark.parametrize(
    ("interface_no", "mutator", "fragment"),
    [
        (21, lambda body: body.update(vulInfoRange="not-base64"), "valid Base64"),
        (
            21,
            lambda body: body.update(
                vulInfoRange=base64.b64encode(b"drop table sys_vulnerability").decode("ascii")
            ),
            "protocol DSL",
        ),
        (19, lambda body: body.update(procTime="20260714000000/20260715000000"), "procTime"),
        (19, lambda body: body.update(procTime="20260715000000-20260714000000"), "procTime"),
        (21, lambda body: body["tstReqParams"].update(opCode=9), "opCode"),
        (3, lambda body: body["timePerd"].update(unit=9), "timePerd.unit"),
        (3, lambda body: body["vulInfoTktReqParams"].update(dstVulInfoStat=[-1]), "length 10"),
        (4, lambda body: body["vulInfoTktRspParams"].update(exRsnLst=[-1]), "length 8"),
        (4, lambda body: body["vulInfoLst"].update(vulNum=1), "must equal comVulLst length"),
        (11, lambda body: body["vulLst"].update(vulNum=2), "must equal keyLst length"),
        (26, lambda body: body["staReqParams"].update(exRsnNumLst=[0]), "length 8"),
    ],
)
def test_strict_validator_rejects_protocol_semantic_drift(
    interface_no: int,
    mutator,
    fragment: str,
) -> None:
    _, fixtures, payloads, _, _ = _modules()
    if interface_no == 3:
        fixture = fixtures.build_work_order_request(31, "2026071400000000065")
    elif interface_no == 4:
        fixture = fixtures.build_work_order_response(31, "2026071400000000065")
    else:
        fixture = fixtures.build_additional_fixture(interface_no, "2026071400000000065")
    mutator(fixture["inner"])

    errors = payloads.validate_business_payload(
        interface_no,
        fixture["inner"],
        ctx_code=fixture["ctxCode"],
    )

    assert any(fragment in error for error in errors), errors


@pytest.mark.parametrize("perd", [-1, 1, 65535])
def test_interface_3_mock_accepts_protocol_time_period_values(perd: int) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000066")
    fixture["inner"]["timePerd"]["perd"] = perd

    assert payloads.validate_business_payload(3, fixture["inner"]) == []


@pytest.mark.parametrize("perd", [-2, 0, 65536])
def test_interface_3_mock_rejects_invalid_time_period_values(perd: int) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000067")
    fixture["inner"]["timePerd"]["perd"] = perd

    errors = payloads.validate_business_payload(3, fixture["inner"])

    assert any("timePerd.perd" in error for error in errors)


def test_interface_3_fixture_contains_all_required_range_nodes() -> None:
    _, fixtures, _, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000068")
    decoded = base64.b64decode(fixture["inner"]["vulInfoRange"], validate=True).decode("utf-8")

    assert "vulKeys." in decoded
    assert "assetInfoRange." in decoded
    assert "vulInfoStat" in decoded


@pytest.mark.parametrize(
    "invalid_dsl",
    [
        "(vulKeys.vulID = 'MVM-001') AND (assetInfoRange.assetID = 'ASSET-001')",
        "(vulKeys.vulID = 'MVM-001') OR "
        "(assetInfoRange.assetID = 'ASSET-001') AND (vulInfoStat = -1)",
        "(vulKeys.vulID = 'MVM-001') AND (vulKeys.vulLevel = 1) AND "
        "(assetInfoRange.assetID = 'ASSET-001') AND (vulInfoStat = -1)",
        "(vulKeys IS NULL) AND (assetInfoRange.assetID = 'ASSET-001') "
        "AND (vulInfoStat = -1)",
    ],
)
def test_interface_3_mock_rejects_invalid_protocol_range_structure(invalid_dsl: str) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000070")
    fixture["inner"]["vulInfoRange"] = base64.b64encode(
        invalid_dsl.encode("utf-8")
    ).decode("ascii")

    errors = payloads.validate_business_payload(3, fixture["inner"])

    assert any("vulInfoRange" in error for error in errors), errors


@pytest.mark.parametrize(
    "invalid_dsl",
    [
        "(vulKeys.vulID = NULL) AND "
        "(assetInfoRange.assetID = 'ASSET-001') AND (vulInfoStat = -1)",
        "(vulKeys.vulID = 'MVM-001') AND "
        "(assetInfoRange.targetPortFileLoc = 'abc') AND (vulInfoStat = -1)",
        "(vulKeys.vulLevel = 'high') AND "
        "(assetInfoRange.assetID = 'ASSET-001') AND (vulInfoStat = -1)",
    ],
)
def test_interface_3_mock_rejects_values_that_production_dsl_rejects(
    invalid_dsl: str,
) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000075")
    fixture["inner"]["vulInfoRange"] = base64.b64encode(
        invalid_dsl.encode("utf-8")
    ).decode("ascii")

    errors = payloads.validate_business_payload(3, fixture["inner"])

    assert any("vulInfoRange" in error for error in errors), errors


def test_interface_3_mock_accepts_numeric_and_string_values_by_production_field_type() -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000076")
    fixture["inner"]["vulInfoRange"] = base64.b64encode(
        b"(vulKeys.vulID = 'MVM-001') AND "
        b"(assetInfoRange.targetPortFileLoc = 443) AND (vulInfoStat = -1)"
    ).decode("ascii")

    assert payloads.validate_business_payload(3, fixture["inner"]) == []


@pytest.mark.parametrize(
    ("field", "dictionary_id"),
    [
        ("pwDictID", 0),
        ("pwDictKeys.pwDictID", 65535),
        ("pwDictRange.pwDictID", 32768),
    ],
)
def test_interface_3_mock_accepts_password_dictionary_protocol_range(
    field: str,
    dictionary_id: int,
) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000071")
    fixture["inner"]["vulInfoRange"] = base64.b64encode(
        b"(vulKeys IS NULL) AND (assetInfoRange.assetID = 'ASSET-001') "
        b"AND (vulInfoStat = -1)"
    ).decode("ascii")
    fixture["inner"]["pwDictRange"] = base64.b64encode(
        f"{field} = {dictionary_id}".encode("utf-8")
    ).decode("ascii")

    assert payloads.validate_business_payload(3, fixture["inner"]) == []


def test_interface_3_mock_accepts_protocol_none_password_range() -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000074")
    fixture["inner"]["pwDictRange"] = base64.b64encode(b"None").decode("ascii")

    assert payloads.validate_business_payload(3, fixture["inner"]) == []


@pytest.mark.parametrize("dictionary_id", [-1, 65536])
def test_interface_3_mock_rejects_password_dictionary_id_outside_uint16(
    dictionary_id: int,
) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000072")
    fixture["inner"]["vulInfoRange"] = base64.b64encode(
        b"(vulKeys IS NULL) AND (assetInfoRange.assetID = 'ASSET-001') "
        b"AND (vulInfoStat = -1)"
    ).decode("ascii")
    fixture["inner"]["pwDictRange"] = base64.b64encode(
        f"pwDictID = {dictionary_id}".encode("utf-8")
    ).decode("ascii")

    errors = payloads.validate_business_payload(3, fixture["inner"])

    assert any("pwDictRange" in error for error in errors), errors


def test_interface_3_mock_rejects_product_vulnerability_range_with_password_filter() -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_work_order_request(31, "2026071400000000073")
    fixture["inner"]["pwDictRange"] = base64.b64encode(b"pwDictID = 32768").decode(
        "ascii"
    )

    errors = payloads.validate_business_payload(3, fixture["inner"])

    assert any("vulInfoRange" in error for error in errors), errors


@pytest.mark.parametrize(
    "invalid_dsl",
    [
        "vulInfoStat = 9 trailing",
        "vulInfoStat = 9 AND",
        "(vulInfoStat = 9",
        "(vulInfoStat = 9) AND (unknownField = 1)",
    ],
)
def test_interface_21_mock_rejects_dsl_not_fully_accepted_by_backend(invalid_dsl: str) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(21, "2026071400000000069")
    fixture["inner"]["vulInfoRange"] = base64.b64encode(invalid_dsl.encode("utf-8")).decode(
        "ascii"
    )

    errors = payloads.validate_business_payload(21, fixture["inner"])

    assert any("protocol DSL" in error for error in errors), errors


def test_password_dictionary_rejects_statistical_count_list_mismatch() -> None:
    _, fixtures, payloads, _, _ = _modules()
    dictionary = fixtures.load_password_dictionary_fixture()
    dictionary["pwDictNum"] += 1

    errors = payloads.validate_password_dictionary(dictionary)

    assert any("pwDictNum must equal pwLst length" in error for error in errors)


def test_interface_22_rejects_non_protocol_optional_log_support_file() -> None:
    _, fixtures, _, _, _ = _modules()

    with pytest.raises(ValueError, match="not part of the strict protocol"):
        fixtures.build_additional_fixture(
            22,
            "2026071400000000005",
            include_log_support_file=True,
        )


@pytest.mark.parametrize("interface_no,subtype", [(26, 202), (27, 203)])
def test_202_203_are_strict_province_to_ministry_data_messages(interface_no: int, subtype: int) -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(interface_no, "2026071400000000006")
    inner = fixture["inner"]

    assert fixture["direction"] == "province_to_ministry"
    assert inner["dataType"] == 1
    assert inner["dataSubType"] == subtype
    assert "orderType" not in inner and "orderSubType" not in inner
    assert payloads.validate_business_payload(interface_no, inner) == []


def test_interface_26_tas_sta_obj_has_fixed_shape() -> None:
    _, fixtures, payloads, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(26, "2026071400000000007")
    tas = fixture["inner"]["staReqParams"]["tasStaObj"]
    assert set(tas) == {"taskType", "logType"}

    fixture["inner"]["staReqParams"]["tasStaObj"]["extra"] = "bad"
    assert any("tasStaObj unexpected keys" in error for error in payloads.validate_business_payload(26, fixture["inner"]))


@pytest.mark.parametrize("ctx_code,expects_file", [(0, False), (1, False), (2, True), (5, True), (6, True)])
def test_interface_27_ctx_matrix_controls_file_before_business(ctx_code: int, expects_file: bool) -> None:
    _, fixtures, _, _, _ = _modules()
    fixture = fixtures.build_additional_fixture(27, "2026071400000000008", ctx_code=ctx_code)

    assert fixture["requires_file"] is expects_file
    if expects_file:
        assert fixture["events"] == ["interface11", "upload_file:12", "send_business:203"]
    else:
        assert fixture["events"] == ["send_business:203"]


def test_interface_27_schema_uses_outer_ctx_code() -> None:
    _, fixtures, payloads, _, _ = _modules()
    no_file = fixtures.build_additional_fixture(27, "2026071400000000018", ctx_code=0)["inner"]
    with_file = fixtures.build_additional_fixture(27, "2026071400000000019", ctx_code=2)["inner"]

    assert payloads.validate_business_payload(27, no_file, ctx_code=0) == []
    assert payloads.validate_business_payload(27, with_file, ctx_code=2) == []
    assert any(
        "payload.data is required" in error
        for error in payloads.validate_business_payload(27, no_file, ctx_code=2)
    )
    assert any(
        "payload.data is forbidden" in error
        for error in payloads.validate_business_payload(27, with_file, ctx_code=0)
    )


def _multipart_file_request(
    metadata: dict,
    *,
    filename: str,
    include_file_tag: bool = True,
    duplicate_auth_tags: bool = False,
):
    headers = {
        "X-Enc-Key": "key",
        "X-Enc-Key-G": "key-g",
        "X-Enc-Nonce": "nonce",
        "X-Enc-Auth-Tag": "business-tag",
    }
    if include_file_tag:
        headers["X-Enc-Auth-Tag-File"] = "business-tag" if duplicate_auth_tags else "file-tag"
    prepared = requests.Request(
        "POST",
        "http://mock/ministry/file",
        data={
            "orderID": "0-0-2026071400000000009",
            "orgCode": "150000",
            "ispCode": "CM",
            "ctxCode": "2",
            "reqMsgCnt": json.dumps(metadata, separators=(",", ":")),
        },
        files={"fileChunk": (filename, b"encrypted archive bytes", "application/octet-stream")},
        headers=headers,
    ).prepare()
    return dict(prepared.headers), prepared.body


def test_file_channel_validates_metadata_headers_tar_name_and_chunk_state() -> None:
    _, _, _, envelope, _ = _modules()
    metadata = {
        "dataType": 0,
        "dataSubType": 0,
        "sign": "a" * 64,
        "timeStamp": "1752500000",
    }
    file_id = "a" * 32
    business_name = "password-dictionary.json"
    filename = f"{file_id}_{business_name}_2_1.tar.gz.bin"
    headers, raw_body = _multipart_file_request(metadata, filename=filename)

    observation = envelope.inspect_file_request(path="/ministry/file", headers=headers, raw_body=raw_body)

    assert observation.is_valid
    assert observation.inner == metadata
    assert observation.file_name == filename
    assert observation.chunk_state == "receiving"
    assert observation.archive_directory == f"{file_id}_{business_name}"


def test_file_channel_accepts_protocol_business_name_with_underscores() -> None:
    _, _, _, envelope, _ = _modules()
    metadata = {
        "dataType": 0,
        "dataSubType": 0,
        "sign": "a" * 64,
        "timeStamp": "1752500000",
    }
    file_id = "e" * 32
    business_name = "1-203-2026071400000000070_system_vulnerabilities.json"
    filename = f"{file_id}_{business_name}_1_1.tar.gz.bin"
    headers, raw_body = _multipart_file_request(metadata, filename=filename)

    observation = envelope.inspect_file_request(
        path="/ministry/file",
        headers=headers,
        raw_body=raw_body,
    )

    assert observation.is_valid, observation.errors
    assert observation.business_file_name == business_name


def test_file_channel_does_not_complete_when_only_final_numbered_chunk_arrives() -> None:
    _, _, _, envelope, responses = _modules()
    metadata = {
        "dataType": 0,
        "dataSubType": 0,
        "sign": "a" * 64,
        "timeStamp": "1752500000",
    }
    filename = f'{"d" * 32}_data.json_2_2.tar.gz.bin'
    headers, raw_body = _multipart_file_request(metadata, filename=filename)

    observation = envelope.inspect_file_request(path="/ministry/file", headers=headers, raw_body=raw_body)
    response = responses.build_protocol_response(observation)
    status = json.loads(response.body["statusText"])

    assert status["receivedChunks"] == [2]
    assert status["unpackStatus"] == "receiving"


@pytest.mark.parametrize(
    ("change", "fragment"),
    [
        ("missing_file_tag", "X-Enc-Auth-Tag-File"),
        ("duplicate_auth_tags", "must be independent"),
        ("bad_name", "archive name"),
        ("bad_chunk", "fileChunkID"),
    ],
)
def test_file_channel_rejects_bad_auth_name_and_chunk(change: str, fragment: str) -> None:
    _, _, _, envelope, _ = _modules()
    metadata = {
        "dataType": 0,
        "dataSubType": 0,
        "sign": "a" * 64,
        "timeStamp": "1752500000",
    }
    filename = f'{"b" * 32}_data.json_2_1.tar.gz.bin'
    if change == "bad_name":
        filename = "wrong.tar.gz.bin"
    if change == "bad_chunk":
        filename = f'{"b" * 32}_data.json_2_3.tar.gz.bin'
    headers, raw_body = _multipart_file_request(
        metadata,
        filename=filename,
        include_file_tag=change != "missing_file_tag",
        duplicate_auth_tags=change == "duplicate_auth_tags",
    )

    observation = envelope.inspect_file_request(path="/ministry/file", headers=headers, raw_body=raw_body)

    assert not observation.is_valid
    assert any(fragment in error for error in observation.errors)


@pytest.mark.parametrize(
    ("scenario", "http_status", "status_code", "unpack_status"),
    [
        ("file_completed", 200, 0, "completed"),
        ("file_failed", 200, 1, "failed"),
        ("unpack_failed", 200, 1, "failed"),
        ("file_receiving", 200, 0, "receiving"),
        ("file_partial", 200, 1, "partial"),
    ],
)
def test_file_response_scenarios_return_serialized_status_text(
    scenario: str,
    http_status: int,
    status_code: int,
    unpack_status: str,
) -> None:
    _, _, _, envelope, responses = _modules()
    metadata = {
        "dataType": 0,
        "dataSubType": 0,
        "sign": "a" * 64,
        "timeStamp": "1752500000",
    }
    filename = f'{"c" * 32}_data.json_2_2.tar.gz.bin'
    headers, raw_body = _multipart_file_request(metadata, filename=filename)
    observation = envelope.inspect_file_request(path="/ministry/file", headers=headers, raw_body=raw_body)

    response = responses.build_protocol_response(observation, scenario=scenario)
    status = json.loads(response.body["statusText"])

    assert response.http_status == http_status
    assert response.body["statusCode"] == status_code
    assert status["unpackStatus"] == unpack_status
    assert status["fileTotalChunk"] == 2
    assert status["fileChunkID"] == 2


@pytest.mark.parametrize(
    ("interface_no", "scenario", "http_status", "status_code"),
    [
        (11, "interface11_failure", 200, 1),
        (12, "interface12_failure", 200, 1),
        (26, "business202_failure", 200, 1),
        (27, "business203_failure", 200, 1),
        (11, "timeout", 504, 504),
        (11, "duplicate", 200, 409),
    ],
)
def test_business_failure_injection(interface_no: int, scenario: str, http_status: int, status_code: int) -> None:
    _, fixtures, _, envelope, responses = _modules()
    fixture = fixtures.build_additional_fixture(interface_no, "2026071400000000010", ctx_code=0)
    outer = {key: value for key, value in fixture.items() if key in {"orderID", "orgCode", "ispCode", "ctxCode"}}
    outer["reqMsgCnt"] = json.dumps(fixture["inner"], separators=(",", ":"))
    observation = envelope.inspect_receive_body(
        raw_body=json.dumps(outer).encode(),
        headers={"Content-Type": "application/json"},
    )

    response = responses.build_protocol_response(observation, scenario=scenario)

    assert response.http_status == http_status
    assert response.body["statusCode"] == status_code
