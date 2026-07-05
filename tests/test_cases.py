from __future__ import annotations

import json
from copy import deepcopy

from mock_ministry.cases import build_plain_envelope, list_cases, load_case
from mock_ministry.negative_cases import NEGATIVE_MUTATIONS, build_negative_case


REQUIRED_CASES = {
    "prod_vul_workorder_5_request",
    "prod_vul_workorder_6_callback",
    "warning_task_7_request",
    "warning_task_8_callback",
    "policy_302",
    "device_cmd_309",
    "platform_event_303",
    "platform_status_304",
    "platform_log_305",
    "platform_file_306",
    "test_data_307_tst_type_1",
    "test_data_307_tst_type_2",
    "test_data_307_tst_type_3",
    "test_data_307_tst_type_4",
    "test_data_307_tst_type_5",
    "test_data_307_tst_type_6",
    "unknown_subtype_399",
}

def test_list_cases_includes_required_cases() -> None:
    assert REQUIRED_CASES <= set(list_cases())


def test_load_case_and_build_plain_envelope() -> None:
    case = load_case("policy_302")
    envelope = build_plain_envelope(case)

    assert envelope["orderID"] == "2-302-2026070500000000001"
    assert envelope["orgCode"] == "MIIT"
    assert envelope["ispCode"] == "CMCC"
    inner = json.loads(envelope["reqMsgCnt"])
    assert inner["dataType"] == 2
    assert inner["dataSubType"] == 302


def test_load_test_data_307_type_6_envelope_uses_nested_tst_params() -> None:
    case = load_case("test_data_307_tst_type_6")
    envelope = build_plain_envelope(case)

    inner = json.loads(envelope["reqMsgCnt"])
    assert inner["dataType"] == 2
    assert inner["dataSubType"] == 307
    assert inner["tstReqParams"]["tstType"] == 6


def test_negative_mutations_cover_feature_interface_groups() -> None:
    assert set(NEGATIVE_MUTATIONS) == {
        "missing_vulTktReqParams",
        "missing_vulRange",
        "missing_product_procTime",
        "invalid_product_procMethod",
        "missing_vulTktRspParams",
        "missing_warning_vulInfoRange",
        "missing_warning_procTime",
        "missing_tskRspParams",
        "missing_register_engHash",
        "invalid_register_params",
        "invalid_register_engHash",
        "missing_register_reqAct",
        "invalid_register_reqAct",
        "missing_policy_threshold",
        "invalid_policy_threshold",
        "coerced_policy_threshold",
        "missing_status_devHash",
        "invalid_status_devHash",
        "invalid_status_params",
        "empty_logInfo",
        "invalid_log_params",
        "missing_log_hash",
        "invalid_log_hash",
        "invalid_log_id",
        "invalid_log_devHash",
        "empty_fileInfoLst",
        "incomplete_fileInfo",
        "duplicate_fileID",
        "overlong_fileID",
        "non_object_fileInfo",
        "duplicate_fileMD5",
        "unsafe_fileID",
        "invalid_fileID_type",
        "invalid_fileName_type",
        "missing_event_type",
        "invalid_event_type",
        "coerced_event_type",
        "missing_event_source",
        "invalid_event_id",
        "missing_event_device_hash",
        "invalid_subtype",
    }

    for mutation in NEGATIVE_MUTATIONS.values():
        case_name = mutation["case"]
        case = load_case(case_name)
        mutated_inner = deepcopy(case["inner"])
        mutation["mutate"](mutated_inner)
        mutated = {**case, "inner": mutated_inner}
        if "outer" in mutation:
            mutated = {**mutated, "outer": {**case["outer"], **mutation["outer"]}}
        envelope = build_plain_envelope(mutated)
        inner = json.loads(envelope["reqMsgCnt"])

        assert envelope["orderID"] == mutated["outer"]["orderID"]
        assert ("dataSubType" in inner) or ("orderSubType" in inner)
        assert "expected_status_code" in mutation
        if "expected_business_result" not in mutation:
            assert mutation["expected_status_code"] != 0


def test_build_negative_case_returns_mutated_fixture_and_expected_status() -> None:
    case, expected_status = build_negative_case("missing_tskRspParams")
    envelope = build_plain_envelope(case)
    inner = json.loads(envelope["reqMsgCnt"])

    assert case["name"] == "missing_tskRspParams"
    assert expected_status == 6
    assert envelope["orderID"] == "2-101-2026070500000000001"
    assert "tskRspParams" not in inner
    assert inner["orderType"] == 2
    assert inner["orderSubType"] == 101
