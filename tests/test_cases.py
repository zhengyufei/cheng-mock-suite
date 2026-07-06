from __future__ import annotations

import json
from copy import deepcopy

from mock_ministry.cases import build_plain_envelope, list_cases, load_case


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
    "unknown_subtype_399",
}

NEGATIVE_MUTATIONS = {
    "missing_vulTktReqParams": {
        "case": "prod_vul_workorder_5_request",
        "mutate": lambda inner: inner.pop("vulTktReqParams"),
        "expected_status_code": 6,
    },
    "missing_vulRange": {
        "case": "prod_vul_workorder_5_request",
        "mutate": lambda inner: inner.pop("vulRange"),
        "expected_status_code": 6,
    },
    "missing_product_procTime": {
        "case": "prod_vul_workorder_5_request",
        "mutate": lambda inner: inner.pop("procTime"),
        "expected_status_code": 6,
    },
    "invalid_product_procMethod": {
        "case": "prod_vul_workorder_5_request",
        "mutate": lambda inner: inner["vulTktReqParams"].__setitem__("procMethod", True),
        "expected_status_code": 7,
    },
    "missing_vulTktRspParams": {
        "case": "prod_vul_workorder_6_callback",
        "mutate": lambda inner: inner.pop("vulTktRspParams"),
        "expected_status_code": 6,
    },
    "missing_warning_vulInfoRange": {
        "case": "warning_task_7_request",
        "mutate": lambda inner: inner.pop("vulInfoRange"),
        "expected_status_code": 6,
    },
    "missing_warning_procTime": {
        "case": "warning_task_7_request",
        "mutate": lambda inner: inner.pop("procTime"),
        "expected_status_code": 6,
    },
    "missing_tskRspParams": {
        "case": "warning_task_8_callback",
        "mutate": lambda inner: inner.pop("tskRspParams"),
        "expected_status_code": 6,
    },
    "missing_register_engHash": {
        "case": "device_cmd_309",
        "mutate": lambda inner: inner["registerReqParams"].pop("engHash"),
        "expected_status_code": 6,
    },
    "invalid_register_params": {
        "case": "device_cmd_309",
        "mutate": lambda inner: inner.__setitem__("registerReqParams", "bad"),
        "expected_status_code": 7,
    },
    "invalid_register_engHash": {
        "case": "device_cmd_309",
        "mutate": lambda inner: inner["registerReqParams"].__setitem__("engHash", True),
        "expected_status_code": 7,
    },
    "missing_register_reqAct": {
        "case": "device_cmd_309",
        "mutate": lambda inner: inner["registerReqParams"].pop("reqAct"),
        "expected_status_code": 6,
    },
    "invalid_register_reqAct": {
        "case": "device_cmd_309",
        "mutate": lambda inner: inner["registerReqParams"].__setitem__("reqAct", True),
        "expected_status_code": 7,
    },
    "missing_policy_threshold": {
        "case": "policy_302",
        "mutate": lambda inner: inner["polyReqParams"].pop("reptPerd"),
        "expected_status_code": 6,
    },
    "invalid_policy_threshold": {
        "case": "policy_302",
        "mutate": lambda inner: inner["polyReqParams"].__setitem__("reptPerd", "abc"),
        "expected_status_code": 7,
    },
    "coerced_policy_threshold": {
        "case": "policy_302",
        "mutate": lambda inner: inner["polyReqParams"].__setitem__("reptPerd", "12"),
        "expected_status_code": 7,
    },
    "missing_status_devHash": {
        "case": "platform_status_304",
        "mutate": lambda inner: inner["devInfoReqParams"].pop("devHash"),
        "expected_status_code": 6,
    },
    "invalid_status_devHash": {
        "case": "platform_status_304",
        "mutate": lambda inner: inner["devInfoReqParams"].__setitem__("devHash", True),
        "expected_status_code": 7,
    },
    "invalid_status_params": {
        "case": "platform_status_304",
        "mutate": lambda inner: inner.__setitem__("devInfoReqParams", "bad"),
        "expected_status_code": 7,
    },
    "empty_logInfo": {
        "case": "platform_log_305",
        "mutate": lambda inner: inner["logInfoReqParams"].__setitem__("logInfo", []),
        "expected_status_code": 6,
    },
    "invalid_log_params": {
        "case": "platform_log_305",
        "mutate": lambda inner: inner.__setitem__("logInfoReqParams", []),
        "expected_status_code": 7,
    },
    "missing_log_hash": {
        "case": "platform_log_305",
        "mutate": lambda inner: (
            inner["logInfoReqParams"]["logInfo"][0].pop("hash"),
            inner["logInfoReqParams"]["logInfo"][0].pop("chainHash"),
        ),
        "expected_status_code": 6,
    },
    "invalid_log_hash": {
        "case": "platform_log_305",
        "mutate": lambda inner: inner["logInfoReqParams"]["logInfo"][0].__setitem__("hash", True),
        "expected_status_code": 7,
    },
    "invalid_log_id": {
        "case": "platform_log_305",
        "mutate": lambda inner: inner["logInfoReqParams"]["logInfo"][0].__setitem__("logID", True),
        "expected_status_code": 7,
    },
    "invalid_log_devHash": {
        "case": "platform_log_305",
        "mutate": lambda inner: inner["logInfoReqParams"]["logInfo"][0].__setitem__("devHash", 123),
        "expected_status_code": 7,
    },
    "empty_fileInfoLst": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__("fileInfoLst", []),
        "expected_status_code": 6,
    },
    "incomplete_fileInfo": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__("fileInfoLst", [{}]),
        "expected_status_code": 6,
    },
    "duplicate_fileID": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__(
            "fileInfoLst",
            [
                {"fileID": "same-file", "fileName": "a.bin"},
                {"fileID": "same-file", "fileName": "b.bin"},
            ],
        ),
        "expected_status_code": 7,
    },
    "overlong_fileID": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__(
            "fileInfoLst",
            [{"fileID": "x" * 65, "fileName": "a.bin"}],
        ),
        "expected_status_code": 7,
    },
    "non_object_fileInfo": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__("fileInfoLst", ["not-an-object"]),
        "expected_status_code": 7,
    },
    "duplicate_fileMD5": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__(
            "fileInfoLst",
            [
                {"fileMD5": "same-md5", "fileName": "a.bin"},
                {"fileMD5": "same-md5", "fileName": "b.bin"},
            ],
        ),
        "expected_status_code": 7,
    },
    "unsafe_fileID": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__(
            "fileInfoLst",
            [{"fileID": "../bad", "fileName": "a.bin"}],
        ),
        "expected_status_code": 7,
    },
    "invalid_fileID_type": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__(
            "fileInfoLst",
            [{"fileID": True, "fileName": "a.bin"}],
        ),
        "expected_status_code": 7,
    },
    "invalid_fileName_type": {
        "case": "platform_file_306",
        "mutate": lambda inner: inner["data"].__setitem__(
            "fileInfoLst",
            [{"fileID": "file001", "fileName": True}],
        ),
        "expected_status_code": 7,
    },
    "missing_event_type": {
        "case": "platform_event_303",
        "mutate": lambda inner: inner["eventInfoReqParams"].pop("eventType"),
        "expected_status_code": 6,
    },
    "invalid_event_type": {
        "case": "platform_event_303",
        "mutate": lambda inner: inner["eventInfoReqParams"].__setitem__("eventType", "not-a-number"),
        "expected_status_code": 7,
    },
    "coerced_event_type": {
        "case": "platform_event_303",
        "mutate": lambda inner: inner["eventInfoReqParams"].__setitem__("eventType", "1001"),
        "expected_status_code": 7,
    },
    "missing_event_source": {
        "case": "platform_event_303",
        "mutate": lambda inner: inner["eventInfoReqParams"].pop("eventSource"),
        "expected_status_code": 6,
    },
    "invalid_event_id": {
        "case": "platform_event_303",
        "mutate": lambda inner: inner["eventInfoReqParams"].__setitem__("eventID", True),
        "expected_status_code": 7,
    },
    "missing_event_device_hash": {
        "case": "platform_event_303",
        "mutate": lambda inner: inner["eventInfoReqParams"].pop("devHash"),
        "expected_status_code": 6,
    },
    "invalid_subtype": {
        "case": "platform_event_303",
        "mutate": lambda inner: inner.__setitem__("dataSubType", 399),
        "outer": {"orderID": "2-399-2026070500000000001"},
        "expected_status_code": 1,
    },
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
