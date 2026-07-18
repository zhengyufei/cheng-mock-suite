from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable

from mock_ministry.cases import load_case

Mutation = Callable[[dict[str, Any]], None]

NEGATIVE_MUTATIONS: dict[str, dict[str, Any]] = {
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
    "mixed_log_delivery_modes": {
        "case": "platform_log_305",
        "mutate": lambda inner: inner["logInfoReqParams"].__setitem__(
            "dataFileID", inner["orderID"] if "orderID" in inner else "2-305-2026071400000000001"
        ),
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


def build_negative_case(name: str) -> tuple[dict[str, Any], int]:
    mutation = NEGATIVE_MUTATIONS[name]
    fixture = load_case(str(mutation["case"]))
    mutated_inner = deepcopy(fixture["inner"])
    mutate: Mutation = mutation["mutate"]
    mutate(mutated_inner)
    outer = dict(fixture["outer"])
    if "outer" in mutation:
        outer.update(mutation["outer"])
    return {
        **fixture,
        "name": name,
        "outer": outer,
        "inner": mutated_inner,
        "base_case": mutation["case"],
    }, int(mutation["expected_status_code"])
