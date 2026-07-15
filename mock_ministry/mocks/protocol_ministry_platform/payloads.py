"""Strict plaintext business validators for the additional V2.2 interfaces."""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime
from typing import Any

from .contracts import (
    FILE_INFO_KEYS,
    FILE_REQUIRED_CTX_CODES,
    INTERFACE_ORDER_SUBTYPES,
    INTERFACE_TEST_TYPES,
    OUTBOUND_DATA_SUBTYPES,
    PASSWORD_DICTIONARY_SVC_TYPE,
    PRODUCT_WORK_ORDER_REPLY_SUBTYPES,
    PRODUCT_WORK_ORDER_REQUEST_SUBTYPES,
    SYSTEM_VULNERABILITY_SVC_TYPE,
    TEST_DATA_SUBTYPE,
    TEST_DATA_SVC_TYPES,
    WORK_ORDER_RESPONSE_SUBTYPES,
    WORK_ORDER_STATUS_SLOTS,
    WORK_ORDER_TARGET_STATUSES,
)


PRODUCT_VULNERABILITY_KEYS = {
    "vulName",
    "vulID",
    "lclID",
    "bslDate",
    "orgVulID",
    "numOrg",
    "pubOrgInfo",
    "vulStat",
    "bslVulVal",
    "vulType",
    "vulLevel",
    "assetType",
    "numAfftCmpt",
    "afftCmptInfo",
    "vulDesc",
    "vulPocDesc",
    "expPath",
    "remed",
    "fixLnk",
    "srcMethod",
    "rsvdDesc",
}

SHARED_INTERFACES = frozenset({5, 6, 7, 8, 15, 24, 29, 30, 31, 32})
COMMON_FILE_SVC_DATA_TYPES = {
    -1: "file",
    1: "file",
    3: "file",
    4: "file",
    5: "json",
    6: "file",
    8: "json",
    9: "txt",
    10: "json",
    11: "json",
    12: "json",
    13: "json",
}
QUERY_LOG_TYPE_MIN = 0
QUERY_LOG_TYPE_MAX = 99
SYSTEM_VULNERABILITY_KEYS = {
    "vulInfoID",
    "srcMethod",
    "logIDLst",
    "vulInfoStat",
    "lvRsn",
    "remedTime",
    "assetID",
    "assetLclId",
    "assetName",
    "vulAddrType",
    "vulNetAddr",
    "vulTransProto",
    "vulPort",
    "vulSvc",
    "transferTime",
    "isAccess",
    "unitType",
    "vulInstCpe",
    "vulInstVendor",
    "vulInstClass",
    "vulInstName",
    "vulInstVer",
    "vulInstRunPath",
    "vulInstFilePath",
    "vulInstFileLoc",
    "vulInstOsType",
    "vulInstOsNameVer",
    "vulInstOsVendor",
    "vulInstOsCpe",
    "vulInstDevNameVer",
    "vulInstDevVendor",
    "vulInstDevCpe",
    "assetOwnerinfo",
    "vulPriorVal",
    "vulPriorLvl",
    "vulPriorMID",
}
SYSTEM_VULNERABILITY_REQUIRED_KEYS = {
    "vulInfoID",
    "srcMethod",
    "vulInfoStat",
    "assetID",
    "assetLclId",
    "assetName",
    "vulAddrType",
    "vulNetAddr",
    "vulTransProto",
    "transferTime",
    "isAccess",
    "unitType",
    "vulInstVendor",
    "vulInstClass",
    "vulInstName",
    "vulInstVer",
    "vulInstOsType",
    "vulInstOsNameVer",
    "vulInstOsVendor",
    "vulInstDevNameVer",
    "vulInstDevVendor",
    "vulPriorVal",
    "vulPriorLvl",
}
_UNREPAIRED_SYSTEM_VULNERABILITY_STATUSES = {7, 9}
_REMEDIATION_SYSTEM_VULNERABILITY_STATUSES = {5, 6}
_UNREPAIRED_REASONS = {101, 102, 103, 104, 105, 107, 108, 109, 999}
_REMEDIATION_DURATION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?[日周月]$")

_PROC_TIME_RE = re.compile(r"^(\d{14})-(\d{14})$")
_DSL_FIELD_RE = re.compile(
    r"\b(?:vulKeys(?:\.[A-Za-z][A-Za-z0-9_]*)?|assetInfoRange(?:\.[A-Za-z][A-Za-z0-9_]*)?|"
    r"vulInfoStat|vulInfoID)\b\s*(?:=|!=|like\b|in\b|not\s+in\b|is\s+(?:not\s+)?null\b)",
    re.IGNORECASE,
)
_DSL_FORBIDDEN_RE = re.compile(r"(?:;|--|/\*|\b(?:drop|delete|insert|update|alter|create)\b)", re.IGNORECASE)


def _exact_keys(value: Any, expected: set[str] | frozenset[str], path: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be object")
        return
    missing = set(expected) - set(value)
    extra = set(value) - set(expected)
    if missing:
        errors.append(f"{path} missing keys: {sorted(missing)}")
    if extra:
        errors.append(f"{path} unexpected keys: {sorted(extra)}")


def _reject_null(value: Any, path: str, errors: list[str]) -> None:
    if value is None:
        errors.append(f"{path} must not be null")
    elif isinstance(value, dict):
        for key, child in value.items():
            _reject_null(child, f"{path}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_null(child, f"{path}[{index}]", errors)


def _typed(value: dict[str, Any], field: str, expected: type, path: str, errors: list[str]) -> None:
    actual = value.get(field)
    if type(actual) is not expected:
        errors.append(f"{path}.{field} must be {expected.__name__}")


def _typed_many(
    value: Any,
    fields: set[str] | frozenset[str],
    expected: type,
    path: str,
    errors: list[str],
) -> None:
    if not isinstance(value, dict):
        return
    for field in fields:
        _typed(value, field, expected, path, errors)


def _int_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list) or not all(type(item) is int for item in value):
        errors.append(f"{path} must be int list")


def _fixed_int_list(value: Any, length: int, path: str, errors: list[str]) -> None:
    _int_list(value, path, errors)
    if isinstance(value, list) and len(value) != length:
        errors.append(f"{path} must have length {length}")


def _validate_proc_time(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        return
    match = _PROC_TIME_RE.fullmatch(value)
    if match is None:
        errors.append(f"{path} must use YYYYMMDDhhmmss-YYYYMMDDhhmmss")
        return
    try:
        start = datetime.strptime(match.group(1), "%Y%m%d%H%M%S")
        end = datetime.strptime(match.group(2), "%Y%m%d%H%M%S")
    except ValueError:
        errors.append(f"{path} contains an invalid calendar time")
        return
    if start >= end:
        errors.append(f"{path} start must be earlier than end")


def _validate_base64_dsl(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, str):
        return
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        errors.append(f"{path} must be valid Base64 UTF-8")
        return
    if not decoded.strip() or _DSL_FORBIDDEN_RE.search(decoded) or _DSL_FIELD_RE.search(decoded) is None:
        errors.append(f"{path} must decode to the protocol DSL")


def _validate_file_data(
    value: Any,
    path: str,
    errors: list[str],
    *,
    svc_types: tuple[int, ...] | None = None,
    repeated_svc_type: int | None = None,
) -> tuple[int, ...]:
    expected = {"numFiles", "numTgzs", "fileInfoLst"}
    _exact_keys(value, expected, path, errors)
    if not isinstance(value, dict):
        return ()
    _typed(value, "numFiles", int, path, errors)
    _typed(value, "numTgzs", int, path, errors)
    info_list = value.get("fileInfoLst")
    if not isinstance(info_list, list) or not info_list:
        errors.append(f"{path}.fileInfoLst must be non-empty list")
        return ()
    if type(value.get("numFiles")) is int and value["numFiles"] != len(info_list):
        errors.append(f"{path}.numFiles must equal fileInfoLst length")
    actual_svc_types: list[int] = []
    for index, info in enumerate(info_list):
        info_path = f"{path}.fileInfoLst[{index}]"
        _exact_keys(info, FILE_INFO_KEYS, info_path, errors)
        if not isinstance(info, dict):
            continue
        for field in ("name", "dataType", "objectID", "reserved"):
            _typed(info, field, str, info_path, errors)
        _typed(info, "svcType", int, info_path, errors)
        if type(info.get("svcType")) is int:
            actual_svc_types.append(info["svcType"])
    if repeated_svc_type is not None and any(
        svc_type != repeated_svc_type for svc_type in actual_svc_types
    ):
        errors.append(
            f"{path}.fileInfoLst svcType must contain only {repeated_svc_type}, "
            f"got {tuple(actual_svc_types)}"
        )
    elif svc_types is not None and tuple(actual_svc_types) != svc_types:
        errors.append(f"{path}.fileInfoLst svcType must be {svc_types}, got {tuple(actual_svc_types)}")
    return tuple(actual_svc_types)


def _validate_query_log_type(value: Any, path: str, errors: list[str]) -> None:
    if type(value) is int:
        numeric = value
    elif isinstance(value, str) and re.fullmatch(r"\d{1,2}", value):
        numeric = int(value)
    else:
        errors.append(f"{path} must be an integer or one/two-digit numeric string")
        return
    if not QUERY_LOG_TYPE_MIN <= numeric <= QUERY_LOG_TYPE_MAX:
        errors.append(f"{path} must be between {QUERY_LOG_TYPE_MIN} and {QUERY_LOG_TYPE_MAX}")


def _validate_platform_file_data(
    value: Any,
    path: str,
    errors: list[str],
    *,
    order_id: str | None,
) -> None:
    _validate_file_data(value, path, errors)
    if not isinstance(value, dict) or not isinstance(value.get("fileInfoLst"), list):
        return
    for index, info in enumerate(value["fileInfoLst"]):
        if not isinstance(info, dict):
            continue
        info_path = f"{path}.fileInfoLst[{index}]"
        svc_type = info.get("svcType")
        if type(svc_type) is int:
            if svc_type not in COMMON_FILE_SVC_DATA_TYPES:
                errors.append(f"{info_path}.svcType is not a protocol file business type")
            elif info.get("dataType") != COMMON_FILE_SVC_DATA_TYPES[svc_type]:
                errors.append(
                    f"{info_path}.dataType must be {COMMON_FILE_SVC_DATA_TYPES[svc_type]} "
                    f"for svcType {svc_type}"
                )
        object_id = info.get("objectID")
        if isinstance(object_id, str) and not object_id.strip():
            errors.append(f"{info_path}.objectID must identify the related protocol object")
        reserved = info.get("reserved")
        if svc_type == -1:
            if isinstance(reserved, str) and not reserved.strip():
                errors.append(f"{info_path}.reserved is required when svcType is -1")
            if reserved == "bsxx" and order_id is not None and object_id != order_id:
                errors.append(f"{info_path}.objectID must equal the platform upload orderID for bsxx")
        elif isinstance(reserved, str) and reserved:
            errors.append(f"{info_path}.reserved is only used by svcType -1 platform uploads")


def _validate_order_route(payload: dict[str, Any], subtype: int, errors: list[str]) -> None:
    _typed(payload, "orderType", int, "payload", errors)
    _typed(payload, "orderSubType", int, "payload", errors)
    if payload.get("orderType") != (1 if subtype < 100 else 2):
        errors.append("payload.orderType does not match protocol route")
    if payload.get("orderSubType") != subtype:
        errors.append(f"payload.orderSubType must be {subtype}")


def _validate_upload(interface_no: int, payload: dict[str, Any], errors: list[str]) -> None:
    expected = {"orderType", "orderSubType", "timeStamp", "sign", "tskReqParams"}
    if interface_no == 12 or "data" in payload:
        expected.add("data")
    if interface_no == 11:
        expected.add("vulLst")
    _exact_keys(payload, expected, "payload", errors)
    _validate_order_route(payload, INTERFACE_ORDER_SUBTYPES[interface_no], errors)
    for field in ("timeStamp", "sign"):
        _typed(payload, field, str, "payload", errors)
    expected_svc = (6,) if interface_no == 11 else (PASSWORD_DICTIONARY_SVC_TYPE,)
    if "data" in expected:
        _validate_file_data(payload.get("data"), "payload.data", errors, svc_types=expected_svc)
    task_keys = {"tskPriority", "transID", "rng", "seq", "tskScn", "tskInfo"}
    if interface_no == 11:
        task_keys.add("tskVulNum")
    task = payload.get("tskReqParams")
    _exact_keys(task, task_keys, "payload.tskReqParams", errors)
    if isinstance(task, dict):
        for field in task_keys - {"transID", "tskInfo"}:
            _typed(task, field, int, "payload.tskReqParams", errors)
        for field in ("transID", "tskInfo"):
            _typed(task, field, str, "payload.tskReqParams", errors)
    if interface_no == 11:
        vul_list = payload.get("vulLst")
        _exact_keys(vul_list, {"keyLst", "vulNum"}, "payload.vulLst", errors)
        if isinstance(vul_list, dict):
            _typed(vul_list, "vulNum", int, "payload.vulLst", errors)
            rows = vul_list.get("keyLst")
            if not isinstance(rows, list) or not rows:
                errors.append("payload.vulLst.keyLst must be non-empty list")
            else:
                if type(vul_list.get("vulNum")) is int and vul_list["vulNum"] != len(rows):
                    errors.append("payload.vulLst.vulNum must equal keyLst length")
                for index, row in enumerate(rows):
                    _validate_product_vulnerability(row, f"payload.vulLst.keyLst[{index}]", errors)


def _validate_product_vulnerability(value: Any, path: str, errors: list[str]) -> None:
    _exact_keys(value, PRODUCT_VULNERABILITY_KEYS, path, errors)
    if not isinstance(value, dict):
        return
    for field in {
        "vulName", "vulID", "lclID", "bslDate", "orgVulID", "assetType", "vulDesc",
        "vulPocDesc", "remed", "fixLnk", "rsvdDesc",
    }:
        _typed(value, field, str, path, errors)
    for field in {"numOrg", "vulStat", "vulType", "vulLevel", "numAfftCmpt", "expPath", "srcMethod"}:
        _typed(value, field, int, path, errors)
    _typed(value, "bslVulVal", float, path, errors)

    publish_orgs = value.get("pubOrgInfo")
    if not isinstance(publish_orgs, list):
        errors.append(f"{path}.pubOrgInfo must be list")
    else:
        if type(value.get("numOrg")) is int and value["numOrg"] != len(publish_orgs):
            errors.append(f"{path}.numOrg must equal pubOrgInfo length")
        for index, row in enumerate(publish_orgs):
            row_path = f"{path}.pubOrgInfo[{index}]"
            _exact_keys(row, {"pubOrgID", "pubVulID", "pubDate", "pubVulVal"}, row_path, errors)
            if isinstance(row, dict):
                for field in ("pubOrgID", "pubVulID", "pubDate"):
                    _typed(row, field, str, row_path, errors)
                _typed(row, "pubVulVal", float, row_path, errors)

    components = value.get("afftCmptInfo")
    if not isinstance(components, list):
        errors.append(f"{path}.afftCmptInfo must be list")
    else:
        if type(value.get("numAfftCmpt")) is int and value["numAfftCmpt"] != len(components):
            errors.append(f"{path}.numAfftCmpt must equal afftCmptInfo length")
        for index, row in enumerate(components):
            row_path = f"{path}.afftCmptInfo[{index}]"
            _exact_keys(row, {"cmptVendor", "cmptClass", "cmptName", "cmptVer"}, row_path, errors)
            if isinstance(row, dict):
                for field in ("cmptVendor", "cmptName", "cmptVer"):
                    _typed(row, field, str, row_path, errors)
                _typed(row, "cmptClass", int, row_path, errors)


def _validate_test_data(interface_no: int, payload: dict[str, Any], errors: list[str]) -> None:
    tst_type = INTERFACE_TEST_TYPES[interface_no]
    expected = {"dataType", "dataSubType", "sign", "tstReqParams", "timeStamp"}
    if tst_type in {1, 2}:
        expected.add("data")
    if tst_type in {3, 5, 6}:
        expected.add("procTime")
    if tst_type in {5, 6}:
        expected.add("vulInfoRange")
    _exact_keys(payload, expected, "payload", errors)
    if "orderType" in payload or "orderSubType" in payload:
        errors.append("payload must not contain orderType/orderSubType")
    for field in ("dataType", "dataSubType"):
        _typed(payload, field, int, "payload", errors)
    if payload.get("dataType") != 2 or payload.get("dataSubType") != TEST_DATA_SUBTYPE:
        errors.append("payload data route must be 2/307")
    _typed_many(payload, {"timeStamp", "sign"}, str, "payload", errors)
    if "procTime" in expected:
        _typed(payload, "procTime", str, "payload", errors)
        _validate_proc_time(payload.get("procTime"), "payload.procTime", errors)
    if "vulInfoRange" in expected:
        _typed(payload, "vulInfoRange", str, "payload", errors)
        _validate_base64_dsl(payload.get("vulInfoRange"), "payload.vulInfoRange", errors)
    params = payload.get("tstReqParams")
    param_keys = {"logType", "orderIDLst", "tstType"} | ({"opCode"} if tst_type != 1 else set())
    _exact_keys(params, param_keys, "payload.tstReqParams", errors)
    if isinstance(params, dict):
        if params.get("tstType") != tst_type:
            errors.append(f"payload.tstReqParams.tstType must be {tst_type}")
        for field in param_keys - {"orderIDLst", "logType"}:
            _typed(params, field, int, "payload.tstReqParams", errors)
        _typed(params, "orderIDLst", str, "payload.tstReqParams", errors)
        _validate_query_log_type(params.get("logType"), "payload.tstReqParams.logType", errors)
        if "opCode" in params and params.get("opCode") != 1:
            errors.append("payload.tstReqParams.opCode must be 1")
    if "data" in expected:
        _validate_file_data(payload.get("data"), "payload.data", errors, svc_types=TEST_DATA_SVC_TYPES[tst_type])


_STAT_KEYS = {"numVulInfo", "astNum", "vulNum", "pwdNum", "prcAstNum", "exRsnLst", "exRsnNumLst"}


def _validate_statistics(
    interface_no: int,
    payload: dict[str, Any],
    errors: list[str],
    *,
    ctx_code: int | None,
) -> None:
    expected = {"dataType", "dataSubType", "timeStamp", "sign", "procTime", "staReqParams"}
    if interface_no == 27 and "data" in payload:
        expected.add("data")
    _exact_keys(payload, expected, "payload", errors)
    if "orderType" in payload or "orderSubType" in payload:
        errors.append("payload must not contain orderType/orderSubType")
    for field in ("dataType", "dataSubType"):
        _typed(payload, field, int, "payload", errors)
    if payload.get("dataType") != 1 or payload.get("dataSubType") != OUTBOUND_DATA_SUBTYPES[interface_no]:
        errors.append(f"payload data route must be 1/{OUTBOUND_DATA_SUBTYPES[interface_no]}")
    stat_keys = set(_STAT_KEYS)
    if interface_no == 26:
        stat_keys.add("tasStaObj")
    stats = payload.get("staReqParams")
    _exact_keys(stats, stat_keys, "payload.staReqParams", errors)
    if isinstance(stats, dict):
        if "tasStaObj" in stats:
            tas = stats["tasStaObj"]
            _exact_keys(tas, {"taskType", "logType"}, "tasStaObj", errors)
            if isinstance(tas, dict):
                _typed(tas, "taskType", str, "tasStaObj", errors)
                _typed(tas, "logType", str, "tasStaObj", errors)
        for field in _STAT_KEYS - {"exRsnLst", "exRsnNumLst"}:
            _typed(stats, field, int, "payload.staReqParams", errors)
        for field in ("exRsnLst", "exRsnNumLst"):
            _fixed_int_list(stats.get(field), 8, f"payload.staReqParams.{field}", errors)
        if isinstance(stats.get("exRsnLst"), list) and isinstance(stats.get("exRsnNumLst"), list):
            if len(stats["exRsnLst"]) != len(stats["exRsnNumLst"]):
                errors.append("payload.staReqParams reason code/count lists must have equal length")
    if "data" in payload:
        _validate_file_data(
            payload["data"],
            "payload.data",
            errors,
            repeated_svc_type=SYSTEM_VULNERABILITY_SVC_TYPE,
        )
    if interface_no == 27 and ctx_code is not None:
        requires_file = ctx_code in FILE_REQUIRED_CTX_CODES
        if requires_file and "data" not in payload:
            errors.append("payload.data is required for this ctxCode")
        if not requires_file and "data" in payload:
            errors.append("payload.data is forbidden for this ctxCode")


def _validate_work_order(interface_no: int, payload: dict[str, Any], errors: list[str]) -> None:
    if interface_no == 3:
        expected = {
            "orderType",
            "orderSubType",
            "timeStamp",
            "sign",
            "procTime",
            "timePerd",
            "vulInfoRange",
            "vulInfoTktReqParams",
        }
        _exact_keys(payload, expected, "payload", errors)
        if payload.get("orderSubType") not in WORK_ORDER_RESPONSE_SUBTYPES:
            errors.append("payload.orderSubType must be one of 31/32/33/34")
        period = payload.get("timePerd")
        _exact_keys(period, {"unit", "perd"}, "timePerd", errors)
        if isinstance(period, dict):
            _typed(period, "unit", int, "timePerd", errors)
            _typed(period, "perd", int, "timePerd", errors)
            if period.get("unit") not in {1, 2, 3, 4}:
                errors.append("timePerd.unit must be a protocol duration enum")
            if type(period.get("perd")) is int and period["perd"] <= 0:
                errors.append("timePerd.perd must be positive")
        request = payload.get("vulInfoTktReqParams")
        request_keys = {
            "vptModID",
            "srcTktRole",
            "dstTktRole",
            "dstVulInfoStat",
            "procMethod",
            "tktPriority",
            "tktVulNum",
            "tktAstNum",
            "tktSLA",
            "tktInfo",
        }
        _exact_keys(request, request_keys, "vulInfoTktReqParams", errors)
        if isinstance(request, dict):
            integer_fields = request_keys - {"vptModID", "dstVulInfoStat", "tktSLA", "tktInfo"}
            for field in integer_fields:
                _typed(request, field, int, "vulInfoTktReqParams", errors)
            for field in ("vptModID", "tktSLA", "tktInfo"):
                _typed(request, field, str, "vulInfoTktReqParams", errors)
            statuses = request.get("dstVulInfoStat")
            _fixed_int_list(statuses, 10, "vulInfoTktReqParams.dstVulInfoStat", errors)
    else:
        expected = {
            "orderType",
            "orderSubType",
            "timeStamp",
            "sign",
            "vulInfoLst",
            "vulInfoTktRspParams",
        }
        if "data" in payload:
            expected.add("data")
        _exact_keys(payload, expected, "payload", errors)
        if payload.get("orderSubType") not in set(WORK_ORDER_RESPONSE_SUBTYPES.values()):
            errors.append("payload.orderSubType must be one of 41/42/43/44")
        vulnerability_list = payload.get("vulInfoLst")
        actual_status_counts = {status: 0 for status in WORK_ORDER_STATUS_SLOTS}
        actual_instance_count = 0
        _exact_keys(vulnerability_list, {"vulNum", "engLst", "comVulLst"}, "vulInfoLst", errors)
        if isinstance(vulnerability_list, dict):
            _typed(vulnerability_list, "vulNum", int, "vulInfoLst", errors)
            engineering = vulnerability_list.get("engLst")
            _exact_keys(engineering, {"engNum", "engDevs"}, "vulInfoLst.engLst", errors)
            if isinstance(engineering, dict):
                _typed(engineering, "engNum", int, "vulInfoLst.engLst", errors)
                devices = engineering.get("engDevs")
                if not isinstance(devices, list):
                    errors.append("vulInfoLst.engLst.engDevs must be list")
                else:
                    if type(engineering.get("engNum")) is int and engineering["engNum"] != len(devices):
                        errors.append("vulInfoLst.engLst.engNum must equal engDevs length")
                    for index, device in enumerate(devices):
                        path = f"vulInfoLst.engLst.engDevs[{index}]"
                        _exact_keys(device, {"engHash", "engType"}, path, errors)
                        if isinstance(device, dict):
                            _typed(device, "engHash", str, path, errors)
                            _typed(device, "engType", int, path, errors)
            rows = vulnerability_list.get("comVulLst")
            if not isinstance(rows, list):
                errors.append("vulInfoLst.comVulLst must be list")
            else:
                if type(vulnerability_list.get("vulNum")) is int and vulnerability_list["vulNum"] != len(rows):
                    errors.append("vulInfoLst.vulNum must equal comVulLst length")
                for index, row in enumerate(rows):
                    row_path = f"vulInfoLst.comVulLst[{index}]"
                    if not isinstance(row, dict):
                        errors.append(f"{row_path} must be object")
                        continue
                    identifier_keys = {"vulID", "pwDictInstID"} & set(row)
                    expected_keys = {"assetNum", "instVulLst"} | identifier_keys
                    _exact_keys(row, expected_keys, row_path, errors)
                    if len(identifier_keys) != 1:
                        errors.append(f"{row_path} requires exactly one vulnerability identifier")
                    else:
                        _typed(row, next(iter(identifier_keys)), str, row_path, errors)
                    _typed(row, "assetNum", int, row_path, errors)
                    instances = row.get("instVulLst")
                    if not isinstance(instances, list):
                        errors.append(f"{row_path}.instVulLst must be list")
                        continue
                    if type(row.get("assetNum")) is int and row["assetNum"] != len(instances):
                        errors.append(f"{row_path}.assetNum must equal instVulLst length")
                    actual_instance_count += len(instances)
                    for instance_index, instance in enumerate(instances):
                        _validate_system_vulnerability(
                            instance,
                            f"{row_path}.instVulLst[{instance_index}]",
                            errors,
                        )
                        if isinstance(instance, dict) and type(instance.get("vulInfoStat")) is int:
                            status = instance["vulInfoStat"]
                            if status in actual_status_counts:
                                actual_status_counts[status] += 1
        if "data" in payload:
            _validate_file_data(payload["data"], "payload.data", errors)
        response = payload.get("vulInfoTktRspParams")
        response_keys = {
            "srcTktRole",
            "srcTktProcer",
            "srcTktProcerDept",
            "dstTktRole",
            "transID",
            "prcVulNum",
            "toPrcAstNum",
            "prcAstNum",
            "exRsnLst",
            "exRsnNumLst",
            "dstVulInfoStat",
            "sucVulInfoNum",
            "tktResult",
            "tktInfo",
            "logNum",
        }
        _exact_keys(response, response_keys, "vulInfoTktRspParams", errors)
        if isinstance(response, dict):
            for field in (
                "srcTktRole",
                "dstTktRole",
                "prcVulNum",
                "toPrcAstNum",
                "prcAstNum",
                "tktResult",
                "logNum",
            ):
                _typed(response, field, int, "vulInfoTktRspParams", errors)
            for field in ("srcTktProcer", "srcTktProcerDept", "transID", "tktInfo"):
                _typed(response, field, str, "vulInfoTktRspParams", errors)
            for field in ("exRsnLst", "exRsnNumLst", "dstVulInfoStat", "sucVulInfoNum"):
                values = response.get(field)
                length = 8 if field in {"exRsnLst", "exRsnNumLst"} else 10
                _fixed_int_list(values, length, f"vulInfoTktRspParams.{field}", errors)
            if isinstance(response.get("exRsnLst"), list) and isinstance(response.get("exRsnNumLst"), list):
                if len(response["exRsnLst"]) != len(response["exRsnNumLst"]):
                    errors.append("vulInfoTktRspParams reason code/count lists must have equal length")
            destinations = response.get("dstVulInfoStat")
            success_counts = response.get("sucVulInfoNum")
            if (
                isinstance(destinations, list)
                and len(destinations) == len(WORK_ORDER_STATUS_SLOTS)
                and isinstance(success_counts, list)
                and len(success_counts) == len(WORK_ORDER_STATUS_SLOTS)
                and all(type(value) is int for value in destinations + success_counts)
            ):
                response_subtype = payload.get("orderSubType")
                request_subtype = next(
                    (
                        request
                        for request, response_code in WORK_ORDER_RESPONSE_SUBTYPES.items()
                        if response_code == response_subtype
                    ),
                    None,
                )
                allowed_targets = WORK_ORDER_TARGET_STATUSES.get(request_subtype, frozenset())
                expected_success_counts = []
                active_targets = set()
                for slot, destination in zip(WORK_ORDER_STATUS_SLOTS, destinations):
                    if destination not in {-1, slot}:
                        errors.append(
                            "vulInfoTktRspParams.dstVulInfoStat must use its fixed status slot"
                        )
                    if destination == -1:
                        expected_success_counts.append(-1)
                    else:
                        active_targets.add(destination)
                        expected_success_counts.append(actual_status_counts[destination])
                if active_targets and not active_targets.issubset(allowed_targets):
                    errors.append(
                        "vulInfoTktRspParams.dstVulInfoStat does not match the work-order workflow"
                    )
                if success_counts != expected_success_counts:
                    errors.append(
                        "vulInfoTktRspParams.sucVulInfoNum must match actual vulnerability statuses"
                    )

                processed_count = response.get("prcVulNum")
                if type(processed_count) is int and processed_count != actual_instance_count:
                    errors.append(
                        "vulInfoTktRspParams.prcVulNum must equal the actual vulnerability instance count"
                    )
                successful_count = sum(actual_status_counts[value] for value in active_targets)
                result = response.get("tktResult")
                if result == 0 and successful_count != 0:
                    errors.append("vulInfoTktRspParams all failed requires zero successful vulnerabilities")
                if (
                    result == 1
                    and type(processed_count) is int
                    and successful_count != processed_count
                ):
                    errors.append(
                        "vulInfoTktRspParams all success requires every processed vulnerability"
                    )
                if (
                    result == 2
                    and type(processed_count) is int
                    and not 0 < successful_count < processed_count
                ):
                    errors.append(
                        "vulInfoTktRspParams partial result requires successful and failed vulnerabilities"
                    )
    _typed(payload, "orderType", int, "payload", errors)
    _typed(payload, "orderSubType", int, "payload", errors)
    _typed(payload, "timeStamp", str, "payload", errors)
    _typed(payload, "sign", str, "payload", errors)
    if "procTime" in payload:
        _validate_proc_time(payload.get("procTime"), "payload.procTime", errors)
    if "vulInfoRange" in payload:
        _validate_base64_dsl(payload.get("vulInfoRange"), "payload.vulInfoRange", errors)
    if payload.get("orderType") != 1:
        errors.append("payload.orderType must be 1")


def _validate_shared_route(
    payload: dict[str, Any],
    *,
    family: str,
    route_type: int,
    subtype: int,
    errors: list[str],
) -> None:
    type_key = f"{family}Type"
    subtype_key = f"{family}SubType"
    _typed(payload, type_key, int, "payload", errors)
    _typed(payload, subtype_key, int, "payload", errors)
    if payload.get(type_key) != route_type or payload.get(subtype_key) != subtype:
        errors.append(f"payload route must be {route_type}/{subtype}")


def _validate_system_vulnerability(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{path} must be object")
        return
    missing = SYSTEM_VULNERABILITY_REQUIRED_KEYS - set(value)
    unexpected = set(value) - SYSTEM_VULNERABILITY_KEYS
    if missing:
        errors.append(f"{path} missing keys: {sorted(missing)}")
    if unexpected:
        errors.append(f"{path} unexpected keys: {sorted(unexpected)}")

    string_fields = SYSTEM_VULNERABILITY_KEYS - {
        "srcMethod",
        "vulInfoStat",
        "lvRsn",
        "vulAddrType",
        "vulPort",
        "isAccess",
        "vulInstClass",
        "vulPriorVal",
        "vulPriorLvl",
    }
    _typed_many(value, string_fields & set(value), str, path, errors)
    _typed_many(
        value,
        {
            "srcMethod",
            "vulInfoStat",
            "lvRsn",
            "vulAddrType",
            "vulPort",
            "isAccess",
            "vulInstClass",
            "vulPriorLvl",
        } & set(value),
        int,
        path,
        errors,
    )
    if "vulPriorVal" in value:
        _typed(value, "vulPriorVal", float, path, errors)

    status = value.get("vulInfoStat")
    if type(status) is int:
        if status in _UNREPAIRED_SYSTEM_VULNERABILITY_STATUSES:
            if "lvRsn" not in value:
                errors.append(f"{path}.lvRsn is required for an unrepaired system vulnerability")
        elif "lvRsn" in value:
            errors.append(f"{path}.lvRsn is only allowed for an unrepaired system vulnerability")

        if status in _REMEDIATION_SYSTEM_VULNERABILITY_STATUSES:
            if "remedTime" not in value:
                errors.append(f"{path}.remedTime is required during the repair phase")
        elif "remedTime" in value:
            errors.append(f"{path}.remedTime is only allowed during the repair phase")

    if type(value.get("lvRsn")) is int and value["lvRsn"] not in _UNREPAIRED_REASONS:
        errors.append(f"{path}.lvRsn is not a valid unrepaired reason")
    if "remedTime" in value and isinstance(value["remedTime"], str):
        if _REMEDIATION_DURATION_RE.fullmatch(value["remedTime"]) is None:
            errors.append(f"{path}.remedTime must be a number followed by 日, 周, or 月")
    if isinstance(value.get("transferTime"), str) and not value["transferTime"].isdigit():
        errors.append(f"{path}.transferTime must be a numeric protocol timestamp")
    if type(value.get("vulPort")) is int and not 0 <= value["vulPort"] <= 65535:
        errors.append(f"{path}.vulPort must be between 0 and 65535")


def _validate_task_response(value: Any, path: str, errors: list[str]) -> None:
    keys = {
        "tskProcIndication",
        "prcVulNum",
        "prcPwNum",
        "toPrcAstNum",
        "prcAstNum",
        "exRsnLst",
        "exRsnNumLst",
        "logNum",
    }
    _exact_keys(value, keys, path, errors)
    _typed_many(value, keys - {"exRsnLst", "exRsnNumLst"}, int, path, errors)
    if isinstance(value, dict):
        _int_list(value.get("exRsnLst"), f"{path}.exRsnLst", errors)
        _int_list(value.get("exRsnNumLst"), f"{path}.exRsnNumLst", errors)


def _validate_shared_work_orders(interface_no: int, payload: dict[str, Any], errors: list[str]) -> None:
    if interface_no == 5:
        expected = {
            "orderType", "orderSubType", "timeStamp", "sign", "procTime", "vulRange",
            "vulTktReqParams",
        }
        if "data" in payload:
            expected.add("data")
        _exact_keys(payload, expected, "payload", errors)
        _typed(payload, "orderType", int, "payload", errors)
        _typed(payload, "orderSubType", int, "payload", errors)
        if (
            payload.get("orderType") != 1
            or payload.get("orderSubType") not in PRODUCT_WORK_ORDER_REQUEST_SUBTYPES
        ):
            errors.append("payload route must be 1/11 or 1/12")
        _typed_many(payload, {"procTime", "vulRange"}, str, "payload", errors)
        request = payload.get("vulTktReqParams")
        request_keys = {
            "procMethod", "srcTktRole", "dstTktRole", "dstVulStat", "tktPriority",
            "tktSLA", "tktVulNum", "tktInfo",
        }
        _exact_keys(request, request_keys, "payload.vulTktReqParams", errors)
        _typed_many(request, request_keys - {"tktInfo"}, int, "payload.vulTktReqParams", errors)
        _typed_many(request, {"tktInfo"}, str, "payload.vulTktReqParams", errors)
        if "data" in payload:
            _validate_file_data(payload["data"], "payload.data", errors, svc_types=(1,))
        return
    if interface_no == 6:
        expected = {
            "orderType", "orderSubType", "timeStamp", "sign", "vulTktRspParams", "vulIdLst",
        }
        if "data" in payload:
            expected.add("data")
        _exact_keys(payload, expected, "payload", errors)
        _typed(payload, "orderType", int, "payload", errors)
        _typed(payload, "orderSubType", int, "payload", errors)
        if (
            payload.get("orderType") != 1
            or payload.get("orderSubType") not in PRODUCT_WORK_ORDER_REPLY_SUBTYPES
        ):
            errors.append("payload route must be 1/21 or 1/22")
        response = payload.get("vulTktRspParams")
        response_keys = {
            "srcTktRole", "srcTktProcer", "srcTktProcerDept", "dstTktRole", "prcVulNum",
            "dstVulStat", "sucVulNum", "tktResult", "tktInfo",
        }
        _exact_keys(response, response_keys, "payload.vulTktRspParams", errors)
        _typed_many(
            response,
            {"srcTktRole", "dstTktRole", "prcVulNum", "tktResult"},
            int,
            "payload.vulTktRspParams",
            errors,
        )
        _typed_many(
            response,
            {"srcTktProcer", "srcTktProcerDept", "tktInfo"},
            str,
            "payload.vulTktRspParams",
            errors,
        )
        if isinstance(response, dict):
            _int_list(response.get("dstVulStat"), "payload.vulTktRspParams.dstVulStat", errors)
            _int_list(response.get("sucVulNum"), "payload.vulTktRspParams.sucVulNum", errors)
        ids = payload.get("vulIdLst")
        _exact_keys(ids, {"idLst", "vulNum"}, "payload.vulIdLst", errors)
        if isinstance(ids, dict):
            _typed(ids, "vulNum", int, "payload.vulIdLst", errors)
            rows = ids.get("idLst")
            if not isinstance(rows, list):
                errors.append("payload.vulIdLst.idLst must be list")
            else:
                for index, item in enumerate(rows):
                    item_path = f"payload.vulIdLst.idLst[{index}]"
                    _exact_keys(item, {"vulID"}, item_path, errors)
                    if isinstance(item, dict):
                        _typed(item, "vulID", str, item_path, errors)
            if (
                isinstance(rows, list)
                and type(ids.get("vulNum")) is int
                and ids["vulNum"] != len(rows)
            ):
                errors.append("payload.vulIdLst.vulNum must equal idLst length")
        if "data" in payload:
            _validate_file_data(payload["data"], "payload.data", errors, svc_types=(1,))
        return
    if interface_no == 7:
        expected = {
            "orderType", "orderSubType", "timeStamp", "sign", "vulInfoRange", "procTime",
            "tskReqParams", "timePerd",
        }
        _exact_keys(payload, expected, "payload", errors)
        _validate_shared_route(payload, family="order", route_type=2, subtype=101, errors=errors)
        _typed_many(payload, {"vulInfoRange", "procTime"}, str, "payload", errors)
        task = payload.get("tskReqParams")
        task_keys = {
            "procMethod", "seq", "tskScn", "rng", "tskPriority", "tskInfo", "astUnitNum", "transID",
        }
        _exact_keys(task, task_keys, "payload.tskReqParams", errors)
        _typed_many(task, task_keys - {"tskInfo", "transID"}, int, "payload.tskReqParams", errors)
        _typed_many(task, {"tskInfo", "transID"}, str, "payload.tskReqParams", errors)
        period = payload.get("timePerd")
        _exact_keys(period, {"unit", "perd"}, "payload.timePerd", errors)
        _typed_many(period, {"unit", "perd"}, int, "payload.timePerd", errors)
        return
    expected = {"orderType", "orderSubType", "timeStamp", "sign", "vulInfoLst", "tskRspParams"}
    if "data" in payload:
        expected.add("data")
    _exact_keys(payload, expected, "payload", errors)
    _validate_shared_route(payload, family="order", route_type=2, subtype=101, errors=errors)
    vul_list = payload.get("vulInfoLst")
    _exact_keys(vul_list, {"vulNum", "comVulLst"}, "payload.vulInfoLst", errors)
    if isinstance(vul_list, dict):
        _typed(vul_list, "vulNum", int, "payload.vulInfoLst", errors)
        rows = vul_list.get("comVulLst")
        if not isinstance(rows, list):
            errors.append("payload.vulInfoLst.comVulLst must be list")
        else:
            if type(vul_list.get("vulNum")) is int and vul_list["vulNum"] != len(rows):
                errors.append("payload.vulInfoLst.vulNum must equal comVulLst length")
            for index, row in enumerate(rows):
                row_path = f"payload.vulInfoLst.comVulLst[{index}]"
                _exact_keys(row, {"vulID", "assetNum", "instVulLst"}, row_path, errors)
                if not isinstance(row, dict):
                    continue
                _typed(row, "vulID", str, row_path, errors)
                _typed(row, "assetNum", int, row_path, errors)
                instances = row.get("instVulLst")
                if not isinstance(instances, list):
                    errors.append(f"{row_path}.instVulLst must be list")
                else:
                    if type(row.get("assetNum")) is int and row["assetNum"] != len(instances):
                        errors.append(f"{row_path}.assetNum must equal instVulLst length")
                    for instance_index, instance in enumerate(instances):
                        _validate_system_vulnerability(
                            instance,
                            f"{row_path}.instVulLst[{instance_index}]",
                            errors,
                        )
    _validate_task_response(payload.get("tskRspParams"), "payload.tskRspParams", errors)
    if "data" in payload:
        _validate_file_data(
            payload["data"],
            "payload.data",
            errors,
            svc_types=(SYSTEM_VULNERABILITY_SVC_TYPE,),
        )


def _validate_shared_data(
    interface_no: int,
    payload: dict[str, Any],
    errors: list[str],
    *,
    order_id: str | None,
) -> None:
    subtypes = {15: 302, 24: 309, 29: 303, 30: 304, 31: 305, 32: 306}
    subtype = subtypes[interface_no]
    top_level = {
        15: {"dataType", "dataSubType", "timeStamp", "sign", "polyReqParams"},
        24: {"dataType", "dataSubType", "timeStamp", "sign", "registerReqParams"},
        29: {"dataType", "dataSubType", "timeStamp", "sign", "eventInfoReqParams"},
        30: {"dataType", "dataSubType", "timeStamp", "sign", "devInfoReqParams"},
        31: {"dataType", "dataSubType", "timeStamp", "sign", "procTime", "logInfoReqParams"},
        32: {"dataType", "dataSubType", "timeStamp", "sign", "data"},
    }[interface_no]
    if interface_no == 31 and "data" in payload:
        top_level.add("data")
    _exact_keys(payload, top_level, "payload", errors)
    _validate_shared_route(payload, family="data", route_type=2, subtype=subtype, errors=errors)
    if interface_no == 15:
        params = payload.get("polyReqParams")
        keys = {"reptPerd", "sycPerd", "devHash", "sycNum", "decIp", "reptNum", "perdType"}
        _exact_keys(params, keys, "payload.polyReqParams", errors)
        _typed_many(params, keys - {"devHash", "decIp"}, int, "payload.polyReqParams", errors)
        _typed_many(params, {"devHash", "decIp"}, str, "payload.polyReqParams", errors)
    elif interface_no == 24:
        params = payload.get("registerReqParams")
        _exact_keys(params, {"devHash", "devIp"}, "payload.registerReqParams", errors)
        _typed_many(params, {"devHash", "devIp"}, str, "payload.registerReqParams", errors)
    elif interface_no == 29:
        params = payload.get("eventInfoReqParams")
        keys = {"eventId", "devHash", "eventSource", "eventDescription", "eventArgs"}
        _exact_keys(params, keys, "payload.eventInfoReqParams", errors)
        _typed_many(params, {"eventId"}, int, "payload.eventInfoReqParams", errors)
        _typed_many(params, keys - {"eventId"}, str, "payload.eventInfoReqParams", errors)
    elif interface_no == 30:
        _validate_device_status(payload.get("devInfoReqParams"), errors)
    elif interface_no == 31:
        _typed(payload, "procTime", str, "payload", errors)
        _validate_platform_logs(payload.get("logInfoReqParams"), errors)
        if "data" in payload:
            actual = _validate_file_data(payload["data"], "payload.data", errors)
            if actual not in {(11,), (11, 13)}:
                errors.append(
                    "payload.data.fileInfoLst svcType must be (11,) or (11, 13), "
                    f"got {actual}"
                )
    else:
        _validate_platform_file_data(payload.get("data"), "payload.data", errors, order_id=order_id)


def _validate_device_status(value: Any, errors: list[str]) -> None:
    path = "payload.devInfoReqParams"
    keys = {"devInfoObj", "monitDataObj", "devHash", "devType", "token", "netTrafficObj", "devIp"}
    _exact_keys(value, keys, path, errors)
    _typed_many(value, {"devHash", "token", "devIp"}, str, path, errors)
    _typed_many(value, {"devType"}, int, path, errors)
    if not isinstance(value, dict):
        return
    device = value.get("devInfoObj")
    device_keys = {
        "product", "devModel", "installTime", "factoryVersion", "devHash", "devName",
        "updateTime", "curVersion", "isVirtual", "versionType", "loginUrl",
    }
    _exact_keys(device, device_keys, f"{path}.devInfoObj", errors)
    _typed_many(device, device_keys - {"isVirtual"}, str, f"{path}.devInfoObj", errors)
    _typed_many(device, {"isVirtual"}, int, f"{path}.devInfoObj", errors)
    monitor = value.get("monitDataObj")
    _exact_keys(monitor, {"resourceLoadObj", "devStatus", "devHash", "devType"}, f"{path}.monitDataObj", errors)
    _typed_many(monitor, {"devStatus"}, int, f"{path}.monitDataObj", errors)
    _typed_many(monitor, {"devHash", "devType"}, str, f"{path}.monitDataObj", errors)
    if isinstance(monitor, dict):
        resources = monitor.get("resourceLoadObj")
        resource_keys = {"cpuInfo", "memInfo", "otherInfo", "cfInfo", "flowInfo", "diskInfo"}
        _exact_keys(resources, resource_keys, f"{path}.monitDataObj.resourceLoadObj", errors)
        _typed_many(resources, resource_keys, str, f"{path}.monitDataObj.resourceLoadObj", errors)
    traffic = value.get("netTrafficObj")
    traffic_keys = {
        "obps", "obytes", "procTime", "ipps", "name", "ibps", "ipackets", "opps", "opackets", "ibytes",
    }
    _exact_keys(traffic, traffic_keys, f"{path}.netTrafficObj", errors)
    _typed_many(traffic, traffic_keys, str, f"{path}.netTrafficObj", errors)


def _validate_platform_logs(value: Any, errors: list[str]) -> None:
    path = "payload.logInfoReqParams"
    keys = {"logReqSeq", "logReqNote", "dataFileID", "numLogs", "logInfo"}
    _exact_keys(value, keys, path, errors)
    _typed_many(value, {"logReqSeq", "numLogs"}, int, path, errors)
    _typed_many(value, {"logReqNote", "dataFileID"}, str, path, errors)
    if not isinstance(value, dict):
        return
    rows = value.get("logInfo")
    if not isinstance(rows, list):
        errors.append(f"{path}.logInfo must be list")
        return
    if type(value.get("numLogs")) is int and value["numLogs"] != len(rows):
        errors.append(f"{path}.numLogs must equal logInfo length")
    row_keys = {
        "timeStamp", "devHash", "loginAccount", "loginIp", "devIp", "orderID", "l2Code",
        "bkItemID", "logID", "logType", "logLvl", "opCode", "opRslt", "content", "hash", "chainHash",
    }
    integer_fields = {"l2Code", "logType", "logLvl", "opCode", "opRslt"}
    for index, row in enumerate(rows):
        row_path = f"{path}.logInfo[{index}]"
        _exact_keys(row, row_keys, row_path, errors)
        _typed_many(row, integer_fields, int, row_path, errors)
        _typed_many(row, row_keys - integer_fields - {"content"}, str, row_path, errors)
        if isinstance(row, dict) and not isinstance(row.get("content"), dict):
            errors.append(f"{row_path}.content must be object")


def _validate_shared(
    interface_no: int,
    payload: dict[str, Any],
    errors: list[str],
    *,
    order_id: str | None,
) -> None:
    if interface_no in {5, 6, 7, 8}:
        _validate_shared_work_orders(interface_no, payload, errors)
    else:
        _validate_shared_data(interface_no, payload, errors, order_id=order_id)


def validate_business_payload(
    interface_no: int,
    payload: Any,
    *,
    ctx_code: int | None = None,
    order_id: str | None = None,
) -> list[str]:
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["payload must be object"]
    _reject_null(payload, "payload", errors)
    _typed(payload, "timeStamp", str, "payload", errors)
    _typed(payload, "sign", str, "payload", errors)
    if interface_no in {3, 4}:
        _validate_work_order(interface_no, payload, errors)
    elif interface_no in SHARED_INTERFACES:
        _validate_shared(interface_no, payload, errors, order_id=order_id)
    elif interface_no in INTERFACE_ORDER_SUBTYPES:
        _validate_upload(interface_no, payload, errors)
    elif interface_no in INTERFACE_TEST_TYPES:
        _validate_test_data(interface_no, payload, errors)
    elif interface_no in OUTBOUND_DATA_SUBTYPES:
        _validate_statistics(interface_no, payload, errors, ctx_code=ctx_code)
    else:
        errors.append(f"unsupported interface {interface_no}")
    return errors


def validate_password_dictionary(payload: Any) -> list[str]:
    errors: list[str] = []
    _exact_keys(payload, {"pwDictNum", "pwLst"}, "passwordDictionary", errors)
    if not isinstance(payload, dict):
        return errors
    _reject_null(payload, "passwordDictionary", errors)
    _typed(payload, "pwDictNum", int, "passwordDictionary", errors)
    rows = payload.get("pwLst")
    if not isinstance(rows, list) or not rows:
        errors.append("passwordDictionary.pwLst must be non-empty list")
        return errors
    if type(payload.get("pwDictNum")) is int and payload["pwDictNum"] != len(rows):
        errors.append("passwordDictionary.pwDictNum must equal pwLst length")
    expected = {"pwDictID", "pwProto", "pwDTitle", "pwDictType", "pwData"}
    for index, row in enumerate(rows):
        path = f"passwordDictionary.pwLst[{index}]"
        _exact_keys(row, expected, path, errors)
        if not isinstance(row, dict):
            continue
        for field in ("pwDictID", "pwDictType"):
            _typed(row, field, int, path, errors)
        for field in ("pwProto", "pwDTitle", "pwData"):
            _typed(row, field, str, path, errors)
        if isinstance(row.get("pwData"), str):
            try:
                decoded = base64.b64decode(row["pwData"], validate=True)
                decoded.decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                errors.append(f"{path}.pwData must be valid Base64 UTF-8")
            else:
                if not decoded:
                    errors.append(f"{path}.pwData must decode to non-empty content")
        if type(row.get("pwDictID")) is int and not 0 <= row["pwDictID"] <= 65535:
            errors.append(f"{path}.pwDictID out of range")
    return errors
