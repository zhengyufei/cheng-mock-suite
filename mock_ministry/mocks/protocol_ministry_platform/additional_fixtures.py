"""Deterministic V2.2 fixtures for interfaces 3/4/11/12/17-19/21-22/26/27."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from .contracts import (
    ADDITIONAL_INTERFACE_DIRECTIONS,
    FILE_INFO_KEYS,
    FILE_REQUIRED_CTX_CODES,
    INTERFACE_ORDER_SUBTYPES,
    INTERFACE_TEST_TYPES,
    OUTBOUND_DATA_SUBTYPES,
    PASSWORD_DICTIONARY_SVC_TYPE,
    SYSTEM_VULNERABILITY_SVC_TYPE,
    TEST_DATA_SUBTYPE,
    TEST_DATA_SVC_TYPES,
    WORK_ORDER_PROC_METHODS,
    WORK_ORDER_RESPONSE_SUBTYPES,
    WORK_ORDER_STATUS_SLOTS,
    WORK_ORDER_TARGET_STATUSES,
)

_SEQUENCE_RE = re.compile(r"^\d{19}$")
_FIXTURE_ROOT = Path(__file__).resolve().parents[3] / "fixtures" / "additional_ministry"
_SIGN = "a" * 64


def walk_values(value: Any) -> Iterator[Any]:
    if isinstance(value, dict):
        for child in value.values():
            yield from walk_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_values(child)
    else:
        yield value


def _sequence(value: str) -> str:
    if not _SEQUENCE_RE.fullmatch(value):
        raise ValueError("sequence must be exactly 19 digits")
    return value


def _file_info(*, name: str, object_id: str, svc_type: int) -> dict[str, Any]:
    result = {
        "name": name,
        "dataType": "json",
        "objectID": object_id,
        "svcType": svc_type,
        "reserved": "",
    }
    assert set(result) == FILE_INFO_KEYS
    return result


def _data(file_info: list[dict[str, Any]]) -> dict[str, Any]:
    return {"numFiles": len(file_info), "numTgzs": 1, "fileInfoLst": file_info}


def _outer(order_id: str, inner: dict[str, Any], interface_no: int, *, ctx_code: int = 1) -> dict[str, Any]:
    return {
        "interface_no": interface_no,
        "direction": ADDITIONAL_INTERFACE_DIRECTIONS[interface_no],
        "orderID": order_id,
        "orgCode": "150000",
        "ispCode": "CM",
        "ctxCode": ctx_code,
        "inner": inner,
    }


def build_work_order_request(request_subtype: int, sequence: str) -> dict[str, Any]:
    _sequence(sequence)
    if request_subtype not in WORK_ORDER_RESPONSE_SUBTYPES:
        raise ValueError(f"unsupported interface 3 subtype: {request_subtype}")
    inner = {
        "orderType": 1,
        "orderSubType": request_subtype,
        "timeStamp": "1752500000",
        "sign": _SIGN,
        "procTime": "20260714000000-20260715000000",
        "timePerd": {"unit": 1, "perd": 1},
        "vulInfoRange": "KHZ1bEtleXMudnVsSUQgPSAnTVZNLTAwMScp",
        "vulInfoTktReqParams": {
            "vptModID": "acceptance-vpt-model",
            "srcTktRole": 6,
            "dstTktRole": 6,
            "dstVulInfoStat": [
                status if status in WORK_ORDER_TARGET_STATUSES[request_subtype] else -1
                for status in WORK_ORDER_STATUS_SLOTS
            ],
            "procMethod": WORK_ORDER_PROC_METHODS[request_subtype],
            "tktPriority": 3,
            "tktVulNum": 1,
            "tktAstNum": 1,
            "tktSLA": "30,70",
            "tktInfo": "additional work order",
        },
    }
    return _outer(f"1-{request_subtype}-{sequence}", inner, 3)


def build_work_order_response(request_subtype: int, sequence: str) -> dict[str, Any]:
    _sequence(sequence)
    response_subtype = WORK_ORDER_RESPONSE_SUBTYPES.get(request_subtype)
    if response_subtype is None:
        raise ValueError(f"unsupported interface 3 subtype: {request_subtype}")
    inner = {
        "orderType": 1,
        "orderSubType": response_subtype,
        "timeStamp": "1752500001",
        "sign": _SIGN,
        "vulInfoLst": {
            "vulNum": 0,
            "engLst": {
                "engNum": 1,
                "engDevs": [{"engHash": "ACCEPTANCE-ENG-001", "engType": 32}],
            },
            "comVulLst": [],
        },
        "vulInfoTktRspParams": {
            "srcTktRole": 4,
            "srcTktProcer": "acceptance",
            "srcTktProcerDept": "NA",
            "dstTktRole": 4,
            "transID": "1",
            "prcVulNum": 0,
            "toPrcAstNum": 0,
            "prcAstNum": 0,
            "exRsnLst": [-1, -1, -1, -1, -1, -1, -1, -1],
            "exRsnNumLst": [0, 0, 0, 0, 0, 0, 0, 0],
            "dstVulInfoStat": [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
            "sucVulInfoNum": [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1],
            "tktResult": 0,
            "tktInfo": "completed",
            "logNum": 0,
        },
    }
    return _outer(f"1-{response_subtype}-{sequence}", inner, 4)


def _upload_fixture(interface_no: int, sequence: str, *, include_poc_file: bool) -> dict[str, Any]:
    subtype = INTERFACE_ORDER_SUBTYPES[interface_no]
    info = _file_info(
        name=f"2-{subtype}-{sequence}_payload.json",
        object_id=f"2-{subtype}-{sequence}",
        svc_type=6 if interface_no == 11 else PASSWORD_DICTIONARY_SVC_TYPE,
    )
    task = {
        "tskPriority": 1,
        "transID": sequence,
        "rng": 2,
        "seq": 1,
        "tskScn": 0,
        "tskInfo": "additional upload task",
    }
    inner: dict[str, Any] = {
        "orderType": 2,
        "orderSubType": subtype,
        "timeStamp": "1752500000",
        "sign": _SIGN,
        "tskReqParams": task,
    }
    if interface_no == 12 or include_poc_file:
        inner["data"] = _data([info])
    if interface_no == 11:
        task["tskVulNum"] = 1
        inner["vulLst"] = {
            "keyLst": [
                {
                    "vulID": f"MVM-2026-{sequence}",
                    "lclID": f"LOCAL-{sequence}",
                    "bslDate": "2026-07-14",
                    "orgVulID": "CVE-2026-0001",
                    "vulName": "additional acceptance vulnerability",
                    "numOrg": 1,
                    "pubOrgInfo": [
                        {
                            "pubOrgID": "CVE",
                            "pubVulID": "CVE-2026-0001",
                            "pubDate": "2026-07-14",
                            "pubVulVal": 5.0,
                        }
                    ],
                    "vulStat": 1,
                    "bslVulVal": 5.0,
                    "vulType": 24,
                    "vulLevel": 3,
                    "assetType": "cpe:2.3:a:acceptance:component:1.0:*:*:*:*:*:*:*",
                    "numAfftCmpt": 1,
                    "afftCmptInfo": [
                        {
                            "cmptVendor": "acceptance",
                            "cmptClass": 2,
                            "cmptName": "component",
                            "cmptVer": "1.0",
                        }
                    ],
                    "vulDesc": "acceptance vulnerability description",
                    "vulPocDesc": "acceptance detection method",
                    "expPath": 1,
                    "remed": "apply the acceptance fix",
                    "fixLnk": "https://example.invalid/fix",
                    "srcMethod": 1080,
                    "rsvdDesc": "",
                }
            ],
            "vulNum": 1,
        }
    fixture = _outer(f"2-{subtype}-{sequence}", inner, interface_no)
    fixture["events"] = [
        *([f"upload_file:{info['svcType']}"] if "data" in inner else []),
        f"send_business:{subtype}",
    ]
    return fixture


def _test_data_fixture(
    interface_no: int,
    sequence: str,
    *,
    include_log_support_file: bool = False,
) -> dict[str, Any]:
    tst_type = INTERFACE_TEST_TYPES[interface_no]
    params: dict[str, Any] = {"logType": 1, "orderIDLst": f"2-104-{sequence}", "tstType": tst_type}
    if tst_type != 1:
        params["opCode"] = 1
    inner: dict[str, Any] = {
        "dataType": 2,
        "dataSubType": TEST_DATA_SUBTYPE,
        "sign": _SIGN,
        "tstReqParams": params,
        "timeStamp": "1752500000",
    }
    if tst_type in {3, 5, 6}:
        inner["procTime"] = "20260714000000-20260715000000"
    if tst_type in {5, 6}:
        inner["vulInfoRange"] = "KHZ1bEtleXMudnVsTmFtZSBsaWtlICclQ1ZFJScp"
    if tst_type in {1, 2}:
        svc_type = TEST_DATA_SVC_TYPES[tst_type][0]
        inner["data"] = _data(
            [_file_info(name=f"test-data-{tst_type}.json", object_id=f"2-307-{sequence}", svc_type=svc_type)]
        )
    svc_types = TEST_DATA_SVC_TYPES[tst_type]
    if include_log_support_file:
        raise ValueError("optional log support file is not part of the strict protocol")
    fixture = _outer(f"2-{TEST_DATA_SUBTYPE}-{sequence}", inner, interface_no)
    fixture["expected_ack"] = {
        "dataType": 2,
        "dataSubType": TEST_DATA_SUBTYPE,
        "tstResParams": {"tstProcRslt": 0},
    }
    fixture["expected_svc_types"] = svc_types
    fixture["events"] = ["business_ack", *(f"upload_file:{svc}" for svc in svc_types)]
    return fixture


def _statistics_fixture(interface_no: int, sequence: str, ctx_code: int) -> dict[str, Any]:
    subtype = OUTBOUND_DATA_SUBTYPES[interface_no]
    stats: dict[str, Any] = {
        "numVulInfo": 1,
        "astNum": 1,
        "vulNum": 1,
        "pwdNum": 0,
        "prcAstNum": 1,
        "exRsnLst": [-1, -1, -1, -1, -1, -1, -1, 99],
        "exRsnNumLst": [0, 0, 0, 0, 0, 0, 0, 1],
    }
    if interface_no == 26:
        stats["tasStaObj"] = {"taskType": "108:1, 103:1", "logType": "108:1, 103:1"}
    inner: dict[str, Any] = {
        "dataType": 1,
        "dataSubType": subtype,
        "timeStamp": "1752500000",
        "sign": _SIGN,
        "procTime": "20260714000000-20260715000000",
        "staReqParams": stats,
    }
    requires_file = interface_no == 27 and ctx_code in FILE_REQUIRED_CTX_CODES
    if requires_file:
        inner["data"] = _data(
            [
                _file_info(
                    name=f"1-203-{sequence}_system-vulnerabilities.json",
                    object_id=f"ledger-log-{sequence}",
                    svc_type=SYSTEM_VULNERABILITY_SVC_TYPE,
                )
            ]
        )
    fixture = _outer(f"1-{subtype}-{sequence}", inner, interface_no, ctx_code=ctx_code)
    fixture["requires_file"] = requires_file
    fixture["events"] = (
        ["interface11", "upload_file:12", "send_business:203"] if requires_file else [f"send_business:{subtype}"]
    )
    return fixture


def build_additional_fixture(
    interface_no: int,
    sequence: str,
    *,
    ctx_code: int = 0,
    include_log_support_file: bool = False,
    include_poc_file: bool = True,
) -> dict[str, Any]:
    _sequence(sequence)
    if interface_no in INTERFACE_ORDER_SUBTYPES:
        return _upload_fixture(interface_no, sequence, include_poc_file=include_poc_file)
    if interface_no in INTERFACE_TEST_TYPES:
        return _test_data_fixture(
            interface_no,
            sequence,
            include_log_support_file=include_log_support_file,
        )
    if interface_no in OUTBOUND_DATA_SUBTYPES:
        return _statistics_fixture(interface_no, sequence, ctx_code)
    raise ValueError(f"unsupported additional interface: {interface_no}")


def load_password_dictionary_fixture() -> dict[str, Any]:
    return json.loads((_FIXTURE_ROOT / "password_dictionary_105.json").read_text(encoding="utf-8"))
