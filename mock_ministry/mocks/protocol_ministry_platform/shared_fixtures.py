"""Exact protocol fixtures shared with the original interface feature set."""

from __future__ import annotations

import re
from typing import Any

_SEQUENCE_RE = re.compile(r"^\d{19}$")
_SIGN = "a" * 64


def _file_data(*svc_types: int) -> dict[str, Any]:
    return {
        "numFiles": len(svc_types),
        "numTgzs": 1,
        "fileInfoLst": [
            {
                "name": f"protocol-{svc_type}.json",
                "dataType": "json",
                "objectID": "",
                "svcType": svc_type,
                "reserved": "",
            }
            for svc_type in svc_types
        ],
    }


def _system_vulnerability(sequence: str) -> dict[str, Any]:
    return {
        "vulInfoID": f"ACCEPT-SYS-{sequence}",
        "srcMethod": 1080,
        "logIDLst": f"LOG-{sequence}",
        "vulInfoStat": 9,
        "lvRsn": 101,
        "assetID": f"ASSET-{sequence}",
        "assetLclId": f"LCL-{sequence}",
        "assetName": "protocol asset",
        "vulAddrType": 1,
        "vulNetAddr": "https://10.8.100.8:443",
        "vulTransProto": "TCP",
        "vulPort": 443,
        "vulSvc": "nginx",
        "transferTime": "1752500000",
        "isAccess": 0,
        "unitType": "0101",
        "vulInstCpe": "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*",
        "vulInstVendor": "nginx",
        "vulInstClass": 2,
        "vulInstName": "nginx",
        "vulInstVer": "1.24",
        "vulInstRunPath": "/usr/sbin/nginx",
        "vulInstFilePath": "/usr/sbin/nginx",
        "vulInstFileLoc": "/usr/sbin",
        "vulInstOsType": "linux",
        "vulInstOsNameVer": "CentOS 7",
        "vulInstOsVendor": "CentOS",
        "vulInstOsCpe": "cpe:2.3:o:centos:centos:7:*:*:*:*:*:*:*",
        "vulInstDevNameVer": "Dell R740",
        "vulInstDevVendor": "Dell EMC",
        "vulInstDevCpe": "cpe:2.3:h:dell:poweredge_r740:*:*:*:*:*:*:*:*",
        "assetOwnerinfo": "acceptance,10086",
        "vulPriorVal": 7.5,
        "vulPriorLvl": 4,
        "vulPriorMID": "ACCEPT-MODEL-01",
    }


def _product_vulnerability(sequence: str) -> dict[str, Any]:
    return {
        "vulName": "protocol product vulnerability",
        "vulID": f"MVM-{sequence}",
        "lclID": "-1",
        "bslDate": "2026-07-18",
        "orgVulID": "CVE-2026-0001",
        "numOrg": 1,
        "pubOrgInfo": [{"pubOrgID": "A02", "pubVulID": "CVE-2026-0001", "pubDate": "2026-07-18", "pubVulVal": 7.5}],
        "vulStat": 1,
        "bslVulVal": 7.5,
        "vulType": 24,
        "vulLevel": 4,
        "assetType": "cpe:2.3:a:example:server:1.0:*:*:*:*:*:*:*",
        "numAfftCmpt": 1,
        "afftCmptInfo": [{"cmptVendor": "example", "cmptClass": 2, "cmptName": "server", "cmptVer": "1.0"}],
        "vulDesc": "protocol fixture",
        "vulPocDesc": "protocol fixture poc",
        "expPath": 1,
        "remed": "upgrade",
        "fixLnk": "https://example.invalid/fix",
        "srcMethod": 1024,
        "rsvdDesc": "",
    }


def _task_request(sequence: str, **extra: Any) -> dict[str, Any]:
    return {
        "seq": 1,
        "tskScn": 1,
        "rng": 1,
        "tskPriority": 1,
        "tskInfo": "protocol task",
        "transID": sequence,
        **extra,
    }


def _task_response() -> dict[str, Any]:
    return {
        "tskProcIndication": 100,
        "prcVulNum": -1,
        "prcPwNum": -1,
        "toPrcAstNum": 1,
        "prcAstNum": 1,
        "exRsnLst": [-1] * 8,
        "exRsnNumLst": [-1] * 8,
        "logNum": -1,
    }


def _base(route_type: int, subtype: int) -> dict[str, Any]:
    prefix = "order" if subtype in {11, 12, 21, 22, 101, 102, 103, 106, 1061, 1062, 1063} else "data"
    return {
        f"{prefix}Type": route_type,
        f"{prefix}SubType": subtype,
        "timeStamp": "1752500000",
        "sign": _SIGN,
    }


def build_shared_fixture(interface_no: int, sequence: str) -> dict[str, Any]:
    if not _SEQUENCE_RE.fullmatch(sequence):
        raise ValueError("sequence must be exactly 19 digits")
    builders = {
        5: _interface_5,
        6: _interface_6,
        7: _interface_7,
        8: _interface_8,
        9: _interface_9,
        10: _interface_10,
        13: _interface_13,
        14: _interface_14,
        15: _interface_15,
        23: _interface_23,
        24: _interface_24,
        25: _interface_25,
        28: _interface_28,
        29: _interface_29,
        30: _interface_30,
        31: _interface_31,
        32: _interface_32,
    }
    try:
        order_id, inner = builders[interface_no](sequence)
    except KeyError as exc:
        raise ValueError(f"unsupported shared interface: {interface_no}") from exc
    return {
        "interface_no": interface_no,
        "orderID": order_id,
        "orgCode": "150000",
        "ispCode": "CM",
        "ctxCode": 0 if interface_no in {15, 24, 28} else 1,
        "inner": inner,
    }


def _interface_5(sequence: str):
    inner = {
        **_base(1, 11),
        "procTime": "20260714000000-20260715000000",
        "vulRange": "dnVsLmlkIGxpa2UgJyVNVMl",
        "vulTktReqParams": {
            "procMethod": 107,
            "srcTktRole": 0,
            "dstTktRole": 1,
            "dstVulStat": 1,
            "tktPriority": 1,
            "tktSLA": 100,
            "tktVulNum": 1,
            "tktInfo": "protocol work order",
        },
        "data": _file_data(1),
    }
    return f"1-11-{sequence}", inner


def _interface_6(sequence: str):
    inner = {
        **_base(1, 21),
        "vulTktRspParams": {
            "srcTktRole": 1,
            "srcTktProcer": "acceptance",
            "srcTktProcerDept": "NA",
            "dstTktRole": 6,
            "prcVulNum": 1,
            "dstVulStat": [-1, -1, -1, -1, -1, 5, 6, 7, 8, 9, -1],
            "sucVulNum": [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "tktResult": 1,
            "tktInfo": "completed",
        },
        "vulIdLst": {"idLst": [f"MVM-{sequence}"], "vulNum": 1},
        "data": _file_data(3),
    }
    return f"1-21-{sequence}", inner


def _interface_7(sequence: str):
    inner = {
        **_base(2, 101),
        "vulInfoRange": "KHZ1bEtleXMudnVsTmFtZSBsaWtlICclQ1ZFJScp",
        "procTime": "20260714000000-20260715000000",
        "tskReqParams": {
            "procMethod": 108,
            "seq": 1,
            "tskScn": 2,
            "rng": 1,
            "tskPriority": 1,
            "tskInfo": "warning task",
            "astUnitNum": -1,
            "transID": sequence,
        },
        "timePerd": {"unit": 1, "perd": 1},
    }
    return f"2-101-{sequence}", inner


def _interface_8(sequence: str):
    inner = {
        **_base(2, 101),
        "vulInfoLst": {
            "vulNum": 1,
            "comVulLst": [
                {"vulID": f"MVM-{sequence}", "assetNum": 1, "instVulLst": [_system_vulnerability(sequence)]}
            ],
        },
        "tskRspParams": {
            "tskProcIndication": 100,
            "prcVulNum": -1,
            "prcPwNum": -1,
            "toPrcAstNum": 1,
            "prcAstNum": 1,
            "exRsnLst": [-1, -1, -1, -1, -1, -1, -1, 99],
            "exRsnNumLst": [0, 0, 0, 0, 0, 0, 0, 1],
            "logNum": 1,
        },
        "data": _file_data(12),
    }
    return f"2-101-{sequence}", inner


def _interface_9(sequence: str):
    inner = {
        **_base(2, 102),
        "tskReqParams": _task_request(sequence),
        "vulLst": {"keyLst": [_product_vulnerability(sequence)], "vulNum": 1},
        "data": _file_data(6),
    }
    return f"2-102-{sequence}", inner


def _interface_10(sequence: str):
    inner = {
        **_base(2, 103),
        "tskReqParams": _task_request(sequence, tskScn=0),
        "data": _file_data(8),
    }
    return f"2-103-{sequence}", inner


def _interface_13(sequence: str):
    inner = {
        **_base(2, 1061),
        "procTime": "20260717000000-20260718000000",
        "vulInfoRange": "KHZ1bEtleXMudnVsTmFtZSBsaWtlICclQ1ZFJScp",
        "tskReqParams": _task_request(
            sequence,
            procMethod=1080,
            astUnitNum=1,
            tskVulNum=1,
            tskAstNum=1,
        ),
        "engLst": {"engNum": 1, "engDevs": [{"engHash": "a" * 32, "engType": 1}]},
        "timePerd": {"unit": 1, "perd": 1},
    }
    return f"2-1061-{sequence}", inner


def _interface_14(sequence: str):
    inner = {
        **_base(2, 1061),
        "vulInfoLst": [
            {
                "vulNum": 0,
                "engLst": {
                    "engNum": 1,
                    "engDevs": [{"engHash": "a" * 32, "engType": 1}],
                },
                "comVulLst": [],
            }
        ],
        "tskRspParams": _task_response(),
    }
    return f"2-1061-{sequence}", inner


def _interface_23(sequence: str):
    engine = {"engHash": "a" * 32, "engType": 1}
    inner = {
        **_base(2, 308),
        "engLst": {"engNum": 1, "engDevs": [engine]},
        "engRegParams": {
            "engNum": 1,
            "engRegInfo": [{
                "vendor": "protocol vendor",
                "engName": "protocol engine",
                "engVer": "1.0",
                "devIp": "10.8.100.7",
                "rngIp": "10.8.100.0/24",
                "plugInsVer": "1.0",
                "timeStamp": "1752500000",
                "engVulNum": 1,
                "plugIns": 1,
                "pocs": 1,
                "exps": 1,
                "reqAct": 0,
                "status": 0,
                "engDev": engine,
            }],
        },
    }
    return f"2-308-{sequence}", inner


def _interface_25(sequence: str):
    inner = {
        **_base(1, 201),
        "procTime": "20260717000000-20260718000000",
        "staReqParams": {
            "workOrderDataObj": {"localTotal": "1-0:1"},
            "numVulInfo": -1,
            "astNum": -1,
            "vulNum": -1,
            "pwdNum": -1,
            "prcAstNum": -1,
            "exRsnLst": [-1] * 8,
            "exRsnNumLst": [0] * 8,
        },
    }
    return f"1-201-{sequence}", inner


def _interface_28(sequence: str):
    inner = {
        **_base(2, 301),
        "registerReqParams": {"devHash": "a" * 32, "devIp": "10.8.100.7"},
    }
    return f"2-301-{sequence}", inner


def _interface_15(sequence: str):
    inner = {
        **_base(2, 302),
        "polyReqParams": {
            "reptPerd": 48,
            "sycPerd": 48,
            "devHash": "3627950af9a7fd40526676dd92",
            "sycNum": 1,
            "decIp": "10.65.128.150",
            "reptNum": 1,
            "perdType": 0,
        },
    }
    return f"2-302-{sequence}", inner


def _interface_24(sequence: str):
    inner = {
        **_base(2, 309),
        "registerReqParams": {
            "devHash": "a" * 32,
            "devIp": "10.8.100.7",
            "reqAct": 0,
        },
    }
    return f"2-309-{sequence}", inner


def _interface_29(sequence: str):
    inner = {
        **_base(2, 303),
        "eventInfoReqParams": {
            "eventId": 2001,
            "devHash": "a" * 32,
            "eventSource": "platform",
            "eventDescription": "certificate expired",
            "eventArgs": "protocol event",
        },
    }
    return f"2-303-{sequence}", inner


def _interface_30(sequence: str):
    inner = {
        **_base(2, 304),
        "devInfoReqParams": {
            "devInfoObj": {
                "product": "TVM",
                "devModel": "R740",
                "installTime": "20260714000000",
                "factoryVersion": "1.0",
                "devHash": "a" * 32,
                "devName": "acceptance-device",
                "updateTime": "20260714000000",
                "curVersion": "2.0",
                "isVirtual": 0,
                "versionType": "release",
                "loginUrl": "https://10.8.100.7",
            },
            "monitDataObj": {
                "resourceLoadObj": {
                    "cpuInfo": "10%",
                    "memInfo": "20%",
                    "otherInfo": "ok",
                    "cfInfo": "ok",
                    "flowInfo": "100Mbps",
                    "diskInfo": "30%",
                },
                "devStatus": 1,
                "devHash": "a" * 32,
                "devType": "security-device",
            },
            "devHash": "a" * 32,
            "devType": 1,
            "token": "acceptance-token",
            "netTrafficObj": {
                "obps": "10bits",
                "obytes": "100",
                "procTime": "20260714000000-20260715000000",
                "ipps": "5bits",
                "name": "eth0",
                "ibps": "20bits",
                "ipackets": "200",
                "opps": "4bits",
                "opackets": "180",
                "ibytes": "2000",
            },
            "devIp": "10.8.100.7",
        },
    }
    return f"2-304-{sequence}", inner


def _interface_31(sequence: str):
    inner = {
        **_base(2, 305),
        "procTime": "20260714000000-20260715000000",
        "logInfoReqParams": {
            "logReqSeq": 1,
            "logReqNote": "protocol log upload",
            "numLogs": 1,
            "logInfo": [
                {
                    "timeStamp": "1752500000",
                    "devHash": "a" * 32,
                    "loginAccount": "acceptance",
                    "loginIp": "10.8.100.1",
                    "devIp": "10.8.100.7",
                    "orderID": f"2-305-{sequence}",
                    "l2Code": 0,
                    "bkItemID": "BK-1",
                    "logID": f"LOG-{sequence}",
                    "logType": 1010,
                    "logLvl": 1,
                    "opCode": 1,
                    "opRslt": 1,
                    "content": '{"business":"retained"}',
                    "hash": "b" * 64,
                    "chainHash": "c" * 64,
                }
            ],
        },
    }
    return f"2-305-{sequence}", inner


def _interface_32(sequence: str):
    inner = {**_base(2, 306), "data": _file_data(13)}
    inner["data"]["fileInfoLst"][0]["objectID"] = f"2-306-{sequence}"
    return f"2-306-{sequence}", inner
