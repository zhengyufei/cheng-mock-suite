from __future__ import annotations

import json

from mock_ministry.cases import build_plain_envelope, list_cases, load_case


REQUIRED_CASES = {
    "policy_302",
    "test_data_307_tst_type_1",
    "device_cmd_309",
    "platform_event_303",
    "unknown_subtype_399",
}


def test_list_cases_includes_required_cases() -> None:
    assert REQUIRED_CASES <= set(list_cases())


def test_load_case_and_build_plain_envelope() -> None:
    case = load_case("policy_302")
    envelope = build_plain_envelope(case)

    assert envelope["orderID"] == "2-302-2026070300000000001"
    assert envelope["orgCode"] == "MIIT"
    assert envelope["ispCode"] == "CMCC"
    inner = json.loads(envelope["reqMsgCnt"])
    assert inner["dataType"] == 2
    assert inner["dataSubType"] == 302
