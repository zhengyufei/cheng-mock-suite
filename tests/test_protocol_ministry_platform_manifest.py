from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from mock_ministry.mocks.protocol_ministry_platform.payloads import (
    _is_safe_archive_file_name,
    validate_business_payload,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "fixtures" / "protocol_ministry_platform" / "manifest.json"


def test_protocol_platform_manifest_lists_feature_interface_coverage() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert data["mock"] == "protocol-ministry-platform"
    assert data["receive_from_backend"]["paths"] == [
        "/ministry/receive",
        "/provinceAPI/provisionOrderMiit",
        "/provinceAPI/deviceManagementMiit",
        "/provinceAPI/businessStatistics",
        "/ministry/file",
        "/provinceAPI/fileMiit",
        "/api/v1/platformFileUpload",
    ]
    assert {"106", "1061", "1062", "1063", "201", "301", "308", "104", "105", "202", "203"} <= set(data["receive_from_backend"]["subtypes"])
    assert data["send_to_backend"]["paths"] == ["/api/ministry/receive", "/api/ministry/file"]
    expected_cases = {
        "5",
        "6",
        "7",
        "8",
        "15",
        "16",
        "17",
        "18",
        "19",
        "20",
        "21",
        "22",
        "24",
        "28",
        "29",
        "30",
        "31",
        "32",
        "33",
        "399",
    }
    assert expected_cases <= set(data["send_to_backend"]["fixture_cases"])
    assert data["send_to_backend"]["fixture_cases"]["file_103"] == "file_103"
    assert data["send_to_backend"]["fixture_cases"]["33"] == "file_103"
    assert set(data["send_to_backend"]["delivery_send_cases"]) == {
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
    }
    assert set(data["send_to_backend"]["regression_send_cases"]) == {
        "policy_302_interface_16",
        "test_data_307_tst_type_1",
        "test_data_307_tst_type_2",
        "test_data_307_tst_type_3",
        "test_data_307_tst_type_4",
        "test_data_307_tst_type_5",
        "test_data_307_tst_type_6",
        "platform_register_301",
        "file_103",
        "unknown_subtype_399",
    }
    assert data["send_to_backend"]["default_send_cases"] == [
        "policy_302",
        "prod_vul_workorder_5_request",
    ]
    assert data["interface_directions"] == {
        "1": "ministry_to_province",
        "2": "province_to_ministry",
        "9": "ministry_to_province",
        "10": "ministry_to_province",
        "13": "ministry_to_province",
        "14": "province_to_ministry",
        "23": "province_to_ministry",
        "25": "province_to_ministry",
        "28": "bidirectional",
        "31": "province_to_ministry",
        "33": "bidirectional",
    }
    assert data["additional_interfaces"]["response_subtype_mapping"] == {
        "31": 41,
        "32": 42,
        "33": 43,
        "34": 44,
    }
    assert data["additional_interfaces"]["province_to_ministry"]["interfaces"] == [4, 11, 12, 26, 27]
    assert data["verification_modes"]["observe"]["expected_exit_code_when_warnings_only"] == 0
    assert data["verification_modes"]["contract"]["expected_exit_code_when_warnings_only"] == 1
    strict_line = data["verification_modes"]["strict_local_crypto"]
    assert strict_line["sm2_sm4"] == "real"
    assert strict_line["verification_nature"] == "local_mock_only"
    assert strict_line["production_ministry_joint_test"] is False


def _interface_6_fixture_payload() -> dict:
    fixture = ROOT / "fixtures" / "receive" / "prod_vul_workorder_6_callback.json"
    return json.loads(fixture.read_text(encoding="utf-8"))["inner"]


def test_interface_6_delivery_fixture_matches_strict_contract() -> None:
    assert validate_business_payload(6, _interface_6_fixture_payload()) == []


def test_interface_6_optional_ticket_info_can_be_omitted() -> None:
    payload = _interface_6_fixture_payload()
    payload["vulTktRspParams"].pop("tktInfo")

    assert validate_business_payload(6, payload) == []


def test_interface_6_rejects_blank_operator_fields() -> None:
    for field in ("srcTktProcer", "srcTktProcerDept"):
        payload = copy.deepcopy(_interface_6_fixture_payload())
        payload["vulTktRspParams"][field] = " "

        errors = validate_business_payload(6, payload)

        assert any(field in error and "blank" in error for error in errors)


def test_interface_6_rejects_invalid_role_and_blank_vulnerability_id() -> None:
    payload = _interface_6_fixture_payload()
    payload["vulTktRspParams"]["srcTktRole"] = 11
    payload["vulIdLst"]["idLst"] = [" "]

    errors = validate_business_payload(6, payload)

    assert any("srcTktRole" in error for error in errors)
    assert any("idLst[0]" in error for error in errors)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("srcTktProcer", "x" * 256),
        ("srcTktProcerDept", "x" * 256),
        ("tktInfo", "x" * 2049),
    ],
)
def test_interface_6_rejects_overlong_ticket_text(field, value) -> None:
    payload = _interface_6_fixture_payload()
    payload["vulTktRspParams"][field] = value

    errors = validate_business_payload(6, payload)

    assert any(field in error for error in errors)


def test_interface_6_rejects_more_than_99_vulnerability_ids() -> None:
    payload = _interface_6_fixture_payload()
    payload["vulIdLst"] = {
        "idLst": [f"MVM-{index:03d}" for index in range(100)],
        "vulNum": 100,
    }

    errors = validate_business_payload(6, payload)

    assert any("vulNum" in error and "0 to 99" in error for error in errors)


def test_mock_rejects_nonportable_archive_names() -> None:
    unsafe_names = [
        "CON.json",
        "payload.json.",
        "payload.json ",
        "a<b.json",
        "a>b.json",
        "a|b.json",
        "a?b.json",
        "a*b.json",
        'a"b.json',
    ]

    assert not any(_is_safe_archive_file_name(name) for name in unsafe_names)
