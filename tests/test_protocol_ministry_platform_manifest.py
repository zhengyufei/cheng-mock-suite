from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "fixtures" / "protocol_ministry_platform" / "manifest.json"


def test_protocol_platform_manifest_lists_feature_interface_coverage() -> None:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert data["mock"] == "protocol-ministry-platform"
    assert data["receive_from_backend"]["paths"] == [
        "/ministry/receive",
        "/ministry/file",
        "/api/v1/platformFileUpload",
    ]
    assert {"301", "308", "104", "105", "201", "202", "203"} <= set(data["receive_from_backend"]["subtypes"])
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
        "23",
        "24",
        "25",
        "26",
        "27",
        "28",
        "29",
        "30",
        "31",
        "32",
        "33",
        "307",
        "399",
    }
    assert expected_cases <= set(data["send_to_backend"]["fixture_cases"])
    assert set(data["send_to_backend"]["fixture_cases"]["307"].values()) == {
        "test_data_307_tst_type_1",
        "test_data_307_tst_type_2",
        "test_data_307_tst_type_3",
        "test_data_307_tst_type_4",
        "test_data_307_tst_type_5",
        "test_data_307_tst_type_6",
    }
    assert data["send_to_backend"]["fixture_cases"]["file_103"] == "file_103"
    assert data["send_to_backend"]["fixture_cases"]["33"] == "file_103"
    assert set(data["send_to_backend"]["delivery_send_cases"]) == {
        "prod_vul_workorder_5_request",
        "prod_vul_workorder_6_callback",
        "warning_task_7_request",
        "warning_task_8_callback",
        "policy_302",
        "test_data_307_tst_type_1",
        "test_data_307_tst_type_2",
        "test_data_307_tst_type_3",
        "test_data_307_tst_type_4",
        "test_data_307_tst_type_5",
        "test_data_307_tst_type_6",
        "device_cmd_309",
        "platform_event_303",
        "platform_status_304",
        "platform_log_305",
        "platform_file_306",
    }
    assert set(data["send_to_backend"]["regression_send_cases"]) == {
        "policy_302_interface_16",
        "device_register_308",
        "command_stat_201",
        "tas_stat_202",
        "sys_vul_stat_203",
        "platform_register_301",
        "file_103",
        "unknown_subtype_399",
    }
    assert data["send_to_backend"]["default_send_cases"] == [
        "policy_302",
        "prod_vul_workorder_5_request",
    ]
    assert data["verification_modes"]["observe"]["expected_exit_code_when_warnings_only"] == 0
    assert data["verification_modes"]["contract"]["expected_exit_code_when_warnings_only"] == 1
