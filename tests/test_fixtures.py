from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "receive"
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


def test_required_fixture_files_exist() -> None:
    names = {path.stem for path in FIXTURE_DIR.glob("*.json")}
    assert REQUIRED_CASES <= names


def test_fixture_minimum_shape() -> None:
    for name in REQUIRED_CASES:
        data = json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))
        assert data["name"] == name
        assert data["outer"]["orderID"]
        assert "dataType" in data["inner"] or "orderType" in data["inner"]


def test_platform_event_fixture_uses_contract_params_object() -> None:
    data = json.loads((FIXTURE_DIR / "platform_event_303.json").read_text(encoding="utf-8"))
    params = data["inner"].get("eventInfoReqParams")

    assert isinstance(params, dict)
    assert params["eventID"]
    assert params["eventType"] == 1001
    assert params["eventSource"]
    assert params["eventDescription"]
    assert params["devHash"]
