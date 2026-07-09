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
    "policy_302_interface_16",
    "test_data_307_tst_type_2",
    "test_data_307_tst_type_3",
    "test_data_307_tst_type_4",
    "test_data_307_tst_type_5",
    "test_data_307_tst_type_6",
    "device_register_308",
    "device_cmd_309",
    "command_stat_201",
    "tas_stat_202",
    "sys_vul_stat_203",
    "platform_register_301",
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


def test_refactor_regression_fixtures_cover_shared_route_family() -> None:
    """统一入口重构影响到的路由族都要有本地 mock 输入。"""
    route_by_case = {}
    for name in REQUIRED_CASES:
        data = json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))
        inner = data["inner"]
        route = (
            inner.get("orderType", inner.get("dataType")),
            inner.get("orderSubType", inner.get("dataSubType")),
        )
        route_by_case[name] = route

    assert route_by_case["command_stat_201"] == (1, 201)
    assert route_by_case["tas_stat_202"] == (1, 202)
    assert route_by_case["sys_vul_stat_203"] == (1, 203)
    assert route_by_case["platform_register_301"] == (2, 301)
    assert route_by_case["policy_302_interface_16"] == (2, 302)
    assert route_by_case["device_register_308"] == (2, 308)
    assert route_by_case["device_cmd_309"] == (2, 309)


def test_test_data_307_fixtures_cover_tst_type_1_to_6() -> None:
    """接口17-22共用 dataSubType=307，通过 tstType 区分六类测试数据。"""
    tst_types = set()
    for name in REQUIRED_CASES:
        if not name.startswith("test_data_307_tst_type_"):
            continue
        data = json.loads((FIXTURE_DIR / f"{name}.json").read_text(encoding="utf-8"))
        inner = data["inner"]
        assert inner["dataType"] == 2
        assert inner["dataSubType"] == 307
        tst_types.add(inner["tstReqParams"]["tstType"])

    assert tst_types == {1, 2, 3, 4, 5, 6}


def test_platform_event_fixture_uses_contract_params_object() -> None:
    data = json.loads((FIXTURE_DIR / "platform_event_303.json").read_text(encoding="utf-8"))
    params = data["inner"].get("eventInfoReqParams")

    assert isinstance(params, dict)
    assert params["eventID"]
    assert params["eventType"] == 1001
    assert params["eventSource"]
    assert params["eventDescription"]
    assert params["devHash"]
