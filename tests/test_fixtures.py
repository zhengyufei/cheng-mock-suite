from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "receive"
REQUIRED_CASES = {
    "policy_302",
    "test_data_307_tst_type_1",
    "device_cmd_309",
    "platform_event_303",
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
