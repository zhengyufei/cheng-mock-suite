import json
from pathlib import Path

from mock_ministry.cases import load_case


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "fixtures" / "semantic_compare_cases.json"


def test_semantic_compare_manifest_lists_existing_receive_cases():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["cases"] == [
        "policy_302",
        "test_data_307_tst_type_1",
        "device_cmd_309",
        "platform_event_303",
        "unknown_subtype_399",
    ]
    for case_id in manifest["cases"]:
        assert load_case(case_id)["name"] == case_id


def test_semantic_compare_manifest_defines_feature_contract_expectations():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert set(manifest["expected_fix_cases"]) == set(manifest["cases"])
    assert manifest["expected_feature_status"] == {
        "policy_302": 0,
        "test_data_307_tst_type_1": 0,
        "device_cmd_309": 0,
        "platform_event_303": 0,
        "unknown_subtype_399": 1,
    }
