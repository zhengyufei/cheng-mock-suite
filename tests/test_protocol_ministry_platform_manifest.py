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
    assert {"301", "308", "104", "105", "201"} <= set(data["receive_from_backend"]["subtypes"])
    assert data["send_to_backend"]["paths"] == ["/api/ministry/receive", "/api/ministry/file"]
    assert {"302", "303", "307", "309", "399"} <= set(data["send_to_backend"]["fixture_cases"])
    assert data["send_to_backend"]["fixture_cases"]["file_103"] == "file_103"
    assert data["send_to_backend"]["default_send_cases"] == [
        "policy_302",
        "prod_vul_workorder_5_request",
    ]
    assert data["verification_modes"]["observe"]["expected_exit_code_when_warnings_only"] == 0
    assert data["verification_modes"]["contract"]["expected_exit_code_when_warnings_only"] == 1
