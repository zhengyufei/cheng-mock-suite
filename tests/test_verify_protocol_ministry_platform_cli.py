from __future__ import annotations

import json
import subprocess
import sys


def _write_record(path):
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "method": "POST",
                "path": "/ministry/receive",
                "body": "{}",
                "meta": {
                    "protocol": {"orderID": "2-301-2026070300000000001", "orderSubType": 301},
                    "validation": {"ok": True, "errors": [], "warnings": []},
                },
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def test_verify_cli_outputs_json_report(tmp_path) -> None:
    record_file = tmp_path / "run" / "requests.jsonl"
    _write_record(record_file)

    result = subprocess.run(
        [
            sys.executable,
            "tools/verify_protocol_ministry_platform.py",
            "--record-file",
            str(record_file),
            "--mode",
            "contract",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["mode"] == "contract"


def test_verify_cli_returns_nonzero_on_contract_failure(tmp_path) -> None:
    record_file = tmp_path / "run" / "requests.jsonl"
    record_file.parent.mkdir(parents=True)
    record_file.write_text(
        json.dumps(
            {
                "method": "POST",
                "path": "/api/v1/platformFileUpload",
                "body": "file",
                "meta": {
                    "protocol": {"orderID": None, "orderSubType": None},
                    "validation": {"ok": True, "errors": [], "warnings": []},
                },
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "tools/verify_protocol_ministry_platform.py",
            "--record-file",
            str(record_file),
            "--mode",
            "contract",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
