from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from mock_ministry.cases import build_plain_envelope, load_case
from mock_ministry.recorder import FileRecorder

from .assertions import evaluate_records
from .evidence import load_records
from .server import create_server


def _url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _post_json(base_url: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        response = requests.post(
            _url(base_url, path),
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except requests.RequestException as exc:
        return {"path": path, "status": 0, "body": f"request failed: {exc}"}

    return {"path": path, "status": response.status_code, "body": response.text}


def _backend_report(calls: list[dict[str, Any]]) -> dict[str, Any]:
    failures = [
        f"{call['path']} returned HTTP {call['status']}"
        for call in calls
        if int(call.get("status", 0)) < 200 or int(call.get("status", 0)) >= 300
    ]
    return {"ok": not failures, "failures": failures, "total": len(calls)}


def _evidence_report(record_file: Path, mode: str, should_have_evidence: bool) -> dict[str, Any]:
    if not should_have_evidence:
        return {
            "mode": mode,
            "ok": True,
            "skipped": True,
            "reason": "未触发后端 outbound，mock evidence 检查跳过",
            "summary": {"total": 0, "paths": {}, "subtypes": {}, "errors": 0, "warnings": 0},
            "failures": [],
            "warnings": [],
        }

    records = load_records(record_file) if record_file.is_file() else []
    report = evaluate_records(records, mode=mode).to_dict()
    report["skipped"] = False
    return report


def run_refactor_check(
    *,
    backend_base_url: str,
    record_dir: str | Path,
    mode: str,
    send_cases: list[str],
    outbound_paths: list[str],
    mock_host: str = "127.0.0.1",
    mock_port: int = 18080,
) -> dict[str, Any]:
    recorder = FileRecorder(base_dir=record_dir)
    recorder.path.touch(exist_ok=True)
    server = create_server(host=mock_host, port=mock_port, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    backend_calls: list[dict[str, Any]] = []
    try:
        for case_name in send_cases:
            payload = build_plain_envelope(load_case(case_name))
            result = _post_json(backend_base_url, "/api/ministry/receive", payload)
            result["case"] = case_name
            backend_calls.append(result)

        for path in outbound_paths:
            result = _post_json(backend_base_url, path, {})
            result["case"] = None
            backend_calls.append(result)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    backend = _backend_report(backend_calls)
    evidence = _evidence_report(recorder.path, mode, should_have_evidence=bool(outbound_paths))
    combined_ok = bool(backend["ok"] and evidence["ok"])

    return {
        "mock_url": f"http://{server.server_address[0]}:{server.server_address[1]}",
        "record_file": str(recorder.path),
        "backend_calls": backend_calls,
        "report": {
            "ok": combined_ok,
            "mode": mode,
            "sections": {
                "backend": backend,
                "evidence": evidence,
            },
        },
    }
