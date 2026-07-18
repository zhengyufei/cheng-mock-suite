from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import requests

from mock_ministry.cases import build_plain_envelope, load_case
from mock_ministry.negative_cases import build_negative_case
from mock_ministry.recorder import FileRecorder

from .assertions import evaluate_records
from .evidence import load_records
from .server import create_server

EXPECTED_BUSINESS_STATUS_BY_CASE = {
    "unknown_subtype_399": 1,
}

DEFAULT_SEND_CASES = ["policy_302", "prod_vul_workorder_5_request"]


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

    return {
        "path": path,
        "status": response.status_code,
        "body": response.text,
        "headers": dict(response.headers),
        "expected_order_id": payload.get("orderID"),
    }


def _post_file_case(base_url: str) -> dict[str, Any]:
    order_id = "0-0-2026070300000000001"
    metadata = {
        "dataType": 0,
        "dataSubType": 0,
        "sign": "a" * 64,
        "timeStamp": "1752500000",
    }
    try:
        response = requests.post(
            _url(base_url, "/api/ministry/file"),
            data={
                "orderID": order_id,
                "orgCode": "MIIT",
                "ispCode": "CMCC",
                "ctxCode": "1",
                "reqMsgCnt": json.dumps(metadata, separators=(",", ":")),
            },
            files={"fileChunk": (f"{'f' * 32}_payload.json_1_1.tar.gz.bin", b"cipher-chunk")},
            headers={
                "X-Enc-Key": "key",
                "X-Enc-Key-G": "group-key",
                "X-Enc-Nonce": "nonce",
                "X-Enc-Auth-Tag": "tag",
                "X-Enc-Auth-Tag-File": "file-tag",
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        return {"path": "/api/ministry/file", "status": 0, "body": f"request failed: {exc}"}

    return {
        "path": "/api/ministry/file",
        "status": response.status_code,
        "body": response.text,
        "headers": dict(response.headers),
        "expected_order_id": order_id,
    }


def _response_status_code(call: dict[str, Any]) -> tuple[int | None, str | None]:
    try:
        body = json.loads(str(call.get("body", "")))
    except json.JSONDecodeError:
        return None, "invalid JSON body"
    if not isinstance(body, dict):
        return None, "invalid JSON body"
    value = body.get("statusCode") if isinstance(body, dict) else None
    if value is None:
        return None, "missing business statusCode"
    if type(value) is not int:
        return None, f"non-integer business statusCode {value}"
    return value, None


def _expected_business_status(call: dict[str, Any]) -> int | None:
    if "expected_business_status" in call:
        return int(call["expected_business_status"])
    case_name = call.get("case")
    if not case_name:
        return None
    return EXPECTED_BUSINESS_STATUS_BY_CASE.get(str(case_name), 0)


def _response_json(call: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    try:
        body = json.loads(str(call.get("body", "")))
    except json.JSONDecodeError:
        return None, "invalid JSON body"
    if not isinstance(body, dict):
        return None, "invalid JSON body"
    return body, None


def _required_header(headers: dict[str, Any], name: str) -> str | None:
    lowered = {str(key).lower(): str(value) for key, value in headers.items()}
    value = lowered.get(name.lower())
    return value or None


def _envelope_failures(call: dict[str, Any]) -> list[str]:
    case_label = call.get("case") or call["path"]
    body, parse_error = _response_json(call)
    if parse_error:
        return [f"{case_label} returned {parse_error}"]

    failures: list[str] = []
    expected_order_id = call.get("expected_order_id")
    if body.get("orderID") != expected_order_id:
        failures.append(f"{case_label} returned orderID {body.get('orderID')!r}, expected {expected_order_id!r}")
    if not isinstance(body.get("statusText"), str):
        failures.append(f"{case_label} returned missing or invalid statusText")
    if not isinstance(body.get("rspMsgCnt"), str) or not body.get("rspMsgCnt"):
        failures.append(f"{case_label} returned missing rspMsgCnt")

    headers = call.get("headers", {})
    required_headers = ["X-Enc-Key", "X-Enc-Key-G", "X-Enc-Nonce", "X-Enc-Auth-Tag"]
    if call.get("case") == "file_103" or call.get("path") == "/api/ministry/file":
        required_headers.append("X-Enc-Auth-Tag-File")
    for header in required_headers:
        if not _required_header(headers, header):
            failures.append(f"{case_label} missing response header {header}")
    return failures


def _backend_report(calls: list[dict[str, Any]], mode: str) -> dict[str, Any]:
    failures = [
        f"{call['path']} returned HTTP {call['status']}"
        for call in calls
        if int(call.get("status", 0)) < 200 or int(call.get("status", 0)) >= 300
    ]
    warnings = []
    for call in calls:
        expected = _expected_business_status(call)
        if expected is None:
            continue
        actual, parse_error = _response_status_code(call)
        if parse_error:
            message = f"{call.get('case') or call['path']} returned {parse_error}"
            if mode == "contract":
                failures.append(message)
            else:
                warnings.append(message)
        elif actual != expected:
            message = f"{call.get('case') or call['path']} returned business statusCode {actual}"
            if mode == "contract":
                failures.append(message)
            else:
                warnings.append(message)

        envelope_failures = _envelope_failures(call)
        if envelope_failures:
            if mode == "contract":
                failures.extend(envelope_failures)
            else:
                warnings.extend(envelope_failures)
    return {"ok": not failures, "failures": failures, "warnings": warnings, "total": len(calls)}


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
    negative_cases: list[str] | None = None,
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
            if case_name == "file_103":
                result = _post_file_case(backend_base_url)
            else:
                payload = build_plain_envelope(load_case(case_name))
                result = _post_json(backend_base_url, "/api/ministry/receive", payload)
            result["case"] = case_name
            backend_calls.append(result)

        for negative_name in negative_cases or []:
            case, expected_status = build_negative_case(negative_name)
            payload = build_plain_envelope(case)
            result = _post_json(backend_base_url, "/api/ministry/receive", payload)
            result["case"] = negative_name
            result["fixture_case"] = case.get("base_case")
            result["expected_business_status"] = expected_status
            backend_calls.append(result)

        for path in outbound_paths:
            result = _post_json(backend_base_url, path, {})
            result["case"] = None
            backend_calls.append(result)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

    backend = _backend_report(backend_calls, mode)
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
