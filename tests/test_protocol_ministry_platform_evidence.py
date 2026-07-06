from __future__ import annotations

import json

from mock_ministry.mocks.protocol_ministry_platform.evidence import (
    filter_records,
    latest_run_dir,
    load_records,
    summarize_records,
)


def _write_record(path, record):
    path.write_text(json.dumps(record, ensure_ascii=False) + "\n", encoding="utf-8")


def test_load_records_reads_jsonl_with_meta(tmp_path) -> None:
    record_file = tmp_path / "requests.jsonl"
    _write_record(
        record_file,
        {
            "method": "POST",
            "path": "/ministry/receive",
            "body": "{}",
            "meta": {
                "mock": "protocol-ministry-platform",
                "endpoint_role": "platform_receive",
                "protocol": {"orderID": "2-301-2026070300000000001", "orderSubType": 301},
                "validation": {"ok": True, "errors": [], "warnings": []},
            },
        },
    )

    records = load_records(record_file)

    assert len(records) == 1
    assert records[0].path == "/ministry/receive"
    assert records[0].order_id == "2-301-2026070300000000001"
    assert records[0].sub_type == 301
    assert records[0].validation_ok is True


def test_latest_run_dir_returns_newest_directory(tmp_path) -> None:
    older = tmp_path / "20260703-100000-000000"
    newer = tmp_path / "20260703-110000-000000"
    older.mkdir()
    newer.mkdir()
    (older / "requests.jsonl").write_text("", encoding="utf-8")
    (newer / "requests.jsonl").write_text("", encoding="utf-8")

    assert latest_run_dir(tmp_path) == newer


def test_filter_and_summarize_records(tmp_path) -> None:
    record_file = tmp_path / "requests.jsonl"
    records = [
        {
            "method": "POST",
            "path": "/ministry/receive",
            "body": "{}",
            "meta": {
                "protocol": {"orderID": "2-301-2026070300000000001", "orderSubType": 301},
                "validation": {"ok": True, "errors": [], "warnings": []},
            },
        },
        {
            "method": "POST",
            "path": "/api/v1/platformFileUpload",
            "body": "file",
            "meta": {
                "protocol": {"orderID": None, "orderSubType": None},
                "validation": {"ok": True, "errors": [], "warnings": ["legacy file path"]},
            },
        },
    ]
    record_file.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records), encoding="utf-8")

    loaded = load_records(record_file)
    assert [r.path for r in filter_records(loaded, path="/ministry/receive")] == ["/ministry/receive"]

    summary = summarize_records(loaded)
    assert summary["total"] == 2
    assert summary["paths"]["/ministry/receive"] == 1
    assert summary["subtypes"]["301"] == 1
