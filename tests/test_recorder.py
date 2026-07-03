from __future__ import annotations

import json

from mock_ministry.recorder import FileRecorder


def test_file_recorder_writes_jsonl(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="run")
    path = recorder.record(
        method="POST",
        path="/ministry/receive",
        headers={"Content-Type": "application/json"},
        body='{"hello":"world"}',
        response={"status": 200, "body": {"statusCode": 0}},
    )

    assert path == tmp_path / "run" / "requests.jsonl"
    assert path.is_file()
    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["method"] == "POST"
    assert record["path"] == "/ministry/receive"
    assert record["response"]["status"] == 200
