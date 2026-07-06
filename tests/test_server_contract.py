from __future__ import annotations

import json
import threading
from urllib.request import Request, urlopen

from mock_ministry.recorder import FileRecorder
from mock_ministry.server import ACCEPTED_RESPONSE, create_server


def test_server_accepts_receive_post(tmp_path) -> None:
    recorder = FileRecorder(base_dir=tmp_path, run_id="server")
    server = create_server(host="127.0.0.1", port=0, recorder=recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        body = json.dumps(
            {
                "orderID": "2-301-2026070300000000001",
                "orgCode": "MIIT",
                "ispCode": "CMCC",
                "ctxCode": 0,
                "reqMsgCnt": json.dumps({"orderType": 2, "orderSubType": 301}),
            }
        ).encode("utf-8")
        request = Request(
            f"http://{host}:{port}/ministry/receive",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            assert response.status == 200

        assert payload == ACCEPTED_RESPONSE
        record = json.loads(recorder.path.read_text(encoding="utf-8").strip())
        assert record["path"] == "/ministry/receive"
        assert record["response"]["body"] == ACCEPTED_RESPONSE
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
