# Ministry Mock Suite

Local ministry-side mock suite for protocol and contract checks without PG,
Redis, or a backend dependency.

This first skeleton sends and receives plain envelopes. Real SM2/SM4 envelope
encryption belongs to the `gate-ministry-entry-contract` feature work and is
not implemented here.

## Quick Start

```powershell
python tools/run_mock_server.py --host 127.0.0.1 --port 18080
python tools/send_case.py --case policy_302 --base-url http://127.0.0.1:8000
python -m pytest
```

## Mock Receiver

The receiver uses Python standard library `http.server` and supports:

- `GET /health`
- `POST /ministry/receive`
- `POST /ministry/file`

Accepted ministry POST requests return:

```json
{"statusCode": 0, "statusText": "mock accepted", "rspMsgCnt": ""}
```

Requests and responses are recorded as JSON Lines at:

```text
reports/mock-server/<timestamp>/requests.jsonl
```

## Fixtures

Available receive cases:

- `policy_302`
- `test_data_307_tst_type_1`
- `device_cmd_309`
- `platform_event_303`
- `unknown_subtype_399`

`tools/send_case.py` loads one fixture, builds a plain envelope, and posts it
to `<base-url>/api/ministry/receive` by default. If the target backend already
requires encrypted `reqMsgCnt`, the request may fail with a decode or decrypt
error; that is acceptable for this first mock skeleton.
