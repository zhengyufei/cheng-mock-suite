# Ministry Mock Suite

当前仓库用于维护本地外部系统 mock。第一阶段先完成 `协议级部侧监管平台 mock`，用于支撑 `gate-ministry-entry-contract` 的接口重构和本地联调。

默认不依赖 PG、Redis 或真实后端。第一阶段发送和解析 plain envelope；真实 SM2/SM4 加密能力归属于后续 gate 联调增强，不在当前 mock 基础阶段强做。

## Quick Start

```powershell
python tools/run_mock_server.py --mock protocol-ministry-platform --host 127.0.0.1 --port 18080
python tools/send_case.py --case policy_302 --base-url http://127.0.0.1:8000
python tools/verify_protocol_ministry_platform.py --mode observe --format markdown
python tools/run_protocol_refactor_check.py --backend-base-url http://127.0.0.1:8000 --mode observe
python -m pytest
```

## 外部模拟目录

```text
mock_ministry/mocks/
  protocol_ministry_platform/  协议级部侧监管平台 mock
```

后续如果新增“安全设备/下级平台 mock”或“测试数据/靶标资产 mock”，应在 `mock_ministry/mocks/` 下建立平级目录。

## 协议级部侧监管平台 mock

该 mock 使用 Python standard library `http.server`，支持：

- `GET /health`
- `GET /contracts`
- `POST /ministry/receive`
- `POST /ministry/file`
- `POST /api/v1/platformFileUpload`

其中 `/api/v1/platformFileUpload` 是当前后端文件上报代码里的现有路径，保留用于发现它和协议目标 `/ministry/file` 的偏差。

成功接收时返回：

```json
{"statusCode": 0, "statusText": "mock accepted", "rspMsgCnt": ""}
```

Requests and responses are recorded as JSON Lines at:

```text
reports/mock-server/<timestamp>/requests.jsonl
```

详细说明见：

```text
docs/protocol-ministry-platform-mock.md
```

## 验证模式

- `observe`：服务局部重构，协议偏差只作为 warning。
- `contract`：服务协议验收，协议偏差作为 failure。

## Fixtures

用于模拟部侧下发到后端 `/api/ministry/receive` 的 receive cases：

- `policy_302`
- `test_data_307_tst_type_1`
- `device_cmd_309`
- `platform_event_303`
- `unknown_subtype_399`
- `file_103`

`tools/send_case.py` loads one fixture, builds a plain envelope, and posts it
to `<base-url>/api/ministry/receive` by default. If the target backend already requires encrypted `reqMsgCnt`, the request may fail with a decode or decrypt error; that is acceptable for this first mock stage.
`tools/run_protocol_refactor_check.py` runs the default contract send suite `policy_302,file_103` when `--send-case` is omitted.
