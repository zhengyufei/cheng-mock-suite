# 协议级部侧监管平台 mock

## 定位

`protocol-ministry-platform` 是当前 `gate-ministry-entry-contract` feature 的第一类外部模拟。它模拟“部侧监管平台”的协议边界，不模拟完整部侧业务系统。

它主要解决两个问题：

1. 当前后端没有真实部侧平台时，仍然可以验证本系统主动上报是否发到了正确外部入口。
2. 当前 feature 重构 `/api/ministry/receive`、`/api/ministry/file` 时，可以用固定 fixture 模拟部侧下发。

## 目录边界

```text
mock_ministry/mocks/protocol_ministry_platform/
  contracts.py      接口路径、subtype 覆盖范围
  envelope.py       envelope 解析和协议观察
  responses.py      成功、拒绝、未知 subtype、非法 envelope 响应
  server.py         HTTP mock server

fixtures/protocol_ministry_platform/
  manifest.json     当前 mock 覆盖的接口和场景清单
```

以后如果要加“安全设备/下级平台 mock”或“测试数据/靶标资产 mock”，应该与 `protocol_ministry_platform` 平级新建目录，不要塞进这一类 mock。

## 覆盖接口

mock 接收当前后端主动推送：

| 路径 | 说明 |
| --- | --- |
| `/ministry/receive` | 当前后端 `push_to_ministry()` 的外部目标 |
| `/ministry/file` | 协议目标文件入口 |
| `/api/v1/platformFileUpload` | 当前后端文件上报代码里的现有路径，用于暴露与协议目标的偏差 |

工具模拟部侧下发到当前后端：

| 路径 | 说明 |
| --- | --- |
| `/api/ministry/receive` | 当前 feature 重点重构的统一接收入口 |
| `/api/ministry/file` | 当前 feature 重点重构的文件/分片入口 |

## 启动

```powershell
python tools/run_mock_server.py --mock protocol-ministry-platform --host 127.0.0.1 --port 18080
```

后端联调时，把 `UPSTREAM_BASE_URL` 指向：

```text
http://127.0.0.1:18080
```

当前后端主动注册、上传、统计会被 mock 接收并记录到：

```text
reports/mock-server/<timestamp>/requests.jsonl
```

## 发送 fixture 到后端

```powershell
python tools/send_case.py --case policy_302 --base-url http://127.0.0.1:8000
```

第一阶段发送的是 plain envelope。真实 SM2/SM4 加密 sender 等后端 gate 稳定后再补。

## 验收标准

- 能记录 `/ministry/receive`、`/ministry/file`、`/api/v1/platformFileUpload`。
- 能从 `orderID` 和 plain inner message 中识别 `orderType/orderSubType` 或 `dataType/dataSubType`。
- 能识别未知 subtype 并返回协议级错误。
- 能记录 `X-Enc-*` 头是否存在。
- 不依赖 PG、Redis、真实后端。

## 验证模式

| 模式 | 用途 | 结果解释 |
| --- | --- | --- |
| `observe` | 服务局部重构，记录当前项目行为 | 协议偏差作为 warning，适合重构前后对比 |
| `contract` | 以原始协议/产品要求作为标准答案 | 协议偏差作为 failure，适合验收前检查 |

## 离线验证 evidence

```powershell
python tools/verify_protocol_ministry_platform.py --mode observe --format markdown
python tools/verify_protocol_ministry_platform.py --mode contract --format markdown
```

`observe` 用于重构保护，`contract` 用于协议契约检查。

## 自动联调入口

当前后端已经启动后，执行：

```powershell
python tools/run_protocol_refactor_check.py --backend-base-url http://127.0.0.1:8000 --mode observe --send-case policy_302
```

如果需要触发后端 outbound，可显式传入路径：

```powershell
python tools/run_protocol_refactor_check.py --backend-base-url http://127.0.0.1:8000 --mode observe --outbound-path /api/ministry/register/platform
```

后端必须自行配置 `UPSTREAM_BASE_URL=http://127.0.0.1:<mock-port>`，否则后端 outbound 不会打到 mock。
