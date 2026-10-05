# 空气污染源许可与合规检查

管理设施、排放口、治理设备、现场检查、整改和许可续期。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/ledger.py`：设备序号+因果序号事件账的纯逻辑（因果重建、缺号/分叉/篡改判定、状态投影）。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制、审计链和事件账存储。
- `src/service.py`：权限检查、用例编排、并发控制、审计和事件账用例。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则、失败和事件账测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8314
```

默认端口为`8314`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`

允许角色：applicant, inspector, compliance_manager, viewer。申报量超过许可量或检查发现高严重度问题时提高优先级；存在未关闭整改时不能批准。

## 事件账（设备序号 + 因果序号）

许可、现场检查、整改三类变更不再混写在同一条记录里，而是作为类型化事件
（`license` / `inspection` / `rectification`）追加到因果事件账。

每个事件携带两个序号：

- **设备序号** `device_id` + `device_seq`：设备端单调递增，组成事件键（如 `devB#7`）。
  负责幂等去重与缺号检测。设备断电后用同一序号原样重放（含 `causal_prev`），
  事件与审计都不会重复写入。
- **因果序号** `causal_prev`：前驱事件的事件键（根为 `null`）。当前状态按因果关系
  重建，不按写入顺序。两名检查员同时基于同一已确认事件提交时，只有一人能接上链头，
  晚到者收到 `409 LedgerForkError`，已确认结果不被覆盖。

接口：

- `POST /api/items/{id}/changes`：在线提交一类变更，body 含 `type`、`device_id`、
  `device_seq`、`causal_prev`（省略时默认当前链头）、`payload`。
- `POST /api/items/{id}/backfill`：乱序补传，body 为 `{"events":[...]}`，
  按因果重建当前状态。设备序号缺号、因果前驱无法解析、改过已确认事件，或从非链头
  分叉时，整批不写入并保留原结果（`LedgerGapError` / `LedgerTamperError` /
  `LedgerForkError`，均为 409）。传 `{"accept_pending":true,...}` 可把前驱未到的
  事件先停放，前驱补传到达后自动贯通。
- `POST /api/items/{id}/recover`：补传失败后从最后确认事件恢复，丢弃未确认停放事件；
  重放只认设备序号键，不重复产生审计。
- `GET /api/items/{id}/ledger`：当前因果重建状态（许可、最近已确认检查结果、
  未关闭整改、链头、停放计数）。
- `GET /api/items/{id}/ledger/verify`：重算已确认链哈希，发现篡改即报错。
- `POST /api/ledger/upgrade`（compliance_manager）：把旧的 items/records 数据
  固化为每个事项的基线事件（`baseline`，链根）。应用启动时也会自动执行一次，幂等。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
