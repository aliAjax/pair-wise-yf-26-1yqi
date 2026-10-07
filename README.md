# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、保存点状态上报、按本地原始清单对账、待办任务补传恢复、格式迁移、保留期限和访问控制。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小；入库后为每个已登记保存点生成待办同步任务。
- `GET /api/versions/{id}`：查看版本、文件清单、副本状态、保存点最近上报和同步任务。
- `POST /api/versions/{id}/copies`：在指定保存点建立副本（登记保存点并立即按本地原始清单同步）。
- `POST /api/copies/{id}/report`：保存点单独上报状态（`ok`/`offline`/`degraded`）与文件清单；上报只追加、不覆盖历史。
- `POST /api/copies/{id}/reconcile`：对账。以本地原始清单为准核对副本实际内容和最新上报，不轻信上报；失败时生成待办同步任务。仅 owner/archivist。
- `POST /api/sync-tasks/{id}/run`：从待办恢复，按本地原始清单重新补传；审计记录只追加不覆盖。仅 owner/archivist，审计员越权补传直接 403。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系；新版本同样为每个保存点生成待办同步任务，对账与补传沿用同一套权限判断。
- `GET /api/archives/{id}/status`：保留期限、版本状态、副本与上报状态、待办任务和审计记录。

## 对账与恢复规则

- 健康只认本地原始清单：副本实际内容须与入库清单逐项一致，且保存点最近上报为 `ok`、上报清单与原始清单一致；保存点掉线、缺上报或清单对不上都判不健康。
- 内容对不上标记 `corrupt`，保存点状态异常（掉线/缺上报/上报不符）标记 `degraded`；任一副本非健康，版本降级为 `degraded`，全部恢复健康后回到 `verified`。
- 对账失败自动生成该保存点的待办同步任务；档案管理员（owner/archivist）执行待办任务重新补传，不覆盖原审计记录，审计员只能查看。
- 档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；所有变更写入审计日志（只追加）。

