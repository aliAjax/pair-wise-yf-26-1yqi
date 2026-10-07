# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限和访问控制。

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
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单和副本状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/report`：保存点单独上报 `online`/`offline`；上报只作参考，不决定健康。
- `POST /api/copies/{id}/reconcile`：按本地原始清单对账单个副本，登记差异与待办。
- `POST /api/versions/{id}/reconcile`：对账该版本下全部副本。
- `POST /api/copies/{id}/recover`：从待办恢复，按本地原始清单重新补传副本内容。
- `GET /api/archives/{id}/backlog`：查看对账差异待办（审计员只读）。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。

版本入库或迁移后会按已有保存点生成同步任务（`pending`）；保存点可单独上报在线/掉线，但健康只以服务端按本地原始清单重新计算的对账结果为准，不能只看上报。对账发现内容缺失或对不上时，副本标记 `corrupt`/`degraded`、同步任务标记 `mismatch` 并写入待办；补传从本地原始清单重新写入副本内容并关闭待办。所有对账、上报、补传动作都只追加审计记录，绝不覆盖历史。差异处理（对账、补传）仅 owner/archivist 可执行，审计员只能查看，越权补传直接返回 403。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
