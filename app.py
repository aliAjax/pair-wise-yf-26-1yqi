"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        encoded = item.get("content_b64")
        if not isinstance(encoded, str):
            raise BusinessError(f"{raw_path} 缺少 content_b64", 422, "content_required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BusinessError(f"{raw_path} 不是合法 Base64", 422, "invalid_base64")
        if len(content) > MAX_FILE_SIZE:
            raise BusinessError(f"{raw_path} 超过单文件大小限制", 413, "file_too_large")
        result.append(
            {"path": raw_path, "content": content, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return result


def verify_report_manifest(files: object, state: str) -> list[dict]:
    """校验保存点上报的文件清单；离线/降级上报允许空清单。"""
    if files is None:
        files = []
    if not isinstance(files, list):
        raise BusinessError("上报清单必须是数组", 422, "invalid_report")
    if state == "ok" and not files:
        raise BusinessError("保存点上报健康时必须提供文件清单", 422, "invalid_report")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("上报条目必须是对象", 422, "invalid_report")
        path = str(item.get("path", "")).strip().replace("\\", "/")
        sha256 = str(item.get("sha256", "")).strip().lower()
        size = item.get("size")
        if not path or path in seen:
            raise BusinessError("上报清单路径缺失或重复", 422, "invalid_report")
        seen.add(path)
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise BusinessError(f"{path} 上报的 sha256 不合法", 422, "invalid_report")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BusinessError(f"{path} 上报的 size 不合法", 422, "invalid_report")
        result.append({"path": path, "sha256": sha256, "size": size})
    return result


class PreservationStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init_schema(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
                );
                CREATE TABLE IF NOT EXISTS archives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL REFERENCES users(id),
                    retention_until TEXT NOT NULL,
                    restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archive_members(
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    permission TEXT NOT NULL CHECK(permission IN ('read','write')),
                    PRIMARY KEY(archive_id,user_id)
                );
                CREATE TABLE IF NOT EXISTS archive_versions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded')),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(archive_id,version)
                );
                CREATE TABLE IF NOT EXISTS archive_files(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    UNIQUE(version_id,path)
                );
                CREATE TABLE IF NOT EXISTS copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    UNIQUE(version_id,location)
                );
                CREATE TABLE IF NOT EXISTS copy_files(
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY(copy_id,path)
                );
                CREATE TABLE IF NOT EXISTS migrations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    source_path TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    target_format TEXT NOT NULL,
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS storage_points(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sync_tasks(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','synced')),
                    reason TEXT NOT NULL DEFAULT 'ingest' CHECK(reason IN ('ingest','migrate','reconcile')),
                    actor_id TEXT REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    finished_at TEXT
                );
                CREATE TABLE IF NOT EXISTS copy_reports(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    state TEXT NOT NULL CHECK(state IN ('ok','offline','degraded')),
                    files_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def seed(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name,role) VALUES(?,?,?)",
                [
                    ("owner", "机构档案负责人", "owner"),
                    ("archivist", "档案管理员", "archivist"),
                    ("auditor", "独立审计员", "auditor"),
                    ("outsider", "未授权访客", "auditor"),
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO storage_points(name,created_at) VALUES(?,?)",
                [("site-a", now()), ("site-b", now())],
            )

    def _user(self, conn, user_id: str | None, roles: set[str] | None = None) -> sqlite3.Row:
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在", 401, "unknown_user")
        if roles and user["role"] not in roles:
            raise BusinessError("当前角色无权执行此操作", 403, "forbidden")
        return user

    def _access(self, conn, archive_id: int, user: sqlite3.Row, require_write: bool = False) -> None:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        if archive["owner_id"] == user["id"]:
            return
        row = conn.execute(
            "SELECT permission FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone()
        if not row or (require_write and row["permission"] != "write"):
            raise BusinessError("没有该受限档案的访问权限", 403, "forbidden")

    def _audit(self, conn, archive_id: int, actor: str, action: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def _ensure_storage_point(self, conn, name: str) -> None:
        conn.execute("INSERT OR IGNORE INTO storage_points(name,created_at) VALUES(?,?)", (name, now()))

    def _open_sync_task(self, conn, version_id: int, location: str, reason: str) -> int:
        """确保 (版本, 保存点) 存在待办同步任务；已有待办则复用，历史任务不覆盖。"""
        row = conn.execute(
            "SELECT id FROM sync_tasks WHERE version_id=? AND location=? AND state='pending'",
            (version_id, location),
        ).fetchone()
        if row:
            return row["id"]
        cur = conn.execute(
            "INSERT INTO sync_tasks(version_id,location,state,reason,created_at) VALUES(?,?,'pending',?,?)",
            (version_id, location, reason, now()),
        )
        return cur.lastrowid

    def _sync_tasks_for_all_points(self, conn, version_id: int, reason: str) -> list[int]:
        """版本入库/迁移后，为每个已登记保存点生成待办同步任务。"""
        task_ids = []
        for point in conn.execute("SELECT name FROM storage_points ORDER BY id").fetchall():
            task_ids.append(self._open_sync_task(conn, version_id, point["name"], reason))
        return task_ids

    def _refresh_version_state(self, conn, version_id: int) -> None:
        """版本健康由本地对账结果驱动：存在非健康副本即降级，全部健康则恢复。"""
        bad = conn.execute(
            "SELECT COUNT(*) FROM copies WHERE version_id=? AND state<>'healthy'", (version_id,)
        ).fetchone()[0]
        conn.execute(
            "UPDATE archive_versions SET state=? WHERE id=?", ("verified" if bad == 0 else "degraded", version_id)
        )

    def _run_sync_task(self, conn, task: sqlite3.Row, actor_id: str) -> dict:
        """按本地原始清单重新补传副本内容，并关闭待办任务。"""
        version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (task["version_id"],)).fetchone()
        files = conn.execute(
            "SELECT path,sha256,size,content FROM archive_files WHERE version_id=?", (task["version_id"],)
        ).fetchall()
        copy = conn.execute(
            "SELECT * FROM copies WHERE version_id=? AND location=?", (task["version_id"], task["location"])
        ).fetchone()
        if copy:
            copy_id = copy["id"]
            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
        else:
            copy_id = conn.execute(
                "INSERT INTO copies(version_id,location,created_at) VALUES(?,?,?)",
                (task["version_id"], task["location"], now()),
            ).lastrowid
        conn.execute(
            """INSERT INTO copy_files(copy_id,path,sha256,size,content)
               SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
            (copy_id, task["version_id"]),
        )
        conn.execute("UPDATE copies SET state='healthy' WHERE id=?", (copy_id,))
        conn.execute(
            "UPDATE sync_tasks SET state='synced',actor_id=?,finished_at=? WHERE id=?",
            (actor_id, now(), task["id"]),
        )
        self._refresh_version_state(conn, task["version_id"])
        self._audit(
            conn, version["archive_id"], actor_id, "sync.run",
            {"task_id": task["id"], "version_id": task["version_id"], "location": task["location"],
             "copy_id": copy_id, "files": len(files)},
        )
        return {"task_id": task["id"], "copy_id": copy_id, "version_id": task["version_id"],
                "location": task["location"], "state": "synced", "files": len(files)}

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create", {"retention_until": retention_until, "restricted": restricted})
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted}

    def grant(self, actor_id: str, archive_id: int, user_id: str, permission: str) -> dict:
        if permission not in {"read", "write"}:
            raise BusinessError("permission 必须是 read 或 write", 422, "invalid_permission")
        with self.connect() as conn:
            actor = self._user(conn, actor_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["owner_id"] != actor_id:
                raise BusinessError("只有档案所有者可以授权", 403, "forbidden")
            self._user(conn, user_id)
            conn.execute(
                """INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,?)
                   ON CONFLICT(archive_id,user_id) DO UPDATE SET permission=excluded.permission""",
                (archive_id, user_id, permission),
            )
            self._audit(conn, archive_id, actor_id, "access.grant", {"user_id": user_id, "permission": permission})
            return {"archive_id": archive_id, "user_id": user_id, "permission": permission}

    def ingest_version(self, actor_id: str, archive_id: int, files: object) -> dict:
        manifest = verify_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (archive_id, version_no, actor_id, now()),
                )
                version_id = cur.lastrowid
                for item in manifest:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (version_id, item["path"], item["sha256"], item["size"], item["content"]),
                    )
                task_ids = self._sync_tasks_for_all_points(conn, version_id, "ingest")
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest],
                     "sync_tasks": task_ids},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str) -> dict:
        """在指定保存点建立副本：登记保存点、生成同步任务并按本地原始清单立即补传。"""
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            if conn.execute(
                "SELECT 1 FROM copies WHERE version_id=? AND location=?", (version_id, location)
            ).fetchone():
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._ensure_storage_point(conn, location)
                task_id = self._open_sync_task(conn, version_id, location, "ingest")
                task = conn.execute("SELECT * FROM sync_tasks WHERE id=?", (task_id,)).fetchone()
                result = self._run_sync_task(conn, task, actor_id)
                return {"id": result["copy_id"], "version_id": version_id, "location": location,
                        "state": "healthy", "task_id": task_id}
            except Exception:
                conn.rollback()
                raise

    def get_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            files = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,)
            ).fetchall()
            copies = []
            for row in conn.execute(
                "SELECT id,location,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall():
                item = dict(row)
                report = conn.execute(
                    "SELECT state,created_at FROM copy_reports WHERE copy_id=? ORDER BY id DESC LIMIT 1", (row["id"],)
                ).fetchone()
                item["latest_report"] = dict(report) if report else None
                copies.append(item)
            sync_tasks = conn.execute(
                "SELECT id,location,state,reason,actor_id,created_at,finished_at FROM sync_tasks WHERE version_id=? ORDER BY id",
                (version_id,),
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files],
                    "copies": copies, "sync_tasks": [dict(x) for x in sync_tasks]}

    def report_copy(self, actor_id: str, copy_id: int, state: str, files: object) -> dict:
        """保存点单独上报状态与清单；上报只追加不覆盖，健康与否由对账按本地原始清单判定。"""
        if state not in {"ok", "offline", "degraded"}:
            raise BusinessError("上报状态必须是 ok、offline 或 degraded", 422, "invalid_report_state")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], actor, require_write=True)
            manifest = verify_report_manifest(files, state)
            conn.execute(
                "INSERT INTO copy_reports(copy_id,state,files_json,created_at) VALUES(?,?,?,?)",
                (copy_id, state, json.dumps(manifest, ensure_ascii=False, sort_keys=True), now()),
            )
            self._audit(conn, version["archive_id"], actor_id, "copy.report",
                        {"copy_id": copy_id, "state": state, "files": len(manifest)})
            return {"copy_id": copy_id, "state": state, "files": len(manifest)}

    def reconcile_copy(self, actor_id: str, copy_id: int) -> dict:
        """对账：以本地原始清单为准核对副本实际内容和保存点上报，不轻信上报状态。

        内容对不上 -> corrupt；保存点掉线、缺上报或上报清单对不上 -> degraded；
        对账失败会生成待办同步任务，供档案管理员重新补传恢复。
        """
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], actor, require_write=True)
                expected = {
                    r["path"]: (r["sha256"], r["size"])
                    for r in conn.execute(
                        "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                    ).fetchall()
                }
                stored = {
                    r["path"]: r
                    for r in conn.execute(
                        "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=?", (copy_id,)
                    ).fetchall()
                }
                differences = []
                for path, (sha256, size) in sorted(expected.items()):
                    row = stored.get(path)
                    if row is None:
                        differences.append({"path": path, "issue": "missing"})
                    elif hashlib.sha256(row["content"]).hexdigest() != sha256 or len(row["content"]) != size:
                        differences.append({"path": path, "issue": "content_mismatch"})
                for path in sorted(stored.keys() - expected.keys()):
                    differences.append({"path": path, "issue": "unexpected"})
                report = conn.execute(
                    "SELECT * FROM copy_reports WHERE copy_id=? ORDER BY id DESC LIMIT 1", (copy_id,)
                ).fetchone()
                report_issue, report_differences = None, []
                if report is None:
                    report_issue = "no_report"
                elif report["state"] != "ok":
                    report_issue = f"point_{report['state']}"
                else:
                    reported = {f["path"]: (f["sha256"], f["size"]) for f in json.loads(report["files_json"])}
                    for path, expect in sorted(expected.items()):
                        if path not in reported:
                            report_differences.append({"path": path, "issue": "report_missing"})
                        elif reported[path] != expect:
                            report_differences.append({"path": path, "issue": "report_mismatch"})
                    for path in sorted(reported.keys() - expected.keys()):
                        report_differences.append({"path": path, "issue": "report_unexpected"})
                healthy = not differences and report_issue is None and not report_differences
                task_id = None
                if healthy:
                    conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                    conn.execute(
                        """UPDATE sync_tasks SET state='synced',actor_id=?,finished_at=?
                           WHERE version_id=? AND location=? AND state='pending'""",
                        (actor_id, now(), copy["version_id"], copy["location"]),
                    )
                    result_state = "healthy"
                else:
                    result_state = "corrupt" if differences else "degraded"
                    conn.execute("UPDATE copies SET state=? WHERE id=?", (result_state, copy_id))
                    task_id = self._open_sync_task(conn, copy["version_id"], copy["location"], "reconcile")
                self._refresh_version_state(conn, copy["version_id"])
                self._audit(
                    conn, version["archive_id"], actor_id, "copy.reconcile",
                    {"copy_id": copy_id, "result": result_state, "differences": differences,
                     "report_issue": report_issue, "report_differences": report_differences,
                     "sync_task_id": task_id},
                )
                return {"copy_id": copy_id, "state": result_state, "differences": differences,
                        "report_issue": report_issue, "report_differences": report_differences,
                        "sync_task_id": task_id}
            except Exception:
                conn.rollback()
                raise

    def run_sync_task(self, actor_id: str, task_id: int) -> dict:
        """从待办恢复：按本地原始清单重新补传副本；审计记录只追加，不覆盖。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                task = conn.execute("SELECT * FROM sync_tasks WHERE id=?", (task_id,)).fetchone()
                if not task:
                    raise BusinessError("同步任务不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (task["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], actor, require_write=True)
                if task["state"] != "pending":
                    raise BusinessError("同步任务已完成，不能重复补传", 409, "task_already_done")
                return self._run_sync_task(conn, task, actor_id)
            except Exception:
                conn.rollback()
                raise

    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now()),
                )
                target_version_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO archive_files(version_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files
                       WHERE version_id=? AND path<>?""",
                    (target_version_id, version_id, source_path),
                )
                conn.execute(
                    "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                    (target_version_id, converted["path"], converted["sha256"], converted["size"], converted["content"]),
                )
                conn.execute(
                    "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (version_id, target_version_id, source_path, converted["path"], target_format.strip(), actor_id, now()),
                )
                task_ids = self._sync_tasks_for_all_points(conn, target_version_id, "migrate")
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip(),
                     "sync_tasks": task_ids},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id, "target_path": converted["path"]}
            except Exception:
                conn.rollback()
                raise

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            version_items = []
            for v in versions:
                copies = []
                for c in conn.execute(
                    "SELECT id,location,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id", (v["id"],)
                ).fetchall():
                    item = dict(c)
                    report = conn.execute(
                        "SELECT state FROM copy_reports WHERE copy_id=? ORDER BY id DESC LIMIT 1", (c["id"],)
                    ).fetchone()
                    item["latest_report_state"] = report["state"] if report else None
                    copies.append(item)
                version_items.append(
                    dict(v) | {
                        "file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                        "copy_count": len(copies),
                        "copies": copies,
                        "sync_tasks": [
                            dict(t) for t in conn.execute(
                                "SELECT id,location,state,reason,actor_id,created_at,finished_at FROM sync_tasks WHERE version_id=? ORDER BY id",
                                (v["id"],),
                            ).fetchall()
                        ],
                    }
                )
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": version_items,
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.0"

    def _store(self):
        return self.server.store  # type: ignore[attr-defined]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict):
            raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        user = self.headers.get("X-User-Id", "")
        if method == "GET" and path == "/":
            body = (BASE_DIR / "web" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True})
        store = self._store()
        if parts == ["api", "archives"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_archive(user, d.get("name", ""), d.get("retention_until", ""), bool(d.get("restricted", True))))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "reconcile" and method == "POST":
            return self._send(200, store.reconcile_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "report" and method == "POST":
            d = self._body()
            return self._send(200, store.report_copy(user, int(parts[2]), d.get("state", ""), d.get("files")))
        if len(parts) == 4 and parts[:2] == ["api", "sync-tasks"] and parts[3] == "run" and method == "POST":
            return self._send(200, store.run_sync_task(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            self._send(exc.status, {"error": {"code": exc.code, "message": exc.message}})
        except (ValueError, TypeError):
            self._send(400, {"error": {"code": "invalid_path", "message": "路径参数格式错误"}})
        except Exception as exc:
            self._send(500, {"error": {"code": "internal_error", "message": str(exc)}})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class PreservationServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        self.store = store
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="数字档案长期保存服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--port", type=int, default=8102)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    store = PreservationStore(args.db)
    store.init_schema()
    if args.seed:
        store.seed()
    if args.init or args.seed:
        print(f"数据库已初始化: {args.db}")
        return
    print(f"数字档案服务运行于 http://127.0.0.1:{args.port}")
    server = PreservationServer(("127.0.0.1", args.port), store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
