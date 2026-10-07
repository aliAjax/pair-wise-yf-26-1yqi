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
                    reported_state TEXT CHECK(reported_state IN ('online','offline')),
                    reported_at TEXT,
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
                CREATE TABLE IF NOT EXISTS sync_tasks(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    copy_id INTEGER REFERENCES copies(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','synced','mismatch')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(version_id,location)
                );
                CREATE TABLE IF NOT EXISTS recovery_backlog(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    reason TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','resolved')),
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    resolved_by TEXT REFERENCES users(id)
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
                """
            )
            # 兼容旧库：为 copies 补充保存点上报状态字段
            existing = {row[1] for row in conn.execute("PRAGMA table_info(copies)").fetchall()}
            for column in ("reported_state", "reported_at"):
                if column not in existing:
                    conn.execute(f"ALTER TABLE copies ADD COLUMN {column} TEXT")

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

    def _create_sync_tasks(self, conn, archive_id: int, version_id: int) -> None:
        """版本入库或迁移后，为该档案已有保存点生成同步任务（待对账）。"""
        locations = [
            r["location"]
            for r in conn.execute(
                """SELECT DISTINCT c.location FROM copies c
                   JOIN archive_versions v ON v.id=c.version_id
                   WHERE v.archive_id=? ORDER BY c.location""",
                (archive_id,),
            ).fetchall()
        ]
        for loc in locations:
            conn.execute(
                """INSERT INTO sync_tasks(archive_id,version_id,copy_id,location,state,created_at,updated_at)
                   VALUES(?,?,NULL,?,'pending',?,?)
                   ON CONFLICT(version_id,location) DO NOTHING""",
                (archive_id, version_id, loc, now(), now()),
            )

    def _copy_health(self, conn, copy_id: int, version_id: int) -> tuple[list[str], list[str]]:
        """按本地原始清单核对副本，返回 (损坏/缺失路径, 多余路径)。

        健康以服务端持有的原始清单 archive_files 为准重新计算，
        不信任保存点上报，也不采纳副本自身记录的哈希。
        """
        manifest = conn.execute(
            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (version_id,)
        ).fetchall()
        stored = conn.execute(
            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=?", (copy_id,)
        ).fetchall()
        expected = {r["path"]: r for r in manifest}
        actual = {r["path"]: r for r in stored}
        corrupt = [
            p for p, exp in expected.items()
            if (got := actual.get(p)) is None
            or len(got["content"]) != exp["size"]
            or hashlib.sha256(got["content"]).hexdigest() != exp["sha256"]
        ]
        extra = [p for p in actual if p not in expected]
        return corrupt, extra

    def _refresh_version_state(self, conn, version_id: int) -> str:
        bad_copies = conn.execute(
            "SELECT COUNT(*) AS n FROM copies WHERE version_id=? AND state<>'healthy'", (version_id,)
        ).fetchone()["n"]
        bad_tasks = conn.execute(
            "SELECT COUNT(*) AS n FROM sync_tasks WHERE version_id=? AND state='mismatch'", (version_id,)
        ).fetchone()["n"]
        state = "degraded" if bad_copies or bad_tasks else "verified"
        conn.execute("UPDATE archive_versions SET state=? WHERE id=?", (state, version_id))
        return state

    def _ensure_backlog(self, conn, version: sqlite3.Row, copy: sqlite3.Row, detail: dict) -> None:
        """对账失败后登记待办；同一副本同一原因只保留一条未完成项，恢复后关闭。"""
        open_item = conn.execute(
            "SELECT id FROM recovery_backlog WHERE copy_id=? AND state='open' AND reason='sync_mismatch'",
            (copy["id"],),
        ).fetchone()
        if not open_item:
            conn.execute(
                """INSERT INTO recovery_backlog(archive_id,version_id,copy_id,reason,state,detail,created_at)
                   VALUES(?,?,?,'sync_mismatch','open',?,?)""",
                (version["archive_id"], version["id"], copy["id"],
                 json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
            )

    def _reconcile_copy(self, conn, actor_id: str, copy: sqlite3.Row) -> dict:
        """对账单个副本：以本地原始清单为准，更新副本/同步任务/待办并追加审计。

        调用方负责事务与权限；审计只追加，绝不覆盖既有记录。
        """
        version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
        corrupt, extra = self._copy_health(conn, copy["id"], version["id"])
        healthy = not corrupt and not extra
        if healthy:
            conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy["id"]))
            conn.execute(
                """UPDATE sync_tasks SET state='synced',updated_at=?,copy_id=COALESCE(copy_id,?)
                   WHERE version_id=? AND location=?""",
                (now(), copy["id"], version["id"], copy["location"]),
            )
            result_state = "healthy"
        else:
            conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy["id"]))
            conn.execute(
                """UPDATE sync_tasks SET state='mismatch',updated_at=?,copy_id=COALESCE(copy_id,?)
                   WHERE version_id=? AND location=?""",
                (now(), copy["id"], version["id"], copy["location"]),
            )
            self._ensure_backlog(conn, version, copy, {"corrupt_paths": corrupt, "extra_paths": extra})
            result_state = "corrupt"
        version_state = self._refresh_version_state(conn, version["id"])
        self._audit(
            conn, version["archive_id"], actor_id, "copy.reconcile",
            {"copy_id": copy["id"], "location": copy["location"], "state": result_state,
             "corrupt_paths": corrupt, "extra_paths": extra},
        )
        return {"copy_id": copy["id"], "location": copy["location"], "state": result_state,
                "corrupt_paths": corrupt, "extra_paths": extra, "version_state": version_state}

    def report_copy(self, user_id: str, copy_id: int, state: str) -> dict:
        """保存点单独上报在线/离线状态；上报不决定健康，健康只能来自对账。"""
        state = (state or "").strip().lower()
        if state not in ("online", "offline"):
            raise BusinessError("上报状态必须是 online 或 offline", 422, "invalid_report")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            conn.execute("UPDATE copies SET reported_state=?,reported_at=? WHERE id=?", (state, now(), copy_id))
            if state == "offline":
                conn.execute("UPDATE copies SET state='degraded' WHERE id=?", (copy_id,))
                self._refresh_version_state(conn, version["id"])
            self._audit(
                conn, version["archive_id"], user_id, "copy.report",
                {"copy_id": copy_id, "location": copy["location"], "reported_state": state},
            )
            return {"copy_id": copy_id, "location": copy["location"], "reported_state": state}

    def reconcile_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user, require_write=True)
                return self._reconcile_copy(conn, user_id, copy)
            except Exception:
                conn.rollback()
                raise

    def reconcile_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
                if not version:
                    raise BusinessError("档案版本不存在", 404, "not_found")
                self._access(conn, version["archive_id"], user, require_write=True)
                copies = conn.execute("SELECT * FROM copies WHERE version_id=? ORDER BY id", (version_id,)).fetchall()
                results = [self._reconcile_copy(conn, user_id, c) for c in copies]
                version_state = conn.execute("SELECT state FROM archive_versions WHERE id=?", (version_id,)).fetchone()["state"]
                return {"version_id": version_id, "state": version_state, "results": results}
            except Exception:
                conn.rollback()
                raise

    def recover_copy(self, user_id: str, copy_id: int) -> dict:
        """从待办恢复：以本地原始清单重新补传副本内容，关闭待办并追加审计。

        补传只重写副本内容与同步任务状态，绝不覆盖历史审计记录。
        """
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user, require_write=True)
                manifest = conn.execute(
                    "SELECT path,sha256,size,content FROM archive_files WHERE version_id=? ORDER BY path",
                    (version["id"],),
                ).fetchall()
                conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                for m in manifest:
                    conn.execute(
                        "INSERT INTO copy_files(copy_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (copy_id, m["path"], m["sha256"], m["size"], m["content"]),
                    )
                conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                conn.execute(
                    """UPDATE sync_tasks SET state='synced',updated_at=?,copy_id=?
                       WHERE version_id=? AND location=?""",
                    (now(), copy_id, version["id"], copy["location"]),
                )
                resolved = conn.execute(
                    """UPDATE recovery_backlog SET state='resolved',resolved_at=?,resolved_by=?
                       WHERE copy_id=? AND state='open' AND reason='sync_mismatch'""",
                    (now(), user_id, copy_id),
                )
                self._refresh_version_state(conn, version["id"])
                self._audit(
                    conn, version["archive_id"], user_id, "copy.recover",
                    {"copy_id": copy_id, "location": copy["location"],
                     "files": len(manifest), "resolved_backlog": resolved.rowcount},
                )
                return {"copy_id": copy_id, "location": copy["location"],
                        "state": "healthy", "files": len(manifest), "recovered": True}
            except Exception:
                conn.rollback()
                raise

    def backlog(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            items = conn.execute(
                "SELECT * FROM recovery_backlog WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            return [dict(i) | {"detail": json.loads(i["detail"])} for i in items]

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
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                self._create_sync_tasks(conn, archive_id, version_id)
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,created_at,last_verified_at) VALUES(?,?,?,?)",
                    (version_id, location, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                conn.execute(
                    """INSERT INTO sync_tasks(archive_id,version_id,copy_id,location,state,created_at,updated_at)
                       VALUES(?,?,?,?,'pending',?,?)
                       ON CONFLICT(version_id,location) DO UPDATE SET
                         copy_id=excluded.copy_id, updated_at=excluded.updated_at""",
                    (version["archive_id"], version_id, copy_id, location, now(), now()),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create", {"copy_id": copy_id, "version_id": version_id, "location": location})
                return {"id": copy_id, "version_id": version_id, "location": location, "state": "healthy"}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
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
            copies = conn.execute(
                """SELECT id,location,state,reported_state,reported_at,last_verified_at
                   FROM copies WHERE version_id=? ORDER BY id""", (version_id,)
            ).fetchall()
            sync_tasks = conn.execute(
                "SELECT id,copy_id,location,state,created_at,updated_at FROM sync_tasks WHERE version_id=? ORDER BY id",
                (version_id,),
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files],
                    "copies": [dict(x) for x in copies], "sync_tasks": [dict(x) for x in sync_tasks]}

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                # 健康以本地原始清单为准重新计算，不信任保存点上报或副本自身记录
                corrupt_paths, extra_paths = self._copy_health(conn, copy_id, copy["version_id"])
                repaired = False
                if not corrupt_paths and not extra_paths:
                    conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                    conn.execute(
                        """UPDATE sync_tasks SET state='synced',updated_at=?,copy_id=COALESCE(copy_id,?)
                           WHERE version_id=? AND location=?""",
                        (now(), copy_id, copy["version_id"], copy["location"]),
                    )
                    result_state = "healthy"
                else:
                    conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                    conn.execute(
                        """UPDATE sync_tasks SET state='mismatch',updated_at=?,copy_id=COALESCE(copy_id,?)
                           WHERE version_id=? AND location=?""",
                        (now(), copy_id, copy["version_id"], copy["location"]),
                    )
                    healthy = conn.execute(
                        "SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                        (copy["version_id"], copy_id),
                    ).fetchone()
                    result_state = "degraded"
                    if healthy:
                        donor = conn.execute(
                            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                        ).fetchall()
                        donor_by_path = {r["path"]: r for r in donor}
                        expected = {r["path"]: r for r in conn.execute(
                            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                        ).fetchall()}
                        if set(donor_by_path) == set(expected) and all(
                            hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected[p]["sha256"] for p in expected
                        ):
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                            conn.execute(
                                """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                   SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                (copy_id, healthy["id"]),
                            )
                            conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                            conn.execute(
                                """UPDATE sync_tasks SET state='synced',updated_at=?,copy_id=?
                                   WHERE version_id=? AND location=?""",
                                (now(), copy_id, copy["version_id"], copy["location"]),
                            )
                            repaired, result_state = True, "healthy"
                    if result_state == "degraded":
                        self._ensure_backlog(
                            conn, version, copy,
                            {"corrupt_paths": corrupt_paths, "extra_paths": extra_paths, "via": "verify"},
                        )
                        self._refresh_version_state(conn, copy["version_id"])
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                     "extra_paths": extra_paths, "repaired": repaired},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths,
                        "extra_paths": extra_paths, "repaired": repaired}
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
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip()},
                )
                self._create_sync_tasks(conn, source_version["archive_id"], target_version_id)
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
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
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
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "report" and method == "POST":
            d = self._body()
            return self._send(200, store.report_copy(user, int(parts[2]), d.get("state", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "reconcile" and method == "POST":
            return self._send(200, store.reconcile_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "recover" and method == "POST":
            return self._send(200, store.recover_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "reconcile" and method == "POST":
            return self._send(200, store.reconcile_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "backlog" and method == "GET":
            return self._send(200, store.backlog(user, int(parts[2])))
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
