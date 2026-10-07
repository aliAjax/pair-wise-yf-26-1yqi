import base64
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.store.grant("owner", self.archive["id"], "archivist", "write")
        self.store.grant("owner", self.archive["id"], "auditor", "read")
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def _report_ok(self, copy_id, version_id=None):
        """模拟保存点按本地原始清单上报健康状态。"""
        detail = self.store.get_version("owner", version_id or self.version["id"])
        files = [{"path": f["path"], "sha256": f["sha256"], "size": f["size"]} for f in detail["files"]]
        return self.store.report_copy("archivist", copy_id, "ok", files)

    def test_ingest_generates_sync_tasks_for_storage_points(self):
        detail = self.store.get_version("owner", self.version["id"])
        tasks = {t["location"]: t["state"] for t in detail["sync_tasks"]}
        # seed 的两处保存点生成待办任务；add_copy 的位置已立即同步
        self.assertEqual(tasks["site-a"], "pending")
        self.assertEqual(tasks["site-b"], "pending")
        self.assertEqual(tasks["offline-disk-a"], "synced")
        self.assertEqual(tasks["offline-disk-b"], "synced")

    def test_reconcile_detects_mismatch_and_recovers_from_pending_task(self):
        self._report_ok(self.copy1)
        ok = self.store.reconcile_copy("archivist", self.copy1)
        self.assertEqual(ok["state"], "healthy")

        # 保存点内容损坏但仍上报一切正常：对账按本地原始清单核对，不信上报
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        self._report_ok(self.copy1)
        bad = self.store.reconcile_copy("archivist", self.copy1)
        self.assertEqual(bad["state"], "corrupt")
        self.assertEqual(bad["differences"], [{"path": "records/one.xml", "issue": "content_mismatch"}])
        self.assertIsNotNone(bad["sync_task_id"])
        version = self.store.get_version("owner", self.version["id"])["version"]
        self.assertEqual(version["state"], "degraded")

        # 越权补传直接拒绝
        with self.assertRaises(BusinessError) as ctx:
            self.store.run_sync_task("auditor", bad["sync_task_id"])
        self.assertEqual(ctx.exception.status, 403)

        # 档案管理员从待办恢复：重新补传后副本与版本恢复健康
        done = self.store.run_sync_task("archivist", bad["sync_task_id"])
        self.assertEqual(done["state"], "synced")
        again = self.store.reconcile_copy("archivist", self.copy1)
        self.assertEqual(again["state"], "healthy")
        version = self.store.get_version("owner", self.version["id"])["version"]
        self.assertEqual(version["state"], "verified")

        # 已完成的任务不能重复补传
        with self.assertRaises(BusinessError) as ctx:
            self.store.run_sync_task("archivist", bad["sync_task_id"])
        self.assertEqual(ctx.exception.code, "task_already_done")

        # 原审计记录不被覆盖：失败与恢复全程可追溯
        status = self.store.archive_status("auditor", self.archive["id"])
        reconciles = [a["detail"]["result"] for a in status["audit"] if a["action"] == "copy.reconcile"]
        self.assertEqual(reconciles, ["healthy", "corrupt", "healthy"])
        self.assertTrue(any(a["action"] == "sync.run" for a in status["audit"]))

    def test_offline_point_is_not_healthy(self):
        self.store.report_copy("archivist", self.copy1, "offline", [])
        result = self.store.reconcile_copy("archivist", self.copy1)
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["report_issue"], "point_offline")
        self.assertEqual(result["differences"], [])
        # 保存点恢复在线并上报正确清单后，对账通过
        self._report_ok(self.copy1)
        self.assertEqual(self.store.reconcile_copy("archivist", self.copy1)["state"], "healthy")

    def test_missing_report_is_not_healthy(self):
        result = self.store.reconcile_copy("archivist", self.copy1)
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["report_issue"], "no_report")

    def test_reported_manifest_mismatch_is_caught(self):
        detail = self.store.get_version("owner", self.version["id"])
        files = [{"path": f["path"], "sha256": f["sha256"], "size": f["size"]} for f in detail["files"]]
        files[0]["sha256"] = "0" * 64  # 保存点上报的清单与本地原始清单对不上
        tampered = files[0]["path"]
        self.store.report_copy("archivist", self.copy1, "ok", files)
        result = self.store.reconcile_copy("archivist", self.copy1)
        self.assertEqual(result["state"], "degraded")
        self.assertEqual(result["report_differences"],
                         [{"path": tampered, "issue": "report_mismatch"}])

    def test_auditor_is_read_only(self):
        # 审计员可以查看版本与状态
        self.store.get_version("auditor", self.version["id"])
        self.store.archive_status("auditor", self.archive["id"])
        # 但不能对账、上报或建立副本
        with self.assertRaises(BusinessError) as ctx:
            self.store.reconcile_copy("auditor", self.copy1)
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.report_copy("auditor", self.copy1, "ok", [])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("auditor", self.version["id"], "site-c")
        self.assertEqual(ctx.exception.status, 403)

    def test_migration_generates_sync_tasks_and_follows_same_rules(self):
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["version"], 2)
        self.assertTrue(any(f["path"] == "records/one.html" for f in detail["files"]))
        tasks = {t["location"]: t for t in detail["sync_tasks"]}
        # 迁移后的新版本为每个保存点生成待办任务
        self.assertEqual(set(tasks), {"site-a", "site-b", "offline-disk-a", "offline-disk-b"})
        self.assertTrue(all(t["state"] == "pending" for t in tasks.values()))
        self.assertTrue(all(t["reason"] == "migrate" for t in tasks.values()))

        # 越权补传同样直接拒绝
        task_id = tasks["offline-disk-a"]["id"]
        with self.assertRaises(BusinessError) as ctx:
            self.store.run_sync_task("auditor", task_id)
        self.assertEqual(ctx.exception.status, 403)

        # 管理员补传、上报、对账，沿用同一套判断
        self.store.run_sync_task("archivist", task_id)
        copy_id = [c for c in self.store.get_version("owner", migrated["id"])["copies"]
                   if c["location"] == "offline-disk-a"][0]["id"]
        self._report_ok(copy_id, migrated["id"])
        self.assertEqual(self.store.reconcile_copy("archivist", copy_id)["state"], "healthy")

    def test_restricted_access_and_invalid_manifest_are_rejected(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_version("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.ingest_version("owner", self.archive["id"], [{"path": "../escape.txt", "content_b64": "eA=="}])
        self.assertEqual(ctx.exception.code, "unsafe_path")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-a")
        self.assertEqual(ctx.exception.code, "copy_exists")


if __name__ == "__main__":
    unittest.main()
