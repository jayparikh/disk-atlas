import sqlite3
import unittest

from recommendations import MINIMUM_BYTES, analyze, candidate_for
from scanner import SCHEMA, classify


class RecommendationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.report = {"scan": {"started": 2_000_000_000, "finished": 2_000_000_010, "status": "complete"}}

    def tearDown(self):
        self.db.close()

    def add(self, path, allocated, logical=None, modified=1_000_000_000):
        category, subcategory, kind = classify(path)
        self.db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)",
                        (path, path.rsplit("\\", 1)[0], category, subcategory, kind,
                         allocated if logical is None else logical, allocated, modified, 0))

    def test_threshold_applies_to_allocated_group_not_logical_bytes(self):
        self.add(r"C:\Users\a\AppData\Local\A\Cache\first", MINIMUM_BYTES // 2)
        self.add(r"C:\Users\a\AppData\Local\A\Cache\second", MINIMUM_BYTES // 2)
        self.add(r"C:\Users\a\AppData\Local\B\Cache\small", MINIMUM_BYTES - 1)
        self.add(r"C:\Users\a\Downloads\sparse.zip", 4096, logical=20 * 1024**3)
        self.add(r"C:\Users\a\Downloads\locked.zip", 0, logical=20 * 1024**3)
        items = analyze(self.db, self.report)["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["bytes"], MINIMUM_BYTES)
        self.assertEqual(items[0]["files"], 2)

    def test_nested_paths_have_one_owner_and_manifest_evidence(self):
        self.add(r"C:\Users\a\project\package.json", 100)
        self.add(r"C:\Users\a\project\package-lock.json", 100)
        self.add(r"C:\Users\a\project\node_modules\a\file", MINIMUM_BYTES)
        self.add(r"C:\Users\a\project\node_modules\a\node_modules\b\Cache\file", MINIMUM_BYTES)
        items = analyze(self.db, self.report)["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["path"], r"C:\Users\a\project\node_modules")
        self.assertEqual(items[0]["bytes"], 2 * MINIMUM_BYTES)
        self.assertEqual(items[0]["risk"], "regenerable")
        self.assertEqual(len(items[0]["evidence"]), 2)

    def test_missing_restore_inputs_requires_review(self):
        self.add(r"C:\Users\a\project\.venv\Lib\file", MINIMUM_BYTES)
        item = analyze(self.db, self.report)["items"][0]
        self.assertEqual(item["risk"], "review")
        self.assertIn("not verified", item["caution"])

    def test_system_git_cloud_and_shared_components_are_not_candidates(self):
        paths = [
            r"C:\Windows\SoftwareDistribution\Download\huge.zip",
            r"C:\pagefile.sys",
            r"C:\Users\a\project\.git\objects\huge",
            r"C:\Users\a\OneDrive - Company\Downloads\huge.zip",
            r"C:\ProgramData\vendor\Cache\huge",
            r"C:\Program Files\Common Files\Cache\huge",
            r"C:\Program Files\Microsoft\Edge\Cache\huge",
            r"C:\Users\a\Documents\build\valuable.pdf",
            r"C:\Users\a\AppData\Local\Microsoft\OneNote\16.0\cache\unsynced",
        ]
        for path in paths:
            self.add(path, MINIMUM_BYTES * 3)
        self.assertEqual(analyze(self.db, self.report)["items"], [])

    def test_app_scope_absorbs_nested_caches(self):
        self.add(r"C:\Program Files\LargeApp\main.exe", MINIMUM_BYTES)
        self.add(r"C:\Program Files\LargeApp\Cache\contents", MINIMUM_BYTES)
        items = analyze(self.db, self.report)["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["rule"], "application")
        self.assertEqual(items[0]["bytes"], 2 * MINIMUM_BYTES)
        self.assertIn("Never delete Program Files", items[0]["steps"][-1])

    def test_disk_images_do_not_claim_unused_capacity(self):
        self.add(r"C:\Users\a\AppData\Local\Docker\ext4.vhdx", MINIMUM_BYTES)
        item = analyze(self.db, self.report)["items"][0]
        self.assertEqual(item["risk"], "review")
        self.assertIn("NOT an estimate of unused space", item["caution"])
        self.assertFalse(item["isDirectory"])

    def test_order_activity_and_partial_snapshot(self):
        self.add(r"C:\Users\a\Downloads\small.zip", MINIMUM_BYTES)
        self.add(r"C:\Users\a\Downloads\large.zip", MINIMUM_BYTES * 5, modified=1_999_999_999)
        self.report["scan"]["status"] = "cancelled"
        result = analyze(self.db, self.report)
        self.assertTrue(result["partial"])
        self.assertGreater(result["items"][0]["bytes"], result["items"][1]["bytes"])
        self.assertEqual(result["items"][0]["recentBytes"], MINIMUM_BYTES * 5)
        self.assertEqual(result["items"][1]["recentBytes"], 0)

    def test_unix_paths_and_component_boundaries(self):
        self.assertEqual(candidate_for("/home/a/project/node_modules/file", "Development", "Data"),
                         ("dependencies", "/home/a/project/node_modules", True))
        self.assertIsNone(candidate_for(r"C:\Users\a\Documents\cache-analysis.txt", "Personal files", "Documents"))


if __name__ == "__main__":
    unittest.main()
