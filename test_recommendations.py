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

    def test_mac_candidates_use_app_scopes_and_mac_instructions(self):
        paths = [
            "/Applications/Example.app/Contents/MacOS/Example",
            "/Applications/Example.app/Contents/Resources/Cache/file",
            "/Users/Demo/.Trash/file",
            "/Users/Demo/Library/Caches/Homebrew/file",
            "/Users/Demo/Library/Caches/Example/file",
            "/Users/Demo/Library/Developer/Xcode/DerivedData/Example/Build/file",
            "/Users/Demo/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
            "/Users/Demo/Downloads/example.dmg",
        ]
        for path in paths:
            self.add(path, MINIMUM_BYTES)
        items = analyze(self.db, self.report)["items"]
        self.assertEqual(len(items), 7)
        app = next(item for item in items if item["rule"] == "mac-application")
        self.assertEqual(app["bytes"], 2 * MINIMUM_BYTES)
        self.assertEqual(app["path"], "/Applications/Example.app")
        self.assertEqual({item["rule"] for item in items}, {
            "mac-application", "mac-trash", "package-cache", "cache",
            "xcode-derived", "virtual-disk", "download",
        })
        self.assertNotIn("Windows Settings", str(items))

    def test_mac_sensitive_data_never_becomes_cache_candidates(self):
        for path in [
            "/System/Library/Caches/file",
            "/Library/Caches/file",
            "/private/var/folders/example/cache/file",
            "/usr/local/share/example/cache/file",
            "/Users/Demo/Library/Mobile Documents/example/Downloads/file",
            "/Users/Demo/Library/CloudStorage/Example/Cache/file",
            "/Users/Demo/Library/Mail/Cache/file",
            "/Users/Demo/Library/Containers/Example/Data/Cache/file",
            "/Users/Demo/Library/Developer/Xcode/Archives/Cache/file",
            "/Users/Demo/Pictures/Example.photoslibrary/Cache/file",
            "/Users/Demo/Downloads/Backup.sparsebundle/bands/0",
            "/Users/Demo/project/.git/Example.app/Cache/file",
        ]:
            with self.subTest(path=path):
                category, _, kind = classify(path)
                self.assertIsNone(candidate_for(path, category, kind))

    def test_posix_case_distinct_candidates_do_not_merge(self):
        for path in ("/Users/Demo/Downloads/A.dmg", "/Users/Demo/Downloads/a.dmg"):
            self.add(path, MINIMUM_BYTES)
        items = analyze(self.db, self.report)["items"]
        self.assertEqual(len(items), 2)
        self.assertEqual(len({item["id"] for item in items}), 2)

    def test_mac_trash_owns_bundles_and_project_library_is_not_user_library(self):
        self.assertEqual(candidate_for("/Users/Demo/.Trash/Example.app/Contents/file", "Applications", "Binaries"),
                         ("mac-trash", "/Users/Demo/.Trash", True))
        self.assertEqual(candidate_for("/Users/Demo/project/node_modules/library/Caches/file", "Development", "Data"),
                         ("dependencies", "/Users/Demo/project/node_modules", True))
        path = "/Users/Demo/Library/Developer/Xcode/DerivedData/Example/Build/Example.app/Contents/file"
        self.assertEqual(classify(path)[:2], ("Development", "Xcode derived data"))
        self.assertEqual(candidate_for(path, "Development", "Binaries"),
                         ("xcode-derived", "/Users/Demo/Library/Developer/Xcode/DerivedData/Example", True))


if __name__ == "__main__":
    unittest.main()
