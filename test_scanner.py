import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer

from scanner import Inventory, allocated_size, classify
from recommendations import analyze
from server import make_handler


class TaxonomyTests(unittest.TestCase):
    def test_path_priority_and_file_types(self):
        cases = [
            (r"C:\Windows\WinSxS\foo.dll", ("System & recovery", "Component store", "Binaries")),
            (r"C:\pagefile.sys", ("System & recovery", "Paging & hibernation", "Binaries")),
            (r"C:\Users\a\project\node_modules\a\package.json", ("Development", "Dependencies & environments", "Data")),
            (r"C:\Users\a\.ollama\models\blob", ("AI & models", "Model weights & assets", "No extension")),
            (r"C:\Users\a\AppData\Local\Docker\disk.vhdx", ("Virtual machines", "Containers", "Virtual disks")),
            (r"C:\Program Files\Acme\logo.png", ("Applications", "Installed applications", "Images")),
            (r"C:\Users\a\Downloads\video.mp4", ("Personal files", "Downloads", "Video")),
            (r"C:\Users\a\project\.git\objects\file", ("Development", "Git history", "No extension")),
            (r"C:\Users\a\AppData\Local\Acme\Cache\entry", ("Caches & temporary", "Application & package caches", "No extension")),
            (r"C:\something.unknown", ("Other", "Unclassified files", ".unknown")),
        ]
        for path, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(classify(path), expected)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "source"
        self.root.mkdir()
        self.inventory = Inventory(self.base / "data")

    def tearDown(self):
        self.temp.cleanup()

    def scan(self):
        self.inventory.start([str(self.root)])
        self.inventory.thread.join(timeout=20)
        self.assertFalse(self.inventory.thread.is_alive())
        self.assertEqual(self.inventory.status()["status"], "complete")
        return self.inventory.report()

    def test_allocation_hardlinks_taxonomy_search_and_persistence(self):
        source = self.root / "a.bin"
        source.write_bytes(b"a" * 12000)
        os.link(source, self.root / "b.bin")
        nested = self.root / "100%_real"
        nested.mkdir()
        other = nested / "report.pdf"
        other.write_bytes(b"c" * 6000)
        expected = allocated_size(str(source), source.stat()) + allocated_size(str(other), other.stat())
        report = self.scan()
        self.assertEqual(report["allocated"], expected)
        self.assertEqual(report["logical"], 30000)
        self.assertEqual(report["scan"]["hardlinks"], 1)
        self.assertEqual(report["scan"]["files"], 3)
        self.assertEqual(sum(row["bytes"] for row in report["taxonomy"]), expected)
        self.assertEqual(sum(row["bytes"] for row in report["ages"]), expected)
        self.assertEqual(self.inventory.files({"search": "100%_"})["count"], 1)
        self.assertEqual(self.inventory.files({"search": "' OR 1=1 --"})["count"], 0)
        self.assertEqual(self.inventory.files({"parent": str(self.root)})["count"], 2)
        self.assertEqual(self.inventory.files({"path": str(source)})["count"], 1)
        children = self.inventory.folders(str(self.root) + os.sep)
        self.assertEqual(sum(child["bytes"] for child in children), expected)
        self.assertEqual(len(children), 2)
        nested_tree = self.inventory.folder_tree(str(self.root) + os.sep, 3)
        self.assertEqual(nested_tree["bytes"], expected)
        self.assertEqual(nested_tree["files"], 3)
        self.assertEqual(sum(child["bytes"] for child in nested_tree["children"]), expected)
        nested_folder = next(child for child in nested_tree["children"] if not child["direct"])
        self.assertEqual(nested_folder["name"], "100%_real")
        self.assertTrue(nested_folder["children"][0]["direct"])
        self.assertEqual(nested_folder["children"][0]["files"], 1)
        self.assertEqual(self.inventory.folder_tree(str(self.root), 1)["bytes"], expected)
        with self.assertRaises(ValueError):
            self.inventory.folder_tree("", 10)
        self.assertEqual(Inventory(self.base / "data").report()["allocated"], expected)

    def test_unknown_allocation_not_estimated(self):
        (self.root / "sample.bin").write_bytes(b"a" * 5000)
        with patch("scanner.allocated_size", side_effect=PermissionError("denied")):
            report = self.scan()
        self.assertEqual(report["allocated"], 0)
        self.assertEqual(report["scan"]["unmeasuredLogical"], 5000)
        self.assertEqual(report["scan"]["allocationFailures"], 1)
        self.assertEqual(self.inventory.issues()["count"], 1)

    def test_empty_scan_and_cancelled_scan(self):
        report = self.scan()
        self.assertEqual(report["allocated"], 0)
        self.assertEqual(report["scan"]["files"], 0)
        self.inventory.cancel_event.set()
        self.inventory._scan([str(self.root)])
        self.assertEqual(self.inventory.report()["scan"]["status"], "cancelled")

    def test_failed_scan_preserves_prior_snapshot(self):
        self.scan()
        with self.assertLogs("disk-atlas", level="ERROR"), patch("scanner.volume_usage", side_effect=OSError("drive offline")):
            self.inventory.start([str(self.root)])
            self.inventory.thread.join(timeout=10)
        self.assertEqual(self.inventory.status()["status"], "error")
        self.assertEqual(self.inventory.report()["scan"]["status"], "complete")

    def test_reparse_point_is_not_followed(self):
        (self.root / "sample.bin").write_bytes(b"a" * 100)
        with patch("scanner.REPARSE_POINT", 0x20):
            report = self.scan()
        if os.name == "nt":
            self.assertEqual(report["scan"]["files"], 0)
            self.assertEqual(report["scan"]["reparse"], 1)

    def test_rescan_replaces_snapshot_after_reads(self):
        (self.root / "first.bin").write_bytes(b"a" * 12000)
        self.scan()
        self.inventory.files({})
        self.inventory.folders(str(self.root) + os.sep)
        self.inventory.folder_tree(str(self.root))
        self.inventory.issues()
        (self.root / "second.bin").write_bytes(b"b" * 16000)
        report = self.scan()
        self.assertEqual(report["scan"]["files"], 2)
        self.assertEqual(self.inventory.folder_tree(str(self.root))["files"], 2)

    def test_busy_scan_rejected(self):
        gate = threading.Event()
        with patch.object(self.inventory, "_scan", side_effect=lambda roots: gate.wait(3)):
            self.inventory.start([str(self.root)])
            try:
                with self.assertRaisesRegex(ValueError, "already running"):
                    self.inventory.start([str(self.root)])
            finally:
                gate.set()
                self.inventory.thread.join(timeout=5)

    def test_recommendations_cache_is_persisted_and_invalidated_on_rescan(self):
        self.scan()
        with patch("scanner.analyze", wraps=analyze) as build:
            first = self.inventory.recommendations()
            self.inventory.recommendations()
            restored = Inventory(self.base / "data")
            self.assertEqual(restored.recommendations(), first)
            self.assertEqual(build.call_count, 1)
            self.scan()
            refreshed = self.inventory.recommendations()
            self.assertNotEqual(refreshed["snapshot"], first["snapshot"])
            self.assertEqual(build.call_count, 2)
        with self.assertRaises(ValueError):
            self.inventory.recommendations(100)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        inventory = Inventory(Path(self.temp.name) / "data")
        self.inventory = inventory
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(inventory, "test-token", 0))
        self.port = self.server.server_address[1]
        self.server.RequestHandlerClass = make_handler(inventory, "test-token", self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path, headers=None, data=None):
        return urlopen(Request(f"http://127.0.0.1:{self.port}{path}", headers=headers or {}, data=data), timeout=5)

    def test_authenticated_status_and_html(self):
        with self.request("/api/status", {"X-Atlas-Token": "test-token"}) as result:
            self.assertEqual(json.load(result)["status"], "idle")
        with self.request("/") as result:
            self.assertIn(b'const TOKEN = "test-token"', result.read())

    def test_missing_token_origin_and_host_rejected(self):
        for headers in ({}, {"X-Atlas-Token": "wrong"},
                        {"X-Atlas-Token": "test-token", "Origin": "https://untrusted.invalid"},
                        {"X-Atlas-Token": "test-token", "Host": "untrusted.invalid"}):
            with self.subTest(headers=headers), self.assertRaises(HTTPError) as error:
                self.request("/api/status", headers)
            self.assertEqual(error.exception.code, 403)

    def test_scan_rejects_arbitrary_paths_and_json_arrays(self):
        for payload in ({"roots": [r"C:\Users"]}, []):
            with self.subTest(payload=payload), self.assertRaises(HTTPError) as error:
                self.request("/api/scan", {"X-Atlas-Token": "test-token"}, json.dumps(payload).encode())
            self.assertEqual(error.exception.code, 400)

    def test_recommendations_api_threshold_and_authentication(self):
        root = Path(self.temp.name) / "source"
        root.mkdir()
        self.inventory.start([str(root)])
        self.inventory.thread.join(timeout=10)
        with self.request("/api/recommendations", {"X-Atlas-Token": "test-token"}) as response:
            result = json.load(response)
            self.assertEqual(result["minimumBytes"], 256 * 1024**2)
            self.assertEqual(result["items"], [])
        for minimum in ("1", "-100", "not-a-number"):
            with self.assertRaises(HTTPError) as error:
                self.request("/api/recommendations?minimum=" + minimum, {"X-Atlas-Token": "test-token"})
            self.assertEqual(error.exception.code, 400)
        with self.assertRaises(HTTPError) as error:
            self.request("/api/recommendations")
        self.assertEqual(error.exception.code, 403)


if __name__ == "__main__":
    unittest.main()
