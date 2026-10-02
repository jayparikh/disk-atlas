from http.server import ThreadingHTTPServer
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

from demo import create_demo_inventory
from scanner import Inventory, SCHEMA
from server import default_data_dir, make_handler


class DemoTests(unittest.TestCase):
    def test_synthetic_inventory_reconciles_without_scanning(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("scanner.os.scandir", side_effect=AssertionError("Demo attempted a scan")):
                inventory = create_demo_inventory(Path(directory))
            report = inventory.report()
            self.assertTrue(report["demo"])
            self.assertEqual(sum(row["bytes"] for row in report["taxonomy"]), report["allocated"])
            self.assertEqual(sum(age["bytes"] for age in report["ages"]), report["allocated"])
            self.assertEqual(report["used"] + report["free"], report["total"])
            self.assertEqual(report["used"] - report["allocated"], report["unaccounted"])
            files = inventory.files({})
            self.assertEqual(files["count"], report["scan"]["files"])
            tree = inventory.folder_tree(report["scan"]["roots"][0])
            self.assertEqual(tree["bytes"], report["allocated"])
            self.assertGreater(len(inventory.recommendations()["items"]), 0)
            for file in files["rows"]:
                self.assertNotIn(str(Path.home()), file["path"])

    def test_demo_api_never_enumerates_real_drives_and_rejects_scans(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = create_demo_inventory(Path(directory))
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(inventory, "demo-token", 0, True))
            port = server.server_address[1]
            server.RequestHandlerClass = make_handler(inventory, "demo-token", port, True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            headers = {"X-Atlas-Token": "demo-token"}
            try:
                with patch("server.fixed_drives", side_effect=AssertionError("Real drives were enumerated")):
                    for endpoint in ("status", "drives", "report", "recommendations"):
                        with urlopen(Request(f"http://127.0.0.1:{port}/api/{endpoint}", headers=headers), timeout=5) as response:
                            result = json.load(response)
                            if endpoint in {"status", "report"}:
                                self.assertTrue(result["demo"])
                    for endpoint in ("scan", "cancel"):
                        with self.assertRaises(HTTPError) as error:
                            urlopen(Request(f"http://127.0.0.1:{port}/api/{endpoint}", headers=headers, data=b"{}"), timeout=5)
                        self.assertEqual(error.exception.code, 403)
                        error.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_default_storage_is_outside_source(self):
        directory = default_data_dir()
        self.assertTrue(directory.is_absolute())
        self.assertFalse(directory.is_relative_to(Path(__file__).resolve().parent))
        if os.name == "nt":
            self.assertEqual(directory.name, "DiskAtlas")

    def test_posix_root_navigation_keeps_absolute_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = Inventory(Path(directory))
            with sqlite3.connect(inventory.database) as db:
                db.executescript(SCHEMA)
                db.execute("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)",
                           ("/demo/Users/Demo/file.txt", "/demo/Users/Demo", "Personal files",
                            "Documents", "Documents", 4096, 4096, 0, 0))
            db.close()
            with patch("scanner.IS_WINDOWS", False):
                self.assertEqual(inventory.folders("")[0]["path"], "/demo/")
                tree = inventory.folder_tree("")
                self.assertEqual(tree["children"][0]["path"], "/demo/")
                self.assertEqual(tree["children"][0]["children"][0]["path"], "/demo/Users/")


if __name__ == "__main__":
    unittest.main()
