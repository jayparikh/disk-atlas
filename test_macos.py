import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import nullcontext

from scanner import Inventory, MAC_SCAN_NOTE, UF_DATALESS, allocated_size, classify, fixed_drives, volume_usage


class MacPlatformTests(unittest.TestCase):
    def test_startup_discovery_and_shared_capacity(self):
        usage = SimpleNamespace(total=1000, used=20, free=600)
        with patch("scanner.IS_WINDOWS", False), patch("scanner.IS_MACOS", True), patch(
                "shutil.disk_usage", return_value=usage):
            self.assertEqual(fixed_drives(), [{"root": "/", "total": 1000, "free": 600, "used": 400}])
        with patch("scanner.IS_WINDOWS", False), patch("scanner.IS_MACOS", False), patch(
                "shutil.disk_usage", return_value=usage):
            self.assertEqual(volume_usage("/")["used"], 20)

    def test_mac_classification(self):
        cases = [
            ("/System/Library/CoreServices/file", "System & recovery", "macOS & Unix system files"),
            ("/usr/bin/tool", "System & recovery", "macOS & Unix system files"),
            ("/private/var/vm/swapfile0", "System & recovery", "Paging & hibernation"),
            ("/Applications/Example.app/Contents/Resources/logo.png", "Applications", "Application bundles"),
            ("/Users/Demo/Library/Application Support/Example/data", "Applications", "Per-user application data"),
            ("/Library/Application Support/Example/data", "Applications", "Shared application data"),
            ("/Users/Demo/Library/Caches/Homebrew/file", "Caches & temporary", "Application & package caches"),
            ("/Users/Demo/Library/Developer/Xcode/DerivedData/Example/build", "Development", "Xcode derived data"),
            ("/Users/Demo/.Trash/file", "Caches & temporary", "Trash"),
            ("/Users/Demo/Library/Mobile Documents/example/file", "Personal files", "Cloud documents"),
            ("/Users/Demo/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw", "Virtual machines", "Containers"),
            ("/System/Volumes/Data/Users/Demo/Library/Caches/Example/file", "Caches & temporary", "Application & package caches"),
        ]
        for path, category, subcategory in cases:
            with self.subTest(path=path):
                self.assertEqual(classify(path)[:2], (category, subcategory))
        for extension in ("dmg", "pkg"):
            self.assertEqual(classify("/Users/Demo/Downloads/example." + extension),
                             ("Personal files", "Downloads", "Installers"))

    @unittest.skipIf(os.name == "nt", "POSIX traversal and allocation")
    def test_sparse_files_symlinks_unicode_and_database_uri(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "source"
            root.mkdir()
            sparse = root / "sparse.bin"
            with sparse.open("wb") as file:
                file.seek(16 * 1024**2)
                file.write(b"x")
            (root / "caf\u00e9 # ?.txt").write_bytes(b"example")
            (root / "linked").symlink_to(root, target_is_directory=True)
            inventory = Inventory(base / "data # ?")
            inventory.start([str(root)])
            inventory.thread.join(10)
            self.assertEqual(inventory.status()["status"], "complete")
            report = inventory.report()
            self.assertEqual(report["scan"]["files"], 2)
            self.assertEqual(report["scan"]["reparse"], 1)
            self.assertLess(allocated_size(str(sparse), sparse.stat()), sparse.stat().st_size)
            self.assertEqual(inventory.files({"search": "caf\u00e9 # ?"})["count"], 1)
            self.assertEqual(Inventory(base / "data # ?").report(), report)

    @unittest.skipIf(os.name == "nt", "Simulated macOS namespace uses POSIX paths")
    def test_startup_firmlinks_mounts_cloud_permissions_and_data_alias(self):
        def metadata(device, inode, directory=False, flags=0):
            return SimpleNamespace(st_dev=device, st_ino=inode, st_nlink=1, st_size=100,
                                   st_blocks=8, st_mtime=1, st_flags=flags,
                                   st_mode=stat.S_IFDIR if directory else stat.S_IFREG)

        def entry(name, info):
            return SimpleNamespace(name=name, stat=lambda **kwargs: info,
                                   is_symlink=lambda: False,
                                   is_dir=lambda **kwargs: stat.S_ISDIR(info.st_mode),
                                   is_file=lambda **kwargs: stat.S_ISREG(info.st_mode))

        with tempfile.TemporaryDirectory() as directory:
            inventory = Inventory(Path(directory) / "data")
            data = os.stat(inventory.data_dir)
            folders = {
                "/": metadata(1, 1, True),
                "/System": metadata(1, 2, True),
                "/System/Volumes/Data": metadata(2, 1, True),
                "/Users": metadata(2, 2, True),
                "/Users/Demo": metadata(2, 7, True),
                "/Users/Demo/Denied": metadata(2, 3, True),
            }
            tree = {
                "/": [entry("System", folders["/System"]), entry("Users", folders["/Users"]),
                      entry("External", metadata(3, 1, True))],
                "/System": [entry("Volumes", metadata(1, 3, True))],
                "/Users": [entry("Demo", folders["/Users/Demo"])],
                "/Users/Demo": [entry("sample", metadata(2, 4)),
                           entry("cloud", metadata(2, 5, flags=UF_DATALESS)),
                           entry("cloud-folder", metadata(2, 6, True, UF_DATALESS)),
                           entry("Denied", folders["/Users/Demo/Denied"]),
                           entry("scanner-alias", data)],
            }
            real_stat = os.stat

            def file_stat(path, **kwargs):
                return folders[str(path)] if str(path) in folders else real_stat(path, **kwargs)

            def scandir(path):
                if path == "/Users/Demo/Denied":
                    raise PermissionError("Operation not permitted")
                self.assertIn(path, tree, "Excluded directory was traversed")
                return nullcontext(iter(tree[path]))

            with patch("scanner.IS_MACOS", True), patch("scanner.os.stat", side_effect=file_stat), patch(
                    "scanner.os.scandir", side_effect=scandir), patch("scanner.volume_usage", return_value={
                        "root": "/", "total": 100000, "free": 50000, "used": 50000}):
                inventory.start(["/"])
                inventory.thread.join(10)
            self.assertEqual(inventory.status()["status"], "complete")
            report = inventory.report()
            self.assertEqual(report["scan"]["files"], 1)
            self.assertEqual(report["allocated"], 4096)
            self.assertEqual(report["accountingNote"], MAC_SCAN_NOTE)
            self.assertEqual(report["issuesByReason"], {
                "Mounted filesystem": 1, "Cloud placeholder": 2, "Scanner data": 1,
                "Directory unavailable": 1, "APFS volume mirrors": 1,
            })
            self.assertEqual(inventory.files({})["rows"][0]["path"], "/Users/Demo/sample")

    @unittest.skipIf(os.name == "nt", "POSIX directory identities")
    def test_repeated_root_does_not_double_count(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "source"
            root.mkdir()
            (root / "example").write_bytes(b"example")
            inventory = Inventory(base / "data")
            inventory.start([str(root), str(root)])
            inventory.thread.join(10)
            self.assertEqual(inventory.status()["status"], "complete")
            self.assertEqual(inventory.report()["scan"]["files"], 1)
            self.assertEqual(inventory.report()["issuesByReason"], {"Repeated directory": 1})


if __name__ == "__main__":
    unittest.main()
