import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("check_release", Path(__file__).parent / "scripts" / "check_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseChecks(unittest.TestCase):
    def test_private_metadata_and_unexpected_images_are_rejected(self):
        self.assertTrue(release.check_file("data/inventory.sqlite", b"SQLite data"))
        self.assertTrue(release.check_file("export.json", b"{}"))
        self.assertTrue(release.check_file("private.png", b"not an image"))

    def test_only_synthetic_home_paths_are_accepted(self):
        prefix = "C:" + "\\" + "Users" + "\\"
        self.assertEqual(release.check_file("fixture.py", (prefix + "Demo\\sample.txt").encode()), [])
        self.assertTrue(release.check_file("fixture.py", (prefix + "private-person\\sample.txt").encode()))

    def test_possible_credentials_and_contact_details_are_rejected(self):
        self.assertTrue(release.check_file("config.py", ("ghp_" + "x" * 30).encode()))
        address = "private-person" + "@" + "example" + ".org"
        self.assertTrue(release.check_file("notes.txt", address.encode()))

    def test_screenshot_metadata_is_rejected(self):
        png = b"\x89PNG\r\n\x1a\n" + struct.pack(">I", 3) + b"tEXt" + b"PII" + b"\0" * 4
        self.assertTrue(release.check_file("docs/assets/demo.png", png))


if __name__ == "__main__":
    unittest.main()
