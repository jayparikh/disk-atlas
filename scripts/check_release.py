"""Check Git-indexed release files for private artifacts and common PII patterns."""

from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_SIZE = 5 * 1024**2
SYNTHETIC_USERS = {"a", "demo", "example", "test", "user", "username"}
HOME_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/]+Users[\\/]+|/Users/|/home/)([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|"
    r"AKIA[A-Z0-9]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"
)


def check_file(name, data):
    findings = []
    path = PurePosixPath(name)
    if (any(part in {"data", "exports", "reports", "screenshots", "__pycache__", ".env"}
            for part in path.parts)
            or path.suffix.lower() in {".sqlite", ".db", ".log", ".pyc", ".zip", ".json", ".tmp"}
            or ".sqlite-" in name or ".db-" in name or path.name.startswith(".env")):
        findings.append("runtime or private artifact is indexed")
    if len(data) > MAX_FILE_SIZE:
        findings.append("file exceeds the release size limit")
    if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
        if name != "docs/assets/demo.png":
            findings.append("only the synthetic demo screenshot is permitted")
        if path.suffix.lower() == ".png":
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                findings.append("invalid PNG signature")
                return findings
            offset = 8
            while offset + 12 <= len(data):
                length = struct.unpack(">I", data[offset:offset + 4])[0]
                kind = data[offset + 4:offset + 8]
                if kind in {b"tEXt", b"zTXt", b"iTXt", b"eXIf"}:
                    findings.append("PNG contains textual or EXIF metadata")
                if offset + length + 12 > len(data):
                    findings.append("truncated PNG chunk")
                    break
                offset += length + 12
        return findings
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        findings.append("unexpected binary file")
        return findings
    for number, line in enumerate(text.splitlines(), 1):
        if any(match.group(1).lower() not in SYNTHETIC_USERS for match in HOME_PATH.finditer(line)):
            findings.append(f"line {number}: non-synthetic home directory")
        if EMAIL.search(line):
            findings.append(f"line {number}: email address requires review")
        if SECRET.search(line):
            findings.append(f"line {number}: possible credential material")
    return findings


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.PIPE)


def main():
    try:
        names = [name for name in git("ls-files", "-z").decode("utf-8").split("\0") if name]
        if not names:
            print("No indexed files. Stage the intended source files before checking.", file=sys.stderr)
            return 1
        failures = []
        for name in names:
            size = int(git("cat-file", "-s", ":" + name))
            if size > MAX_FILE_SIZE:
                failures.append(f"{name}: file exceeds the release size limit")
                continue
            for finding in check_file(name, git("show", ":" + name)):
                failures.append(f"{name}: {finding}")
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"Release check could not complete: {error}", file=sys.stderr)
        return 1
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Release check passed for {len(names)} Git-indexed files. Review the staged diff before publishing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
