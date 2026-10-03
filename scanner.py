"""Read-only disk inventory. File contents are never opened or hashed."""

from __future__ import annotations

import ctypes
from contextlib import contextmanager
import json
import logging
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time

from recommendations import MINIMUM_BYTES, RULE_VERSION, analyze

LOG = logging.getLogger("disk-atlas")
IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
REPARSE_POINT = 0x400
UF_DATALESS = 0x40000000
MAC_DATA_ROOT = "/System/Volumes/Data"
MAC_SCAN_NOTE = (
    "macOS scans the startup filesystem through its normal paths, including /Users "
    "and /Applications. /System/Volumes mirrors and other mounted filesystems are "
    "excluded. APFS capacity is shared: used space can include other volumes and "
    "snapshots that were not scanned. Per-file allocation cannot distinguish shared "
    "clone extents, so totals and cleanup candidates are not guaranteed savings. "
    "Protected folders are reported as inaccessible. If needed, grant Full Disk "
    "Access to the terminal or app launching Disk Atlas in System Settings > "
    "Privacy & Security, then restart it and rescan. Permissions are never bypassed."
)

if IS_WINDOWS:
    from ctypes import wintypes

    KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
    KERNEL.GetLogicalDrives.restype = wintypes.DWORD
    KERNEL.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    KERNEL.GetDriveTypeW.restype = wintypes.UINT
    KERNEL.GetCompressedFileSizeW.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)
    ]
    KERNEL.GetCompressedFileSizeW.restype = wintypes.DWORD
    KERNEL.GetDiskFreeSpaceExW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.POINTER(ctypes.c_ulonglong),
    ]
    KERNEL.GetDiskFreeSpaceExW.restype = wintypes.BOOL


def native_path(path: str) -> str:
    if IS_WINDOWS and not path.startswith("\\\\?\\"):
        return "\\\\?\\" + os.path.abspath(path)
    return path


def volume_usage(root: str) -> dict:
    if IS_WINDOWS:
        available, total, free = (ctypes.c_ulonglong() for _ in range(3))
        if not KERNEL.GetDiskFreeSpaceExW(
            root, ctypes.byref(available), ctypes.byref(total), ctypes.byref(free)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"root": root, "total": total.value, "free": free.value,
                "used": total.value - free.value}
    import shutil
    usage = shutil.disk_usage(root)
    # APFS's per-volume used blocks exclude sibling volumes sharing this capacity.
    used = usage.total - usage.free if IS_MACOS else usage.used
    return {"root": root, "total": usage.total, "free": usage.free, "used": used}


def fixed_drives() -> list[dict]:
    if not IS_WINDOWS:
        return [volume_usage("/")]
    mask = KERNEL.GetLogicalDrives()
    drives = []
    for index in range(26):
        root = chr(65 + index) + ":\\"
        if mask & (1 << index) and KERNEL.GetDriveTypeW(root) == 3:
            drives.append(volume_usage(root))
    return drives


def allocated_size(path: str, stat: os.stat_result) -> int:
    if not IS_WINDOWS:
        return stat.st_blocks * 512
    high = wintypes.DWORD()
    ctypes.set_last_error(0)
    low = KERNEL.GetCompressedFileSizeW(native_path(path), ctypes.byref(high))
    error = ctypes.get_last_error()
    if low == 0xFFFFFFFF and error:
        raise ctypes.WinError(error)
    return (high.value << 32) | low


EXTENSIONS = {
    "Images": set("jpg jpeg png gif webp heic heif avif tiff tif bmp raw cr2 nef svg ico".split()),
    "Video": set("mp4 mov mkv avi webm m4v mpg mpeg wmv mts".split()),
    "Audio": set("mp3 wav flac aac m4a ogg aiff wma".split()),
    "Documents": set("pdf doc docx xls xlsx ppt pptx txt rtf md csv tsv epub odt one".split()),
    "Archives": set("zip 7z rar tar gz bz2 xz zst cab".split()),
    "Installers": set("msi msix appx appxbundle msixbundle msp dmg pkg".split()),
    "Virtual disks": set("vhd vhdx vmdk vdi qcow qcow2 iso img wim esd sparseimage sparsebundle".split()),
    "Source code": set("py js ts tsx jsx c cpp h hpp cs go rs java rb php swift kt html css scss vue svelte ipynb".split()),
    "Data": set("db sqlite sqlite3 parquet arrow duckdb mdf ldf bak sql json xml yaml yml toml".split()),
    "Models": set("gguf safetensors onnx pt pth ckpt h5 hdf5".split()),
    "Binaries": set("exe dll sys pdb lib obj o a so dylib wasm".split()),
}
EXT_LOOKUP = {ext: group for group, exts in EXTENSIONS.items() for ext in exts}
CATEGORIES = [
    "System & recovery", "Applications", "Development", "AI & models",
    "Virtual machines", "Personal files", "Caches & temporary", "Other",
]


def classify(path: str) -> tuple[str, str, str]:
    parts = path.lower().split("/") if path.startswith("/") else path.replace("/", "\\").lower().split("\\")
    name = parts[-1]
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    kind = EXT_LOOKUP.get(ext, ("." + ext) if ext else "No extension")
    # Purpose takes precedence over extension: a photo shipped with an app is app data.
    if path.startswith("/"):
        posix = path.lower().split("/")
        if posix[:4] == ["", "system", "volumes", "data"]:
            posix = ["", *posix[4:]]
        if posix[1:2] in (["system"], ["bin"], ["sbin"], ["usr"]) and posix[1:3] != ["usr", "local"]:
            return "System & recovery", "macOS & Unix system files", kind
        if posix[1:3] == ["private", "var"] or posix[1:2] == ["var"]:
            if "vm" in posix[2:4]:
                return "System & recovery", "Paging & hibernation", kind
        if ".trash" in posix or ".trashes" in posix:
            return "Caches & temporary", "Trash", kind
        if "com.docker.docker" in posix and name in {"docker.raw", "docker.qcow2"}:
            return "Virtual machines", "Containers", "Virtual disks"
        library = 1 if posix[1:2] == ["library"] else (
            3 if posix[1:2] == ["users"] and posix[3:4] == ["library"] else None)
        if library is not None:
            tail = posix[library + 1:]
            if tail[:3] == ["developer", "xcode", "deriveddata"]:
                return "Development", "Xcode derived data", kind
            if tail[:1] == ["caches"]:
                return "Caches & temporary", "Application & package caches", kind
            if tail[:1] in (["mobile documents"], ["cloudstorage"]):
                return "Personal files", "Cloud documents", kind
            return "Applications", "Shared application data" if library == 1 else "Per-user application data", kind
        if any(part.endswith(".app") for part in posix[:-1]):
            return "Applications", "Application bundles", kind
        if posix[1:3] == ["private", "var"] or posix[1:2] == ["var"]:
            return "System & recovery", "macOS & Unix system data", kind
    if "$recycle.bin" in parts:
        return "Caches & temporary", "Recycle bin", kind
    if name in {"pagefile.sys", "hiberfil.sys", "swapfile.sys"}:
        return "System & recovery", "Paging & hibernation", kind
    if "windows" in parts[:3]:
        sub = "Component store" if "winsxs" in parts else (
            "Update downloads" if "softwaredistribution" in parts else "Windows")
        return "System & recovery", sub, kind
    if any(p in parts[:3] for p in ("recovery", "system volume information", "$windows.~bt")):
        return "System & recovery", "Recovery & restore", kind
    if kind == "Models" or any(p in parts for p in (".ollama", "huggingface", ".lmstudio")):
        return "AI & models", "Model weights & assets", kind
    if kind == "Virtual disks" or any(p in parts for p in ("docker", ".docker", "wsl", "virtualbox vms")):
        return "Virtual machines", "Containers" if any("docker" in p for p in parts) else "Disk images & VMs", kind
    if any(p in parts for p in ("node_modules", ".venv", "venv", "site-packages", ".nuget", ".cargo", ".gradle")):
        return "Development", "Dependencies & environments", kind
    if ".git" in parts:
        return "Development", "Git history", kind
    if any(p in parts for p in ("cache", "caches", ".cache", "code cache", "gpucache", ".npm", ".pnpm-store")):
        return "Caches & temporary", "Application & package caches", kind
    if any(p in parts for p in ("temp", "tmp")) or ext in {"tmp", "temp", "dmp"}:
        return "Caches & temporary", "Temporary files & dumps", kind
    if "program files" in parts[:3] or "program files (x86)" in parts[:3]:
        return "Applications", "Installed applications", kind
    if "programdata" in parts[:3]:
        return "Applications", "Shared application data", kind
    if "appdata" in parts:
        return "Applications", "Per-user application data", kind
    if any(p in parts for p in ("bin", "obj", "target", ".next", ".turbo", "build", "dist")):
        return "Development", "Build outputs", kind
    if kind == "Source code":
        return "Development", "Source & notebooks", kind
    if "downloads" in parts:
        return "Personal files", "Downloads", kind
    if kind in {"Images", "Video", "Audio", "Documents", "Archives", "Installers", "Data"}:
        return "Personal files", kind, kind
    if "users" in parts or "home" in parts:
        return "Personal files", "Other user files", kind
    return "Other", "Unclassified files", kind


SCHEMA = """
CREATE TABLE files(
    path TEXT PRIMARY KEY, parent TEXT NOT NULL, category TEXT NOT NULL,
    subcategory TEXT NOT NULL, kind TEXT NOT NULL, logical INTEGER NOT NULL,
    allocated INTEGER NOT NULL, modified REAL NOT NULL, hardlink INTEGER NOT NULL
);
CREATE TABLE issues(path TEXT, reason TEXT, detail TEXT);
CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT);
"""


class Inventory:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self.database = data_dir / "inventory.sqlite"
        self.lock = threading.RLock()
        self.cancel_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.recommendation_cache: dict | None = None
        self.folder_tree_cache: dict = {}
        self.state: dict = {"status": "idle", "files": 0, "directories": 0,
                            "allocated": 0, "logical": 0, "issues": 0,
                            "current": "", "started": None}
        if self.database.exists():
            with self.connect() as db:
                row = db.execute("SELECT value FROM metadata WHERE key='report'").fetchone()
            if row:
                report = json.loads(row[0])
                self.state = {**report["scan"], "status": report["scan"]["status"]}

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database.resolve().as_uri() + "?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def status(self) -> dict:
        with self.lock:
            return {**self.state, "hasReport": self.database.exists()}

    def start(self, roots: list[str]):
        with self.lock:
            if self.thread is not None and self.thread.is_alive():
                raise ValueError("A scan is already running.")
            if not roots:
                raise ValueError("Select at least one drive.")
            self.cancel_event.clear()
            self.state = {"status": "scanning", "files": 0, "directories": 0,
                          "allocated": 0, "logical": 0, "issues": 0, "current": "",
                          "started": time.time(), "roots": roots}
            self.thread = threading.Thread(target=self._run, args=(roots,), daemon=True)
            self.thread.start()

    def cancel(self):
        self.cancel_event.set()

    def _run(self, roots: list[str]):
        try:
            self._scan(roots)
        except (OSError, sqlite3.Error, ValueError) as error:
            LOG.exception("Scan failed")
            with self.lock:
                self.state.update(status="error", error=str(error), finished=time.time())

    def _scan(self, roots: list[str]):
        temporary = self.data_dir / "scanning.sqlite"
        if temporary.exists():
            temporary.unlink()
        db = sqlite3.connect(temporary)
        try:
            db.executescript(SCHEMA)
            db.execute("PRAGMA journal_mode=OFF")
            db.execute("PRAGMA synchronous=OFF")
            start_volumes = [volume_usage(root) for root in roots]
            stack = []
            for root in reversed(roots):
                devices = {os.stat(native_path(root)).st_dev}
                if IS_MACOS and root == "/" and os.path.isdir(MAC_DATA_ROOT):
                    devices.add(os.stat(MAC_DATA_ROOT).st_dev)
                stack.append((root, devices))
            data_identity = os.stat(self.data_dir)
            data_identity = (data_identity.st_dev, data_identity.st_ino)
            seen_directories: set[tuple[int, int]] = set()
            seen_links: set[tuple[int, int]] = set()
            categories: dict[tuple[str, str, str], list[int]] = {}
            ages = [{"label": label, "bytes": 0, "files": 0} for label in
                    ("Last 30 days", "1–6 months", "6–12 months", "Over a year")]
            counters = {"files": 0, "directories": 0, "allocated": 0, "logical": 0,
                        "issues": 0, "hardlinks": 0, "reparse": 0,
                        "allocationFailures": 0, "unmeasuredLogical": 0}
            issues_by_reason: dict[str, int] = {}
            batch = []
            last_update = 0.0
            now = time.time()

            def issue(path: str, reason: str, detail: str):
                counters["issues"] += 1
                issues_by_reason[reason] = issues_by_reason.get(reason, 0) + 1
                db.execute("INSERT INTO issues VALUES(?,?,?)", (path, reason, detail))

            while stack and not self.cancel_event.is_set():
                folder, devices = stack.pop()
                try:
                    folder_stat = os.stat(native_path(folder), follow_symlinks=False)
                    identity = (folder_stat.st_dev, folder_stat.st_ino)
                    if not IS_WINDOWS and identity in seen_directories:
                        issue(folder, "Repeated directory", "Skipped an already visited filesystem directory.")
                        continue
                    seen_directories.add(identity)
                    with os.scandir(native_path(folder)) as entries:
                        counters["directories"] += 1
                        for entry in entries:
                            if self.cancel_event.is_set():
                                break
                            path = os.path.join(folder, entry.name)
                            # Do not inventory our growing database.
                            if os.path.normcase(path) == os.path.normcase(str(self.data_dir)):
                                issue(path, "Scanner data", "Excluded the scanner's own database directory.")
                                continue
                            try:
                                stat = entry.stat(follow_symlinks=False)
                                if (stat.st_dev, stat.st_ino) == data_identity:
                                    issue(path, "Scanner data", "Excluded the scanner's own database directory.")
                                    continue
                                if entry.is_symlink() or getattr(stat, "st_file_attributes", 0) & REPARSE_POINT:
                                    counters["reparse"] += 1
                                    issue(path, "Reparse point", "Skipped link, junction or cloud placeholder; no target followed.")
                                    continue
                                if IS_MACOS and getattr(stat, "st_flags", 0) & UF_DATALESS:
                                    issue(path, "Cloud placeholder", "Skipped dataless cloud content; no hydration requested.")
                                    continue
                                if entry.is_dir(follow_symlinks=False):
                                    if IS_MACOS and path == "/System/Volumes":
                                        issue(path, "APFS volume mirrors", "Skipped mirrored Data paths and auxiliary volumes; startup files are scanned through their normal paths.")
                                    elif not IS_WINDOWS and stat.st_dev not in devices:
                                        issue(path, "Mounted filesystem", "Outside this scan root's filesystem; target not traversed.")
                                    else:
                                        stack.append((path, devices))
                                    continue
                                if not entry.is_file(follow_symlinks=False):
                                    issue(path, "Special file", "Not a regular file.")
                                    continue
                                # Windows DirEntry.stat omits file identity. os.stat supplies it.
                                if IS_WINDOWS:
                                    stat = os.stat(native_path(path), follow_symlinks=False)
                                duplicate = False
                                identity = (stat.st_dev, stat.st_ino)
                                if stat.st_nlink > 1 and stat.st_ino:
                                    duplicate = identity in seen_links
                                try:
                                    physical = 0 if duplicate else allocated_size(path, stat)
                                except OSError as error:
                                    counters["allocationFailures"] += 1
                                    counters["unmeasuredLogical"] += stat.st_size
                                    issue(path, "Allocation unavailable", str(error))
                                    # Unknown bytes are not guessed from logical size.
                                    physical = 0
                                else:
                                    if stat.st_nlink > 1 and stat.st_ino:
                                        seen_links.add(identity)
                                if duplicate:
                                    counters["hardlinks"] += 1
                                category, subcategory, kind = classify(path)
                                batch.append((path, folder, category, subcategory, kind,
                                              stat.st_size, physical, stat.st_mtime, int(duplicate)))
                                bucket = categories.setdefault((category, subcategory, kind), [0, 0, 0])
                                bucket[0] += physical
                                bucket[1] += stat.st_size
                                bucket[2] += 1
                                age_days = max(0, (now - stat.st_mtime) / 86400)
                                age_index = 0 if age_days < 30 else (1 if age_days < 183 else (2 if age_days < 365 else 3))
                                ages[age_index]["bytes"] += physical
                                ages[age_index]["files"] += 1
                                counters["files"] += 1
                                counters["logical"] += stat.st_size
                                counters["allocated"] += physical
                            except OSError as error:
                                issue(path, "Metadata unavailable", str(error))
                            if len(batch) >= 2000:
                                db.executemany("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)", batch)
                                db.commit()
                                batch.clear()
                            if time.monotonic() - last_update > 0.25:
                                with self.lock:
                                    self.state.update(counters, current=folder)
                                last_update = time.monotonic()
                except OSError as error:
                    issue(folder, "Directory unavailable", str(error))

            if batch:
                db.executemany("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)", batch)
            with self.lock:
                self.state.update(counters, current="", status="finalizing")
            db.executescript("""
                CREATE INDEX files_size ON files(allocated DESC);
                CREATE INDEX files_taxonomy ON files(category, subcategory, kind);
                CREATE INDEX files_parent ON files(parent COLLATE NOCASE);
            """)
            volumes = [volume_usage(root) for root in roots]
            used = sum(volume["used"] for volume in volumes)
            scan = {**self.state, **counters,
                    "status": "cancelled" if self.cancel_event.is_set() else "complete",
                    "finished": time.time(), "current": ""}
            report = {"scan": scan, "volumes": volumes, "volumesAtStart": start_volumes,
                      "allocated": counters["allocated"], "logical": counters["logical"],
                      "used": used, "free": sum(v["free"] for v in volumes),
                      "total": sum(v["total"] for v in volumes),
                      "unaccounted": max(0, used - counters["allocated"]),
                      "overcount": max(0, counters["allocated"] - used),
                      "issuesByReason": issues_by_reason,
                      "taxonomy": [{"category": key[0], "subcategory": key[1], "kind": key[2],
                                    "bytes": value[0], "logical": value[1], "files": value[2]}
                                   for key, value in categories.items()],
                      "ages": ages, "platform": sys.platform,
                      "accountingNote": MAC_SCAN_NOTE if IS_MACOS else ""}
            db.execute("INSERT INTO metadata VALUES('report', ?)", (json.dumps(report),))
            db.commit()
        finally:
            db.close()
        with self.lock:
            os.replace(temporary, self.database)
            self.state = scan
            self.folder_tree_cache.clear()
        LOG.info("Scan %s: %s files; %.2f GiB allocated; %s exclusions/errors",
                 scan["status"], counters["files"], counters["allocated"] / 1024**3, counters["issues"])

    def report(self) -> dict | None:
        with self.lock:
            if not self.database.exists():
                return None
            with self.connect() as db:
                return json.loads(db.execute("SELECT value FROM metadata WHERE key='report'").fetchone()[0])

    @staticmethod
    def filters(params: dict) -> tuple[str, list]:
        conditions, values = [], []
        for field in ("category", "subcategory", "kind", "parent", "path"):
            if params.get(field):
                conditions.append(f"{field}=?")
                values.append(params[field])
        if params.get("search"):
            term = params["search"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("path LIKE ? ESCAPE '\\'")
            values.append("%" + term + "%")
        if params.get("folder"):
            prefix = params["folder"]
            separator = "/" if prefix.startswith("/") else "\\"
            if not prefix.endswith(separator):
                prefix += separator
            collation = "BINARY" if separator == "/" else "NOCASE"
            conditions.append(f"SUBSTR(path,1,?)=? COLLATE {collation}")
            values.extend((len(prefix), prefix))
        return (" WHERE " + " AND ".join(conditions) if conditions else ""), values

    def files(self, params: dict) -> dict:
        where, values = self.filters(params)
        page = max(0, min(1000000, int(params.get("page", 0))))
        with self.lock, self.connect() as db:
            total = db.execute("SELECT COUNT(*),COALESCE(SUM(allocated),0) FROM files" + where, values).fetchone()
            rows = db.execute(
                "SELECT * FROM files" + where + " ORDER BY allocated DESC,path LIMIT 60 OFFSET ?",
                [*values, page * 60]).fetchall()
        return {"rows": [dict(row) for row in rows], "count": total[0], "bytes": total[1], "page": page}

    def folders(self, prefix: str) -> list[dict]:
        separator = "\\" if IS_WINDOWS else "/"
        if not prefix and not IS_WINDOWS:
            prefix = separator
        if prefix and not prefix.endswith(separator):
            prefix += separator
        where, values = self.filters({"folder": prefix})
        with self.lock, self.connect() as db:
            rows = db.execute("""
                WITH tails AS (
                    SELECT SUBSTR(path,?) AS tail,allocated FROM files
            """ + where + """),
                groups AS (
                    SELECT CASE WHEN INSTR(tail,?)=0 THEN '' ELSE
                        SUBSTR(tail,1,INSTR(tail,?)) END AS name,allocated FROM tails)
                SELECT name,SUM(allocated) AS bytes,COUNT(*) AS files
                FROM groups GROUP BY name ORDER BY bytes DESC
            """, [len(prefix) + 1, *values, separator, separator]).fetchall()
        return [{"name": row["name"].rstrip(separator) or "Files in this folder",
                 "path": prefix + row["name"], "bytes": row["bytes"], "files": row["files"],
                 "direct": not bool(row["name"])} for row in rows]

    def issues(self) -> dict:
        with self.lock, self.connect() as db:
            rows = db.execute("SELECT * FROM issues LIMIT 150").fetchall()
            count = db.execute("SELECT COUNT(*) FROM issues").fetchone()[0]
        return {"rows": [dict(row) for row in rows], "count": count}

    def folder_tree(self, prefix: str, depth: int = 3) -> dict:
        if depth not in (1, 2, 3):
            raise ValueError("Folder tree depth must be 1, 2 or 3.")
        separator = "\\" if IS_WINDOWS else "/"
        if not prefix and not IS_WINDOWS:
            prefix = separator
        if prefix and not prefix.endswith(separator):
            prefix += separator
        with self.lock:
            key = (prefix, depth)
            if key in self.folder_tree_cache:
                return self.folder_tree_cache[key]
            root = {"name": prefix or "All scanned drives", "path": prefix,
                    "bytes": 0, "files": 0, "children": {}}
            where, values = self.filters({"folder": prefix})
            with self.connect() as db:
                rows = db.execute(
                    "SELECT parent,SUM(allocated) AS bytes,COUNT(*) AS files FROM files"
                    + where + " GROUP BY parent", values)
                for row in rows:
                    relative = row["parent"][len(prefix):].strip(separator)
                    parts = relative.split(separator) if relative else []
                    node = root
                    node["bytes"] += row["bytes"]
                    node["files"] += row["files"]
                    path = prefix
                    steps = [(part, False) for part in parts[:depth]]
                    if len(steps) < depth:
                        steps.append(("Files in this folder", True))
                    for name, direct in steps:
                        if not direct:
                            path += name + separator
                        child_key = (path, direct)
                        if child_key not in node["children"]:
                            node["children"][child_key] = {
                                "name": name, "path": path, "direct": direct,
                                "bytes": 0, "files": 0, "children": {},
                            }
                        node = node["children"][child_key]
                        node["bytes"] += row["bytes"]
                        node["files"] += row["files"]

            def finish(node):
                node["children"] = sorted(node["children"].values(), key=lambda child: -child["bytes"])
                for child in node["children"]:
                    finish(child)

            finish(root)
            if len(self.folder_tree_cache) >= 8:
                self.folder_tree_cache.pop(next(iter(self.folder_tree_cache)))
            self.folder_tree_cache[key] = root
            return root

    def recommendations(self, minimum: int = MINIMUM_BYTES) -> dict:
        if minimum < MINIMUM_BYTES:
            raise ValueError("Recommendations start at 256 MiB.")
        with self.lock:
            report = self.report()
            if report is None:
                raise ValueError("No scan is available yet.")
            snapshot = report["scan"]["finished"]
            cache_path = self.data_dir / "recommendations.json"
            if self.recommendation_cache is None and cache_path.exists():
                try:
                    self.recommendation_cache = json.loads(cache_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    LOG.exception("Could not read recommendation cache; rebuilding from inventory")
            cache = self.recommendation_cache
            if not isinstance(cache, dict) or cache.get("snapshot") != snapshot or cache.get("version") != RULE_VERSION:
                with self.connect() as db:
                    cache = analyze(db, report)
                temporary = self.data_dir / "recommendations.tmp"
                temporary.write_text(json.dumps(cache), encoding="utf-8")
                os.replace(temporary, cache_path)
                self.recommendation_cache = cache
            items = [item for item in cache["items"] if item["bytes"] >= minimum]
            return {**cache, "items": items, "minimumBytes": minimum,
                    "candidateBytes": sum(item["bytes"] for item in items)}
