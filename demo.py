"""Deterministic, fictional metadata for screenshots and UI exploration."""

import json
import os
from contextlib import closing
from pathlib import Path
import sqlite3

from scanner import Inventory, SCHEMA, classify

MIB = 1024**2
GIB = 1024**3
STARTED = 1767225600


def create_demo_inventory(directory: Path) -> Inventory:
    inventory = Inventory(directory)
    root = "C:\\" if os.name == "nt" else "/demo/"
    rows = []

    def add(relative, allocated, days_old, logical=None):
        path = root + relative.replace("/", os.sep)
        category, subcategory, kind = classify(path)
        rows.append((path, os.path.dirname(path), category, subcategory, kind,
                     allocated if logical is None else logical, allocated,
                     STARTED - days_old * 86400, 0))

    groups = [
        ("Windows/WinSxS/demo-components", "dll", 400, 32),
        ("Windows/System32", "dll", 180, 24),
        ("Windows/SoftwareDistribution/Download", "cab", 12, 256),
        ("Program Files/Vector Editor/Runtime", "dll", 50, 96),
        ("Program Files/Vector Editor/Assets", "pak", 8, 640),
        ("Program Files/Orion CAD/Models", "bin", 12, 512),
        ("Program Files/Orion CAD/Runtime", "dll", 20, 256),
        ("Users/Demo/AppData/Local/Sample Chat/data", "db", 20, 160),
        ("Users/Demo/AppData/Local/Sample Browser/Default/Cache", "data", 160, 8),
        ("Users/Demo/AppData/Local/Sample Browser/Default/Code Cache", "js", 96, 8),
        ("Users/Demo/AppData/Local/Temp", "tmp", 24, 128),
        ("Users/Demo/Projects/web-app/node_modules/example", "js", 320, 5),
        ("Users/Demo/Projects/web-app/node_modules/native-package", "node", 24, 64),
        ("Users/Demo/Projects/web-app/.next/cache", "js", 64, 16),
        ("Users/Demo/Projects/data-tools/.venv/Lib/site-packages", "py", 120, 8),
        ("Users/Demo/Projects/data-tools/src", "py", 50, 16),
        ("Users/Demo/Projects/web-app/.git/objects", "pack", 8, 512),
        ("Users/Demo/Projects/compiler/target/release", "rlib", 32, 128),
        ("Users/Demo/.npm/_cacache/content", "data", 48, 32),
        ("Users/Demo/.rustup/toolchains/demo-toolchain/bin", "exe", 20, 128),
        ("Users/Demo/Downloads", "zip", 6, 640),
        ("Users/Demo/Videos", "mp4", 8, 4096),
        ("Users/Demo/Pictures", "jpg", 100, 8),
        ("Users/Demo/Documents", "pdf", 24, 128),
    ]
    for folder, extension, count, size_mib in groups:
        for index in range(count):
            add(f"{folder}/sample-{index + 1:04d}.{extension}", size_mib * MIB,
                (index * 37 + len(folder)) % 700)
    add("Users/Demo/Projects/web-app/package.json", 4096, 30)
    add("Users/Demo/Projects/web-app/package-lock.json", 128 * 1024, 30)
    add("Users/Demo/Projects/data-tools/pyproject.toml", 4096, 90)
    add("Users/Demo/Projects/data-tools/uv.lock", 64 * 1024, 90)
    add("Users/Demo/Virtual Machines/workstation.vhdx", 64 * GIB, 4, 128 * GIB)
    add("Users/Demo/AppData/Local/Docker/demo-data.vhdx", 18 * GIB, 2, 64 * GIB)
    add("Users/Demo/.ollama/models/sample-model.gguf", 12 * GIB, 120)
    add("Datasets/sample-data.bin", 2 * GIB, 450)
    add("pagefile.sys", 0, 0, 4 * GIB)
    issues = [
        (root + "System Volume Information", "Directory unavailable", "Simulated permission restriction."),
        (root + "pagefile.sys", "Allocation unavailable", "Simulated locked system file."),
    ]
    taxonomy = {}
    ages = [{"label": name, "bytes": 0, "files": 0}
            for name in ("Last 30 days", "1–6 months", "6–12 months", "Over a year")]
    for row in rows:
        key = row[2:5]
        bucket = taxonomy.setdefault(key, {"category": key[0], "subcategory": key[1], "kind": key[2],
                                          "bytes": 0, "logical": 0, "files": 0})
        bucket["bytes"] += row[6]
        bucket["logical"] += row[5]
        bucket["files"] += 1
        days = (STARTED - row[7]) / 86400
        age = ages[0 if days < 30 else (1 if days < 183 else (2 if days < 365 else 3))]
        age["bytes"] += row[6]
        age["files"] += 1
    allocated = sum(row[6] for row in rows)
    logical = sum(row[5] for row in rows)
    total = 512 * GIB
    used = allocated + 12 * GIB
    volume = {"root": root, "total": total, "used": used, "free": total - used}
    scan = {
        "status": "complete", "roots": [root], "started": STARTED, "finished": STARTED + 90,
        "files": len(rows), "directories": len({row[1] for row in rows}),
        "allocated": allocated, "logical": logical, "issues": len(issues), "current": "",
        "hardlinks": 0, "reparse": 0, "allocationFailures": 1, "unmeasuredLogical": 4 * GIB,
    }
    report = {
        "demo": True, "scan": scan, "volumes": [volume], "volumesAtStart": [volume],
        "allocated": allocated, "logical": logical, "used": used, "free": total - used,
        "total": total, "unaccounted": used - allocated, "overcount": 0,
        "issuesByReason": {"Directory unavailable": 1, "Allocation unavailable": 1},
        "taxonomy": list(taxonomy.values()), "ages": ages,
    }
    with closing(sqlite3.connect(inventory.database)) as db:
        db.executescript(SCHEMA)
        db.executemany("INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?)", rows)
        db.executemany("INSERT INTO issues VALUES(?,?,?)", issues)
        db.execute("INSERT INTO metadata VALUES('report',?)", (json.dumps(report),))
        db.executescript("""
            CREATE INDEX files_size ON files(allocated DESC);
            CREATE INDEX files_taxonomy ON files(category, subcategory, kind);
            CREATE INDEX files_parent ON files(parent COLLATE NOCASE);
        """)
        db.commit()
    inventory.state = scan
    return inventory
