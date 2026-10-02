"""Conservative cleanup leads derived from saved metadata, never deletion actions."""

import hashlib
import ntpath
import posixpath

MINIMUM_BYTES = 256 * 1024**2
RULE_VERSION = 2

RULES = {
    "cache": {
        "title": "Clear application cache",
        "risk": "app",
        "reason": "A cache-named directory has a substantial measured footprint.",
        "steps": [
            "Identify the owning app from the path and use its cache or storage settings.",
            "Choose cached files only, not cookies, passwords, profiles or offline documents.",
            "Close the app before cleanup. If it has no documented cleanup option, leave this folder alone.",
        ],
        "caution": "A folder name is not proof that every file is disposable. Offline content may require a download again.",
    },
    "package-cache": {
        "title": "Clear package download cache",
        "risk": "regenerable",
        "reason": "This is a recognized package-manager cache, separate from your source files.",
        "steps": [
            "Finish any running installs or builds and confirm you can download dependencies again.",
            "Use the owning package manager's documented cache-clean command for this location.",
            "Re-run a normal install or build afterward to confirm the environment still works.",
        ],
        "caution": "Subsequent installs may be slower and need network access. Keep caches needed for offline work.",
    },
    "dependencies": {
        "title": "Retire a project's installed dependencies",
        "risk": "regenerable",
        "reason": "Installed dependencies can usually be restored from a project's manifests.",
        "steps": [
            "Confirm this is an inactive project and no process is using its environment.",
            "Verify its manifest, lockfile and reinstall process. Back up any locally patched packages.",
            "Remove only this dependency directory, not the project. Reinstall before using the project again.",
        ],
        "caution": "Local package edits would be lost; unpublished or unavailable dependencies may not be recoverable.",
    },
    "build-cache": {
        "title": "Clear framework build cache",
        "risk": "regenerable",
        "reason": "This is a recognized generated framework directory, not a generic folder named build.",
        "steps": [
            "Stop the project's dev server and confirm the source and build configuration are intact.",
            "Use the framework's documented clean procedure for this generated directory.",
            "Rebuild before running or deploying the application.",
        ],
        "caution": "Do not remove outputs used by a live deployment. Custom files placed here would also be removed.",
    },
    "temporary": {
        "title": "Review Windows temporary files",
        "risk": "app",
        "reason": "Windows' temporary-files directory contains measured allocation.",
        "steps": [
            "Open Windows Settings > System > Storage > Temporary files.",
            "Review the categories selected by Windows. Leave Downloads unchecked unless reviewed separately.",
            "Let Windows handle in-use files; do not force deletion of locked entries.",
        ],
        "caution": "The measured directory footprint is an upper bound, not Windows' confirmed removable amount.",
    },
    "recycle": {
        "title": "Review the Recycle Bin",
        "risk": "review",
        "reason": "Previously deleted files still occupy measured space in the Recycle Bin.",
        "steps": [
            "Open the Recycle Bin and check whether anything needs restoring.",
            "Restore anything you want to keep.",
            "Empty it only after review; this removes the normal restore option.",
        ],
        "caution": "Emptying the Recycle Bin is permanent. Only accessible entries were measured.",
    },
    "application": {
        "title": "Uninstall an application you no longer need",
        "risk": "app",
        "reason": "An installed application directory has a large measured footprint.",
        "steps": [
            "Identify the application and check whether you still use it or other software depends on it.",
            "Back up its documents, settings and license information if needed.",
            "Use Windows Settings > Apps > Installed apps, or the vendor's uninstaller. Never delete Program Files manually.",
        ],
        "caution": "A vendor folder may contain several applications or shared components. An uninstaller may reclaim less.",
    },
    "toolchain": {
        "title": "Retire an unused Rust toolchain",
        "risk": "app",
        "reason": "An individually installed Rust toolchain occupies this directory.",
        "steps": [
            "Check rustup toolchain list and the toolchain selected by your active projects.",
            "Check project overrides and rust-toolchain files before removing any version.",
            "Use rustup's toolchain uninstall command for an unused version, not manual folder deletion.",
        ],
        "caution": "Do not remove a toolchain used by a project or build pipeline. Reinstallation needs network access.",
    },
    "virtual-disk": {
        "title": "Review a large virtual disk",
        "risk": "review",
        "reason": "This host-side disk image is large; the scan cannot see how much space inside it is unused.",
        "steps": [
            "Identify the owning VM, Docker environment or WSL distribution and inspect its contents there.",
            "Export or back up any data you need before retiring an environment.",
            "Use the owning tool to remove an unused environment or follow its supported cleanup and compaction procedure.",
        ],
        "caution": "This is the entire measured image footprint, NOT an estimate of unused space. It may contain irreplaceable data.",
    },
    "download": {
        "title": "Review a large download",
        "risk": "review",
        "reason": "A large file in Downloads may no longer be needed after installation, extraction or use.",
        "steps": [
            "Confirm what this file contains and whether it is still needed.",
            "Verify any replacement, backup or re-download source before removing it.",
            "If discarding it, review the Recycle Bin afterward; recycling alone may not free space yet.",
        ],
        "caution": "No duplicate or backup was verified. Last-modified time does not show whether you still use this file.",
    },
}


def path_module(path):
    return ntpath if "\\" in path or ntpath.splitdrive(path)[0] else posixpath


def candidate_for(path, category, kind):
    module = path_module(path)
    separator = module.sep
    parts = path.split(separator)
    lower = [part.lower() for part in parts]
    if (category == "System & recovery"
            or any(part.startswith("onedrive") for part in lower)
            or any(part in {"onenote", "outlook", "thunderbird"} for part in lower)):
        return None

    def group(rule, index):
        return rule, separator.join(parts[:index + 1]), True

    if len(parts) > 2 and lower[1] in {"program files", "program files (x86)"}:
        shared = {"common files", "windowsapps", "modifiablewindowsapps", "dotnet",
                  "windows defender", "windows nt", "windows kits", "microsoft",
                  "microsoft update health tools", "microsoft edge", "microsoft edgewebview"}
        if lower[2] in shared or lower[2].startswith("windows"):
            return None
        return group("application", 2)
    if len(parts) > 1 and lower[1] == "programdata":
        return None
    # The outermost recognized scope owns all its descendants, preventing overlap.
    for index, part in enumerate(lower[:-1]):
        if part == ".git":
            return None
        if part == "$recycle.bin":
            return group("recycle", index)
        if part == ".rustup" and lower[index + 1:index + 2] == ["toolchains"] and index + 2 < len(parts) - 1:
            return group("toolchain", index + 2)
        if part in {"node_modules", ".venv", "venv"}:
            return group("dependencies", index)
        if part in {".next", ".turbo"}:
            return group("build-cache", index)
        if part == "_cacache" and ".npm" in lower[:index]:
            return group("package-cache", index)
        if part == ".cache":
            if index + 1 < len(parts) - 1:
                rule = "package-cache" if lower[index + 1] in {"pip", "uv"} else "cache"
                return group(rule, index + 1)
            return None
        if part in {"cache", "caches", "code cache", "gpucache", "shadercache"}:
            rule = "package-cache" if index and lower[index - 1] in {"pip", "uv"} else "cache"
            return group(rule, index)
        if part == "temp" and lower[max(0, index - 2):index] == ["appdata", "local"]:
            return group("temporary", index)
    if kind == "Virtual disks" and module.splitext(path)[1].lower() in {
        ".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow", ".qcow2"
    }:
        return "virtual-disk", path, False
    if "downloads" in lower[:-1]:
        return "download", path, False
    return None


def analyze(db, report):
    groups = {}
    for row in db.execute("SELECT path,category,kind,allocated,modified FROM files WHERE allocated>0"):
        match = candidate_for(row["path"], row["category"], row["kind"])
        if match is None:
            continue
        rule, path, is_directory = match
        key = (rule, path.casefold())
        if key not in groups:
            groups[key] = {"rule": rule, "path": path, "isDirectory": is_directory,
                           "bytes": 0, "files": 0, "newest": 0, "recentBytes": 0}
        item = groups[key]
        item["bytes"] += row["allocated"]
        item["files"] += 1
        item["newest"] = max(item["newest"], row["modified"])
        if row["modified"] >= report["scan"]["started"] - 7 * 86400:
            item["recentBytes"] += row["allocated"]

    candidates = []
    for item in groups.values():
        if item["bytes"] < MINIMUM_BYTES:
            continue
        module = path_module(item["path"])
        item.update(RULES[item["rule"]])
        item["name"] = module.basename(item["path"])
        item["context"] = module.basename(module.dirname(item["path"]))
        item["id"] = hashlib.sha256((item["rule"] + "\0" + item["path"].casefold()).encode()).hexdigest()[:20]
        item["evidence"] = []
        if item["rule"] in {"dependencies", "build-cache"}:
            parent = module.dirname(item["path"])
            manifests = (["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]
                         if item["name"].lower() not in {".venv", "venv"}
                         else ["pyproject.toml", "requirements.txt", "Pipfile", "Pipfile.lock", "uv.lock", "poetry.lock"])
            for name in manifests:
                manifest = module.join(parent, name)
                if db.execute("SELECT 1 FROM files WHERE path=?", (manifest,)).fetchone():
                    item["evidence"].append(manifest)
            has_manifest = any(module.basename(path) in {"package.json", "pyproject.toml", "requirements.txt", "Pipfile"}
                               for path in item["evidence"])
            if not has_manifest:
                item["risk"] = "review"
                item["reason"] += " No adjacent project manifest was found in the snapshot."
                item["caution"] = "Restore inputs were not verified. Establish a working reinstall or rebuild process before removing anything."
        candidates.append(item)
    candidates.sort(key=lambda item: (-item["bytes"], item["path"].casefold()))
    return {"snapshot": report["scan"]["finished"], "version": RULE_VERSION,
            "partial": report["scan"]["status"] != "complete", "items": candidates,
            "minimumBytes": MINIMUM_BYTES,
            "estimateNote": "These are measured candidate footprints, not guaranteed savings. Shared hard links, in-use files and app cleanup policies may reduce the amount freed. No backup, last-access time or unused VM capacity was verified."}
