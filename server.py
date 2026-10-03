"""Loopback-only HTTP host for Disk Atlas. No external packages or services."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
from contextlib import ExitStack
from urllib.parse import parse_qs, urlparse

from scanner import IS_MACOS, MAC_SCAN_NOTE, Inventory, fixed_drives

BASE = Path(__file__).resolve().parent


def default_data_dir():
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "DiskAtlas"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "DiskAtlas"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "disk-atlas"


def make_handler(inventory, token, port, demo=False):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{host}" for host in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            if len(args) > 1 and str(args[1]) not in {"200", "204"}:
                super().log_message(format, *args)

        def respond(self, status, payload, content_type="application/json"):
            body = (json.dumps(payload).encode() if content_type == "application/json"
                    else payload.encode("utf-8"))
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'unsafe-inline'; "
                             "style-src 'unsafe-inline'; img-src 'self' data:; "
                             "connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def permitted(self, api=False):
            if self.headers.get("Host") not in allowed_hosts:
                self.respond(403, {"error": "Only local connections are accepted."})
                return False
            origin = self.headers.get("Origin")
            if origin and origin not in allowed_origins:
                self.respond(403, {"error": "Cross-origin requests are not accepted."})
                return False
            if api and not secrets.compare_digest(self.headers.get("X-Atlas-Token", ""), token):
                self.respond(403, {"error": "Missing or invalid local session token. Reload the app."})
                return False
            return True

        def do_GET(self):
            parsed = urlparse(self.path)
            if not self.permitted(parsed.path.startswith("/api/")):
                return
            params = {key: value[0] for key, value in parse_qs(parsed.query).items()}
            try:
                if parsed.path == "/":
                    html = (BASE / "index.html").read_text(encoding="utf-8")
                    self.respond(200, html.replace("__ATLAS_TOKEN__", token), "text/html")
                elif parsed.path == "/favicon.ico":
                    self.respond(204, "", "text/plain")
                elif parsed.path == "/api/status":
                    self.respond(200, {**inventory.status(), "demo": demo,
                                       "platform": sys.platform,
                                       "scanNote": MAC_SCAN_NOTE if IS_MACOS and not demo else ""})
                elif parsed.path == "/api/drives":
                    self.respond(200, inventory.report()["volumes"] if demo else fixed_drives())
                elif parsed.path == "/api/report":
                    self.respond(200, inventory.report())
                elif parsed.path in {"/api/files", "/api/folders", "/api/folder-tree", "/api/issues", "/api/recommendations"}:
                    if not inventory.database.exists():
                        self.respond(409, {"error": "No scan is available yet."})
                        return
                    if parsed.path == "/api/files":
                        result = inventory.files(params)
                    elif parsed.path == "/api/folders":
                        result = inventory.folders(params.get("folder", ""))
                    elif parsed.path == "/api/folder-tree":
                        result = inventory.folder_tree(params.get("folder", ""), int(params.get("depth", 3)))
                    elif parsed.path == "/api/issues":
                        result = inventory.issues()
                    else:
                        result = inventory.recommendations(int(params.get("minimum", 256 * 1024**2)))
                    self.respond(200, result)
                else:
                    self.respond(404, {"error": "Not found."})
            except ValueError as error:
                self.respond(400, {"error": str(error)})
            except (OSError, sqlite3.Error) as error:
                logging.exception("Request failed")
                self.respond(500, {"error": str(error)})

        def do_POST(self):
            if not self.permitted(True):
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 0 or length > 4096:
                    self.respond(413, {"error": "Request too large."})
                    return
                payload = json.loads(self.rfile.read(length) or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("Expected a JSON object.")
                if demo:
                    self.respond(403, {"error": "Demo mode uses synthetic data. Real drive scans are disabled."})
                    return
                if self.path == "/api/scan":
                    drives = fixed_drives()
                    roots = payload.get("roots", [drive["root"] for drive in drives])
                    if not isinstance(roots, list) or not all(isinstance(root, str) for root in roots):
                        raise ValueError("Drive roots must be a list of strings.")
                    allowed = {drive["root"] for drive in drives}
                    if not roots or any(root not in allowed for root in roots):
                        raise ValueError("Select an available scan root.")
                    inventory.start(list(dict.fromkeys(roots)))
                    self.respond(202, inventory.status())
                elif self.path == "/api/cancel":
                    inventory.cancel()
                    self.respond(202, inventory.status())
                else:
                    self.respond(404, {"error": "Not found."})
            except (ValueError, OSError) as error:
                self.respond(400, {"error": str(error)})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scan", action="store_true", help="Scan fixed drives on Windows or the startup filesystem on macOS/Linux.")
    mode.add_argument("--demo", action="store_true", help="Use synthetic data; never scan this device.")
    parser.add_argument("--data-dir", type=Path, help="Private runtime storage; defaults to the user-local application directory.")
    args = parser.parse_args()
    if args.demo and args.data_dir:
        parser.error("--demo uses temporary storage and cannot be combined with --data-dir")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    with ExitStack() as resources:
        if args.demo:
            from demo import create_demo_inventory
            directory = resources.enter_context(tempfile.TemporaryDirectory(prefix="disk-atlas-demo-"))
            inventory = create_demo_inventory(Path(directory))
        else:
            inventory = Inventory((args.data_dir or default_data_dir()).expanduser().resolve())
        token = secrets.token_urlsafe(32)
        server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(inventory, token, args.port, args.demo))
        resources.callback(server.server_close)
        if args.scan:
            inventory.start([drive["root"] for drive in fixed_drives()])
        print(f"Disk Atlas: http://127.0.0.1:{args.port}/?theme=dark", flush=True)
        if args.demo:
            print("Demo mode: synthetic data only. Drive scanning is disabled.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            inventory.cancel()
            if inventory.thread:
                inventory.thread.join(timeout=10)


if __name__ == "__main__":
    main()
