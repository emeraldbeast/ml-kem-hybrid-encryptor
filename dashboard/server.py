"""Dependency-free local HTTP server for the interactive X-Wing dashboard."""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from xwing import run_original_paper_roundtrip  # noqa: E402
from xwing.openssl_backend import OpenSSLCommandError  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "XWingPaperBaseline/0.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        # Keep the local lab console uncluttered; no secrets are logged.
        print("[dashboard] " + fmt % args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/" or path == "/index.html":
            target = STATIC_DIR / "index.html"
            self._send(200, target.read_bytes(), "text/html; charset=utf-8")
            return
        if path == "/static/app.css":
            self._send(200, (STATIC_DIR / "app.css").read_bytes(), "text/css; charset=utf-8")
            return
        if path == "/static/app.js":
            self._send(200, (STATIC_DIR / "app.js").read_bytes(), "text/javascript; charset=utf-8")
            return
        if path == "/api/health":
            try:
                from xwing.openssl_backend import OpenSSLBackend

                backend = OpenSSLBackend()
                self._json(
                    200,
                    {
                        "ok": True,
                        "openssl": backend.version_text,
                        "minimum": "OpenSSL 3.5.0",
                        "algorithm": "X-Wing original-paper baseline",
                    },
                )
            except OpenSSLCommandError as exc:
                self._json(503, {"ok": False, "error": str(exc)})
            return
        self._json(404, {"ok": False, "error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path != "/api/run":
            self._json(404, {"ok": False, "error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > 4096:
            self._json(413, {"ok": False, "error": "Request body too large"})
            return
        if length:
            self.rfile.read(length)  # No client-controlled algorithm parameters are accepted.
        try:
            report = run_original_paper_roundtrip()
            self._json(200, report)
        except (OpenSSLCommandError, RuntimeError, ValueError) as exc:
            self._json(500, {"ok": False, "error": str(exc)})
        except Exception:
            # Do not leak unexpected tracebacks or temporary-path information to the UI.
            self._json(500, {"ok": False, "error": "Unexpected backend error. Check the terminal for environment issues."})


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print("=" * 64)
    print("X-Wing — original-paper baseline dashboard")
    print(f"Open http://{host}:{port} in your browser")
    print("This server is bound to localhost; keep it for local learning only.")
    print("=" * 64)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard...")
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
