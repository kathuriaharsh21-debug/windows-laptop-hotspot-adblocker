"""
api_server.py — Dashboard API server on port 3000

Serves:
  GET  /              -> dashboard HTML
  GET  /api/stats     -> live stats JSON
  GET  /api/devices   -> live connected hotspot devices
  GET  /api/logs      -> last 100 DNS query log entries
  POST /api/toggle    -> flip blocking on/off
"""

import os
import sys
import json
import threading
import urllib.parse
import socketserver
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend", "public")
PORT         = 3000

# ── shared state imported from dns_server ────────────────────────────────────
from dns_server import stats, stats_lock, get_connected_devices, start_dns_server, BLOCKLIST
from blocklist_loader import load_blocklist


class Handler(BaseHTTPRequestHandler):
    log_message = lambda *a: None  # suppress per-request stdout noise

    def _json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/api/stats":
            with stats_lock:
                total = max(stats["total_queries"], 1)
                top   = sorted(stats["top_blocked_domains"].items(), key=lambda x: -x[1])[:10]
                data  = {
                    "total_queries":    stats["total_queries"],
                    "blocked_queries":  stats["blocked_queries"],
                    "allowed_queries":  stats["allowed_queries"],
                    "block_pct":        round(stats["blocked_queries"] / total * 100, 1),
                    "is_on":            stats["is_blocking_enabled"],
                    "blocklist_size":   len(BLOCKLIST),
                    "top_blocked":      [{"domain": d, "count": c} for d, c in top],
                }
            self._json(data)

        elif path == "/api/devices":
            self._json(get_connected_devices())

        elif path == "/api/logs":
            with stats_lock:
                self._json(stats["query_log"][:100])

        else:
            # Serve static files from frontend/public
            req = self.path
            if req == "/":
                req = "/index.html"
            filepath = os.path.join(FRONTEND_DIR, req.lstrip("/"))
            if os.path.isfile(filepath):
                try:
                    with open(filepath, "rb") as f:
                        body = f.read()
                    ct = "text/html" if filepath.endswith(".html") else (
                         "text/css" if filepath.endswith(".css") else
                         "application/javascript" if filepath.endswith(".js") else
                         "text/plain")
                    self.send_response(200)
                    self.send_header("Content-Type", ct)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except Exception:
                    self.send_response(500)
                    self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/toggle":
            with stats_lock:
                stats["is_blocking_enabled"] = not stats["is_blocking_enabled"]
                state = stats["is_blocking_enabled"]
            self._json({"ok": True, "is_on": state, "msg": f"Blocking {'ON' if state else 'OFF'}"})
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()


def run():
    import dns_server as ds
    global BLOCKLIST
    
    print("[Startup] Loading blocklist (using cached lists)...")
    bl = load_blocklist()
    ds.BLOCKLIST = bl
    # Make BLOCKLIST accessible globally in this module too
    import builtins
    builtins._BLOCKLIST_REF = bl

    print("[Startup] Starting DNS sinkhole server...")
    start_dns_server()

    socketserver.TCPServer.allow_reuse_address = True
    print(f"[Dashboard] Live at http://localhost:{PORT}")
    print(f"[Dashboard] {len(bl):,} ad domains loaded")
    print(f"[Dashboard] Blocking: OFF (toggle via dashboard)")

    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    run()
