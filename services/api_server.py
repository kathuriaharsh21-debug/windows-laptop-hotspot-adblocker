"""
api_server.py — Complete standalone server that boots DNS + dashboard together.
"""
import os, sys, json, threading, time, urllib.parse, socketserver
from http.server import BaseHTTPRequestHandler

# Add services dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BASE_DIR     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend", "public")
PORT         = 3000

# ── Shared state (single source of truth) ────────────────────────────────────
from blocklist_loader import load_blocklist

# Load blocklist once at startup
print("[Startup] Loading blocklist (202k+ domains)...")
_BLOCKLIST = load_blocklist()
print(f"[Startup] {len(_BLOCKLIST):,} domains loaded")

# Shared mutable state
_stats = {
    "total_queries":    0,
    "blocked_queries":  0,
    "allowed_queries":  0,
    "is_on":            False,   # DEFAULT OFF
    "query_log":        [],
    "top_blocked":      {},
    "blocklist_size":   len(_BLOCKLIST),
}
_lock = threading.Lock()

# ── DNS Server (inline, no cross-module import issues) ───────────────────────
import socket, struct, subprocess, re

def _parse_dns_domain(data):
    try:
        parts, idx = [], 12
        length = data[idx]
        while length:
            idx += 1
            parts.append(data[idx:idx+length].decode("ascii", errors="ignore"))
            idx += length
            length = data[idx]
        return ".".join(parts).lower()
    except Exception:
        return ""

def _nxdomain(data):
    return data[:2] + b"\x81\x83" + data[4:6] + b"\x00\x00\x00\x00\x00\x00" + data[12:]

def _forward(data):
    for ns in ("1.1.1.1", "8.8.8.8"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.sendto(data, (ns, 53))
            r, _ = s.recvfrom(4096)
            s.close()
            return r
        except Exception:
            pass
    return None

def _is_blocked(domain):
    if not _stats["is_on"]:
        return False
    if domain in _BLOCKLIST:
        return True
    parts = domain.split(".")
    for i in range(1, len(parts)-1):
        if ".".join(parts[i:]) in _BLOCKLIST:
            return True
    return False

def _handle_dns(data, addr, sock):
    domain = _parse_dns_domain(data)
    if not domain:
        return
    blocked = _is_blocked(domain)
    with _lock:
        _stats["total_queries"] += 1
        entry = {"t": time.strftime("%H:%M:%S"), "domain": domain,
                 "client": addr[0], "status": "BLOCKED" if blocked else "ALLOWED"}
        _stats["query_log"].insert(0, entry)
        if len(_stats["query_log"]) > 100:
            _stats["query_log"].pop()
        if blocked:
            _stats["blocked_queries"] += 1
            _stats["top_blocked"][domain] = _stats["top_blocked"].get(domain, 0) + 1
        else:
            _stats["allowed_queries"] += 1
    if blocked:
        print(f"[DNS BLOCK] {domain}")
        try: sock.sendto(_nxdomain(data), addr)
        except Exception: pass
    else:
        r = _forward(data)
        if r:
            try: sock.sendto(r, addr)
            except Exception: pass

def _dns_listen(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        print(f"[DNS] Listening on {host}:{port}")
        while True:
            try:
                data, addr = s.recvfrom(4096)
                threading.Thread(target=_handle_dns, args=(data, addr, s), daemon=True).start()
            except Exception:
                pass
    except Exception as e:
        print(f"[DNS] Cannot bind {host}:{port} — {e}")

def _start_dns():
    for h in ("0.0.0.0", "127.0.0.1"):
        threading.Thread(target=_dns_listen, args=(h, 53), daemon=True).start()

# ── Device detection ─────────────────────────────────────────────────────────
_dev_cache = {}
_dev_lock  = threading.Lock()

def _ping(ip):
    try:
        out = subprocess.check_output(f"ping -n 1 -w 200 {ip}", shell=True,
              text=True, errors="ignore", timeout=2)
        return "TTL=" in out or "ttl=" in out
    except Exception:
        return False

def get_devices():
    devices = []
    try:
        arp = subprocess.check_output("arp -a", shell=True, text=True, errors="ignore")
        for line in arp.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F\-]{17})\s+(\w+)", line)
            if not m: continue
            ip, mac, _ = m.groups()
            if not ip.startswith("192.168.137.") or ip in ("192.168.137.1","192.168.137.255"):
                continue
            now = time.time()
            with _dev_lock:
                c = _dev_cache.get(ip)
                if c and (now - c["ts"]) < 8:
                    if c["alive"]: devices.append(c["d"])
                    continue
            alive = _ping(ip)
            d = {"ip": ip, "mac": mac.upper(), "name": f"Device ({ip})", "status": "Connected"}
            with _dev_lock:
                _dev_cache[ip] = {"d": d, "alive": alive, "ts": now}
            if alive:
                devices.append(d)
    except Exception:
        pass
    return devices

# ── HTTP Handler ──────────────────────────────────────────────────────────────
class H(BaseHTTPRequestHandler):
    log_message = lambda *a: None

    def _j(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try: self.wfile.write(body)
        except Exception: pass

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path

        if p == "/api/stats":
            with _lock:
                top = sorted(_stats["top_blocked"].items(), key=lambda x: -x[1])[:10]
                d = {
                    "total_queries":   _stats["total_queries"],
                    "blocked_queries": _stats["blocked_queries"],
                    "allowed_queries": _stats["allowed_queries"],
                    "block_pct":       round(_stats["blocked_queries"] / max(_stats["total_queries"],1) * 100, 1),
                    "is_on":           _stats["is_on"],
                    "blocklist_size":  _stats["blocklist_size"],
                    "top_blocked":     [{"domain": d, "count": c} for d, c in top],
                }
            self._j(d)

        elif p == "/api/devices":
            self._j(get_devices())

        elif p == "/api/logs":
            with _lock:
                self._j(_stats["query_log"][:100])

        else:
            req = "/index.html" if p == "/" else p
            fp  = os.path.join(FRONTEND_DIR, req.lstrip("/"))
            if os.path.isfile(fp):
                ct = ("text/html" if fp.endswith(".html") else
                      "application/javascript" if fp.endswith(".js") else
                      "text/css" if fp.endswith(".css") else "text/plain")
                with open(fp, "rb") as f: body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try: self.wfile.write(body)
                except Exception: pass
            else:
                self.send_response(404); self.end_headers()

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        if p == "/api/toggle":
            with _lock:
                _stats["is_on"] = not _stats["is_on"]
                state = _stats["is_on"]
            self._j({"ok": True, "is_on": state})
        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()


def main():
    _start_dns()
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), H) as srv:
        print(f"[Dashboard] http://localhost:{PORT}  |  {len(_BLOCKLIST):,} domains  |  Blocking: OFF")
        srv.serve_forever()


if __name__ == "__main__":
    main()
