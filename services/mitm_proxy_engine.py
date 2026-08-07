"""
mitm_proxy_engine.py — HTTP Transparent Proxy with Brave-Parity Injection

Intercepts HTTP requests from connected devices and:
1. Blocks requests to ad domains (DNS-level is primary; this adds HTTP-level enforcement)
2. Injects Brave-equivalent scriptlets + CSS cosmetic filters into HTML responses
3. Strips YouTube adPlacements JSON from API responses

Run alongside dns_server.py for full Brave-parity ad blocking.
Proxy listens on port 8085 (HTTP).
"""

import re
import urllib.request
import urllib.parse
import socketserver
from http.server import BaseHTTPRequestHandler
from blocklist_loader import is_ad_domain
from scriptlet_engine import inject_into_html, CSS_COSMETIC_RULES_GENERIC


class BravePariryProxyHandler(BaseHTTPRequestHandler):
    log_message = lambda *a: None  # Suppress per-request logs unless blocked

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def _handle_request(self, method):
        url = self.path
        if not url.startswith("http"):
            host = self.headers.get("Host", "")
            url = f"http://{host}{self.path}"

        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.split(":")[0]

        # ── DNS-level ad domain enforcement (HTTP layer backup) ──────────────
        if is_ad_domain(netloc):
            print(f"[Proxy BLOCKED] {netloc}")
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # ── Forward to origin ─────────────────────────────────────────────────
        try:
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "content-length")}
            headers["User-Agent"] = "Mozilla/5.0"

            body = None
            if method == "POST":
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else None

            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=8) as resp:
                content_type = resp.headers.get("Content-Type", "")
                raw_body = resp.read()

            # ── Inject scriptlets + cosmetic CSS into HTML ────────────────────
            if "text/html" in content_type:
                try:
                    text = raw_body.decode("utf-8", errors="ignore")
                    text = inject_into_html(text, url=url)
                    raw_body = text.encode("utf-8")
                except Exception:
                    pass

            # ── Strip YouTube ad JSON from API responses ───────────────────────
            elif "application/json" in content_type and "youtube.com" in url:
                try:
                    text = raw_body.decode("utf-8", errors="ignore")
                    for ad_key in ["adPlacements", "playerAds", "adSlots"]:
                        text = re.sub(
                            rf'"{re.escape(ad_key)}"\s*:\s*\[.*?\]',
                            f'"{ad_key}":[]',
                            text, flags=re.DOTALL
                        )
                    raw_body = text.encode("utf-8")
                except Exception:
                    pass

            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in ("content-length", "transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw_body)))
            self.end_headers()
            self.wfile.write(raw_body)

        except Exception as e:
            self.send_response(502)
            self.end_headers()
            err = f"Proxy error: {e}".encode("utf-8")
            try:
                self.wfile.write(err)
            except Exception:
                pass


def start_mitm_proxy_server(port: int = 8085):
    try:
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer(("0.0.0.0", port), BravePariryProxyHandler) as srv:
            print(f"[Proxy] Brave-Parity Scriptlet+CSS Injection Proxy on port {port}")
            srv.serve_forever()
    except Exception as e:
        print(f"[Proxy] Error: {e}")


if __name__ == "__main__":
    start_mitm_proxy_server()
