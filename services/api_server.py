import http.server
import socketserver
import json
import os
import urllib.parse
from dns_server import real_stats, get_real_connected_devices, start_dns_server, BLOCKLIST
import threading

PORT = 3000
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend", "public")

class RealAdBlockerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path == "/api/stats":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            sorted_domains = sorted(real_stats["top_blocked_domains"].items(), key=lambda x: x[1], reverse=True)[:10]
            top_domains_formatted = [{"domain": d, "count": c} for d, c in sorted_domains]

            response_data = {
                "total_queries": real_stats["total_queries"],
                "blocked_queries": real_stats["blocked_queries"],
                "blocked_percentage": round((real_stats["blocked_queries"] / max(1, real_stats["total_queries"])) * 100, 1),
                "is_blocking_enabled": real_stats["is_blocking_enabled"],
                "total_blocklist_domains": len(BLOCKLIST),
                "top_blocked_domains": top_domains_formatted
            }
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
            return

        elif path == "/api/devices":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            devices = get_real_connected_devices()
            self.wfile.write(json.dumps(devices).encode("utf-8"))
            return

        elif path == "/api/logs":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            self.wfile.write(json.dumps(real_stats["query_log"]).encode("utf-8"))
            return

        else:
            return super().do_GET()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path

        if path == "/api/mode/toggle":
            real_stats["is_blocking_enabled"] = not real_stats["is_blocking_enabled"]
            status = "ACTIVE" if real_stats["is_blocking_enabled"] else "PAUSED"
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            resp = {
                "success": True,
                "is_blocking_enabled": real_stats["is_blocking_enabled"],
                "status": status,
                "message": f"Real DNS Blocking is now {status}"
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return

        else:
            self.send_response(404)
            self.end_headers()

def run_servers():
    dns_thread = threading.Thread(target=start_dns_server, daemon=True)
    dns_thread.start()

    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), RealAdBlockerHandler) as httpd:
        print("===================================================")
        print(f"[API-Server] REAL Dashboard Live on http://localhost:{PORT}")
        print("===================================================")
        httpd.serve_forever()

if __name__ == "__main__":
    run_servers()
