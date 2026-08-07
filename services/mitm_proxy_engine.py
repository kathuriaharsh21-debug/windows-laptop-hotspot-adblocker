import re
import json
import urllib.request
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import threading

# Brave / Opera Parity In-DOM Cosmetic Filtering & YouTube Ad Defuser Engine

CSS_COSMETIC_INJECTION = """
<style id="smarttv-adblocker-cosmetic">
div[id*="google_ads"], div[class*="ad-banner"], div[class*="ad-container"],
iframe[src*="doubleclick"], iframe[src*="adsystem"], div[class*="sponsored-post"],
aside[class*="ad"], .ytd-action-companion-ad-renderer, #player-ads {
    display: none !important;
    visibility: hidden !important;
    height: 0px !important;
    opacity: 0 !important;
}
</style>
"""

def strip_youtube_ad_json(json_text):
    try:
        data = json.loads(json_text)
        # Strip YouTube adPlacements and playerAds array from JSON payload
        if isinstance(data, dict):
            if "adPlacements" in data:
                data["adPlacements"] = []
            if "playerAds" in data:
                data["playerAds"] = []
            if "adSlots" in data:
                data["adSlots"] = []
            if "playerResponse" in data and isinstance(data["playerResponse"], dict):
                data["playerResponse"].pop("adPlacements", None)
                data["playerResponse"].pop("playerAds", None)
        return json.dumps(data)
    except Exception:
        return json_text

def process_html_response(html_content, url):
    # 1. If YouTube player JSON endpoint, strip adPlacements
    if "youtube.com" in url or "googlevideo.com" in url:
        if "adPlacements" in html_content or "playerAds" in html_content:
            print(f"[In-DOM Defuser] Stripping YouTube Ad JSON payload from {url}")
            html_content = strip_youtube_ad_json(html_content)

    # 2. Inject CSS Cosmetic Filtering into HTML <head>
    if "<head>" in html_content:
        html_content = html_content.replace("<head>", "<head>" + CSS_COSMETIC_INJECTION)
    elif "<html>" in html_content:
        html_content = html_content.replace("<html>", "<html><head>" + CSS_COSMETIC_INJECTION + "</head>")
        
    return html_content

class MITMProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = self.path
        if not url.startswith("http"):
            url = "http://" + self.headers.get("Host", "") + self.path

        print(f"[MITM Proxy] Intercepting request: {url}")
        
        # Check if ad domain
        from blocklist_loader import is_ad_domain
        parsed_url = urllib.parse.urlparse(url)
        if is_ad_domain(parsed_url.netloc):
            print(f"[MITM Proxy 🛑] BLOCKED Ad Host: {parsed_url.netloc}")
            self.send_response(204) # No Content
            self.end_headers()
            return

        try:
            req = urllib.request.Request(url, headers={k: v for k, v in self.headers.items() if k.lower() != 'host'})
            with urllib.request.urlopen(req, timeout=5) as response:
                content_type = response.headers.get("Content-Type", "")
                body = response.read()

                if "text/html" in content_type or "application/json" in content_type:
                    text = body.decode("utf-8", errors="ignore")
                    processed_text = process_html_response(text, url)
                    body = processed_text.encode("utf-8")

                self.send_response(response.status)
                for k, v in response.headers.items():
                    if k.lower() not in ['content-length', 'transfer-encoding']:
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Proxy Error: {e}".encode("utf-8"))

def start_mitm_proxy_server(port=8085):
    try:
        server = socketserver.TCPServer(("0.0.0.0", port), MITMProxyHandler)
        print(f"[MITM Proxy Engine] In-DOM Cosmetic Filter & YouTube Defuser Live on Port {port}")
        server.serve_forever()
    except Exception as e:
        print(f"[MITM Proxy Error]: {e}")

if __name__ == "__main__":
    start_mitm_proxy_server()
