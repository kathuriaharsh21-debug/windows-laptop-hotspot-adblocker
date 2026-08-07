import os
import re
import urllib.request

# Comprehensive Ad & Tracker Domain Engine (Brave / Opera Parity)
FULL_BLOCKLIST = set()
WILDCARD_PATTERNS = [
    r".*\.doubleclick\.net$",
    r".*\.googlesyndication\.com$",
    r".*\.googleadservices\.com$",
    r".*\.amazon-adsystem\.com$",
    r".*\.adnxs\.com$",
    r".*\.criteo\.com$",
    r".*\.criteo\.net$",
    r".*\.outbrain\.com$",
    r".*\.taboola\.com$",
    r".*\.rubiconproject\.com$",
    r".*\.pubmatic\.com$",
    r".*\.casalemedia\.com$",
    r".*\.openx\.net$",
    r".*\.ad-akamaized\.net$",
    r".*\.ssai-ads\.hotstar\.com$",
    r".*\.dai-sonyliv\.com$",
    r".*\.samsungads\.com$",
    r".*\.lgsmartad\.com$",
    r".*\.ads\.roku\.com$"
]

COMPILED_WILDCARDS = [re.compile(p, re.IGNORECASE) for p in WILDCARD_PATTERNS]

# Built-in High Impact Ad & Tracking Domains (StevenBlack + EasyList + SmartTV + SSAI)
BUILTIN_AD_DOMAINS = [
    # Top Global Ad Networks (Brave/Opera Default)
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com",
    "amazon-adsystem.com", "adnxs.com", "criteo.com", "criteo.net", "outbrain.com", "taboola.com",
    "rubiconproject.com", "pubmatic.com", "casalemedia.com", "openx.net", "scorecardresearch.com",
    "quantserve.com", "moatads.com", "advertising.com", "adroll.com", "mathtag.com",
    
    # Smart TV Manufacturers & Telemetry
    "samsungads.com", "samsungacr.com", "samsungcloudsolution.net",
    "ad.lgappstv.com", "lgsmartad.com", "rdl.lgtvcommon.com",
    "p.ads.roku.com", "cloudservices.roku.com", "ads.rokuroute.com",
    "device-metrics-us.amazon.com", "mads.amazon-adsystem.com", "tvads.vizio.com",
    
    # Indian Streaming SSAI Nodes (Hotstar, SonyLIV, ZEE5)
    "ad-akamaized.net", "hotstar-ads.akamaized.net", "ssai-ads.hotstar.com", "ads.hotstar.com",
    "dai-sonyliv.com", "ssai-vizio.sonyliv.com", "ads.sonyliv.com", "zee5-ssai-ads.akamaized.net"
]

def load_comprehensive_blocklist():
    global FULL_BLOCKLIST
    for d in BUILTIN_AD_DOMAINS:
        FULL_BLOCKLIST.add(d.lower())

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    blocklist_dir = os.path.join(base_dir, "blocklists", "smart-tv")
    
    if os.path.exists(blocklist_dir):
        for root, _, files in os.walk(blocklist_dir):
            for file in files:
                if file.endswith(".txt"):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith("#"):
                                    domain = line.replace("||", "").replace("^", "").replace("0.0.0.0 ", "").replace("127.0.0.1 ", "").strip()
                                    if domain and " " not in domain:
                                        FULL_BLOCKLIST.add(domain.lower())
                    except Exception as e:
                        print(f"[Blocklist-Loader] Error reading {file}: {e}")

    print(f"[Blocklist-Engine] Total Active Ad/Tracker Domains: {len(FULL_BLOCKLIST)}")
    return FULL_BLOCKLIST

def is_ad_domain(domain):
    domain = domain.lower().strip()
    if not domain:
        return False

    # 1. Exact or Subdomain Set Match
    if domain in FULL_BLOCKLIST:
        return True
    
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent_domain = ".".join(parts[i:])
        if parent_domain in FULL_BLOCKLIST:
            return True

    # 2. Wildcard Pattern Match (Brave/Opera Parity)
    for pattern in COMPILED_WILDCARDS:
        if pattern.match(domain):
            return True

    return False

if __name__ == "__main__":
    load_comprehensive_blocklist()
    print("Testing samsungads.com:", is_ad_domain("samsungads.com"))
    print("Testing pagead2.googlesyndication.com:", is_ad_domain("pagead2.googlesyndication.com"))
    print("Testing google.com:", is_ad_domain("google.com"))
