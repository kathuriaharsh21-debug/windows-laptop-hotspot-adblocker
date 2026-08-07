"""
blocklist_loader.py — Downloads and parses exact same filter lists as Brave Browser.

Brave's default filter sources (from adblock-resources/filter_lists/list_catalog.json):
  - EasyList
  - EasyPrivacy
  - uBlock Origin filters (general, privacy, badware, quick-fixes)
  - Brave-specific lists
  - StevenBlack unified hosts
  - URLhaus malware blocklist

Rule syntax supported:
  ||example.com^        -> block domain (ABP/uBlock standard)
  0.0.0.0 example.com  -> hosts-file format
  ! or # lines         -> comments, skipped

24-hour disk cache so lists don't re-download every run.
"""

import os
import re
import time
import urllib.request

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_DIR  = os.path.join(BASE_DIR, "blocklists", "cache")
CACHE_TTL  = 86400  # 24 hours

# ─── Brave's exact filter list sources ───────────────────────────────────────
SOURCES = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-general.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-2024.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters-2025.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/privacy.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt",
    "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/quick-fixes.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-specific.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-firstparty.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-lists/brave-android-specific.txt",
    "https://raw.githubusercontent.com/brave/adblock-lists/master/brave-unbreak.txt",
    "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh-online.txt",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]

# ─── Built-in high-priority domains (always loaded, even if network fails) ───
BUILTIN = {
    # Google ad network
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google-analytics.com", "adservice.google.com", "pagead2.googlesyndication.com",
    # Major ad exchanges
    "amazon-adsystem.com", "adnxs.com", "criteo.com", "criteo.net",
    "outbrain.com", "taboola.com", "rubiconproject.com", "pubmatic.com",
    "casalemedia.com", "openx.net", "scorecardresearch.com",
    "quantserve.com", "moatads.com", "advertising.com", "adroll.com",
    "mathtag.com", "adsrvr.org", "demdex.net", "everesttech.net",
    "lotame.com", "bluekai.com", "mediaplex.com", "turn.com",
    "adzerk.net", "zedo.com", "yieldmanager.com",
    # Smart TV ads & telemetry
    "samsungads.com", "samsungacr.com", "samsungcloudsolution.net",
    "log-ingestion.samsungcloud.com", "stats.samsungads.com",
    "ad.lgappstv.com", "lgsmartad.com", "us.info.lgsmartad.com", "rdl.lgtvcommon.com",
    "p.ads.roku.com", "cloudservices.roku.com", "ads.rokuroute.com",
    "device-metrics-us.amazon.com", "mads.amazon-adsystem.com",
    "tvads.vizio.com", "inscape.tv",
    # Indian streaming SSAI
    "ad-akamaized.net", "hotstar-ads.akamaized.net", "ssai-ads.hotstar.com",
    "ads.hotstar.com", "dai-sonyliv.com", "ssai-vizio.sonyliv.com",
    "ads.sonyliv.com", "zee5-ssai-ads.akamaized.net",
}

_DOMAIN_RE = re.compile(
    r"^\|\|([a-z0-9][a-z0-9\-\.]+[a-z0-9])\^", re.I
)
_HOSTS_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-z0-9][a-z0-9\.\-]+)$", re.I
)


def _fetch(url: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    name = re.sub(r"[^\w]", "_", url)[-80:] + ".cache"
    path = os.path.join(CACHE_DIR, name)

    if os.path.exists(path) and (time.time() - os.path.getmtime(path)) < CACHE_TTL:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", errors="ignore")
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(text)
        return text
    except Exception as e:
        print(f"[Blocklist] WARNING fetch failed: {url.split('/')[-1]} — {e}")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        return ""


def _parse(text: str) -> set:
    result = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in ("!", "#"):
            continue
        if line.startswith("@@"):
            continue     # exception rules — skip
        if "##" in line or "##+js" in line:
            continue     # cosmetic/scriptlet rules — DNS level irrelevant
        m = _DOMAIN_RE.match(line)
        if m:
            result.add(m.group(1).lower())
            continue
        m = _HOSTS_RE.match(line)
        if m:
            d = m.group(1).lower()
            if d not in ("localhost", "broadcasthost", "local"):
                result.add(d)
    return result


def load_blocklist() -> set:
    """Download Brave's filter lists, parse ABP/hosts rules, return domain set."""
    domains = set(BUILTIN)

    # Load local Smart TV text files
    local_dir = os.path.join(BASE_DIR, "blocklists", "smart-tv")
    if os.path.isdir(local_dir):
        for fn in os.listdir(local_dir):
            if fn.endswith(".txt"):
                try:
                    with open(os.path.join(local_dir, fn), encoding="utf-8", errors="ignore") as f:
                        domains.update(_parse(f.read()))
                except Exception:
                    pass

    # Download live Brave filter lists
    for url in SOURCES:
        name = url.split("/")[-1]
        print(f"[Blocklist] Loading {name}...")
        text = _fetch(url)
        if text:
            domains.update(_parse(text))

    print(f"[Blocklist] Loaded {len(domains):,} domains total")
    return domains


if __name__ == "__main__":
    bl = load_blocklist()
    for d in ["pagead2.googlesyndication.com", "samsungads.com", "ad-akamaized.net",
              "dai-sonyliv.com", "netflix.com", "google.com"]:
        print(f"  {d}: {'BLOCKED' if d in bl or any(d.endswith('.'+x) for x in bl) else 'ALLOWED'}")
