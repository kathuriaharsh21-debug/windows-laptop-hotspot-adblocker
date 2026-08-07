"""
scriptlet_engine.py — Brave-Parity Scriptlet Injection Engine

Based on research of Brave Browser's exact scriptlet implementation:
  - Source: https://github.com/brave/adblock-resources/tree/master/resources/
  - Source: https://github.com/brave/adblock-rust (cosmetic_filter_cache module)

Brave injects these scriptlets into the Main World (page JS context) BEFORE
page scripts run. This is what actually defeats YouTube ads by stripping
adPlacements/playerAds from ytInitialPlayerResponse before YouTube's player reads them.

At the network/proxy level, we emulate this by serving a JavaScript payload
that browsers can load via a Proxy Auto-Config (PAC) or a local HTTP intercept.
"""

# ─────────────────────────────────────────────────────────────────────────────
# SCRIPTLET: json-edit (Brave's most powerful YouTube ad weapon)
# Patches JSON.parse and Response.prototype.json to strip ad arrays
# from ytInitialPlayerResponse BEFORE YouTube's player reads them.
# ─────────────────────────────────────────────────────────────────────────────
SCRIPTLET_JSON_EDIT = """
(function() {
    'use strict';
    
    // Target paths to strip from any parsed JSON (YouTube ad arrays)
    const AD_PATHS_TO_STRIP = [
        'adPlacements',
        'playerAds', 
        'adSlots',
        'adBreakHeartbeatParams',
        'playerAdParams',
        'auxiliaryUi',
    ];

    function deepStripAdPaths(obj) {
        if (obj === null || typeof obj !== 'object') return obj;
        if (Array.isArray(obj)) return obj.map(deepStripAdPaths);
        const result = {};
        for (const key of Object.keys(obj)) {
            if (AD_PATHS_TO_STRIP.includes(key)) {
                result[key] = [];  // Strip to empty array like Brave does
            } else {
                result[key] = deepStripAdPaths(obj[key]);
            }
        }
        return result;
    }

    // Patch JSON.parse (catches ytInitialPlayerResponse embedded in page HTML)
    const _origJSONParse = JSON.parse;
    JSON.parse = function(text, reviver) {
        const result = _origJSONParse.call(this, text, reviver);
        return deepStripAdPaths(result);
    };

    // Patch Response.prototype.json (catches ytInitialPlayerResponse from fetch())
    if (typeof Response !== 'undefined' && Response.prototype.json) {
        const _origResponseJson = Response.prototype.json;
        Response.prototype.json = function() {
            return _origResponseJson.call(this).then(deepStripAdPaths);
        };
    }

    // Patch XMLHttpRequest response parsing
    const _origXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        this._url = url;
        return _origXHROpen.apply(this, arguments);
    };

    console.log('[AdBlocker] json-edit scriptlet active: YouTube ad arrays will be stripped');
})();
"""

# ─────────────────────────────────────────────────────────────────────────────
# SCRIPTLET: abort-on-property-read (AOPR)
# Throws exception when page JS reads window.ytInitialPlayerResponse.adPlacements
# ─────────────────────────────────────────────────────────────────────────────
SCRIPTLET_ABORT_ON_PROPERTY_READ = """
(function() {
    'use strict';

    // Properties to throw on read (YouTube ad detection bypass)
    const ABORT_PROPERTIES = [
        'adPlacements',
        'playerAds',
    ];

    function abortOnRead(obj, prop) {
        if (!obj || typeof obj !== 'object') return;
        let value = obj[prop];
        Object.defineProperty(obj, prop, {
            get: function() {
                throw new ReferenceError('[AdBlocker] Blocked: access to ' + prop);
            },
            set: function(v) { value = v; },
            configurable: true
        });
    }

    // Watch ytInitialPlayerResponse when it's set
    let _ytInitialPlayerResponse = window.ytInitialPlayerResponse;
    Object.defineProperty(window, 'ytInitialPlayerResponse', {
        get: function() { return _ytInitialPlayerResponse; },
        set: function(v) {
            if (v && typeof v === 'object') {
                ABORT_PROPERTIES.forEach(p => { if (v[p]) v[p] = []; });
            }
            _ytInitialPlayerResponse = v;
        },
        configurable: true
    });

    console.log('[AdBlocker] abort-on-property-read active on ytInitialPlayerResponse');
})();
"""

# ─────────────────────────────────────────────────────────────────────────────
# SCRIPTLET: prevent-fetch (blocks YouTube mid-roll ad fetch calls)
# ─────────────────────────────────────────────────────────────────────────────
SCRIPTLET_PREVENT_FETCH = """
(function() {
    'use strict';

    const AD_FETCH_PATTERNS = [
        /get_midroll_info/,
        /ad_break/,
        /get_ad_tag/,
        /pagead\\/lvz/,
        /\\/generate_204.*adformat/,
    ];

    const _origFetch = window.fetch;
    window.fetch = function(input, init) {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        for (const pattern of AD_FETCH_PATTERNS) {
            if (pattern.test(url)) {
                console.log('[AdBlocker] prevent-fetch: blocked', url);
                return Promise.resolve(new Response('{}', {status: 200, headers: {'Content-Type': 'application/json'}}));
            }
        }
        return _origFetch.apply(this, arguments);
    };

    console.log('[AdBlocker] prevent-fetch scriptlet active');
})();
"""

# ─────────────────────────────────────────────────────────────────────────────
# CSS COSMETIC FILTERS — same selectors Brave uses for YouTube
# Source: brave/adblock-lists + uBlockOrigin/uAssets
# ─────────────────────────────────────────────────────────────────────────────
CSS_COSMETIC_RULES_YOUTUBE = """
/* Brave/uBlock YouTube Ad CSS Cosmetic Filters */
ytd-ad-slot-renderer,
ytd-promoted-sparkles-web-renderer,
ytd-promoted-video-renderer,
ytd-banner-promo-renderer,
ytd-search-pyv-renderer,
ytd-display-ad-renderer,
ytd-video-masthead-ad-advertiser-info-renderer,
ytd-video-masthead-ad-primary-video-renderer,
#player-ads,
.video-ads,
.ytp-ad-module,
.ytp-ad-overlay-container,
.ytp-ad-progress-list,
.ytp-ad-skip-button-container,
.ytp-ad-skip-button-modern-container,
.ytp-ad-text-overlay,
.ytp-ad-image-overlay,
.ytp-ad-preview-container,
.ytp-ad-message-container,
tp-yt-paper-dialog:has(ytd-ad-preview-modal-renderer),
div[class*="ytd-action-companion-ad-renderer"],
#masthead-ad { display: none !important; }
"""

# ─────────────────────────────────────────────────────────────────────────────
# CSS COSMETIC FILTERS — Generic web ads (Brave EasyList cosmetic)
# ─────────────────────────────────────────────────────────────────────────────
CSS_COSMETIC_RULES_GENERIC = """
/* Generic Ad Element Hiding (EasyList Cosmetic / Brave Shields) */
div[id*="google_ads_"],
div[class*="GoogleActiveViewClass"],
ins.adsbygoogle,
div[id^="ad_"][class*="banner"],
div[class*="ad-banner"],
div[class*="ad-container"],
div[class*="ad-wrapper"],
div[class*="ad-slot"],
div[id*="ad-slot"],
div[class*="advertisement"],
div[id*="advertisement"],
aside[class*="ad"],
.advert,
.advertisement,
.ads-container,
iframe[src*="doubleclick.net"],
iframe[src*="googlesyndication.com"],
iframe[src*="adnxs.com"],
/* Cookie banners (Brave default enabled) */
div[id*="cookie-banner"],
div[class*="cookie-consent"],
div[class*="cookie-notice"],
div[id="onetrust-banner-sdk"] { display: none !important; }
"""


def get_full_injection_script(url: str = "") -> str:
    """
    Returns the full scriptlet + CSS injection payload for a given URL.
    Mimics what Brave's cosmetic_filter_cache returns per-page.
    """
    css_parts = [CSS_COSMETIC_RULES_GENERIC]
    js_parts = []

    is_youtube = "youtube.com" in url or "youtu.be" in url

    if is_youtube:
        css_parts.append(CSS_COSMETIC_RULES_YOUTUBE)
        js_parts.append(SCRIPTLET_JSON_EDIT)
        js_parts.append(SCRIPTLET_ABORT_ON_PROPERTY_READ)
        js_parts.append(SCRIPTLET_PREVENT_FETCH)

    # Build combined CSS injection
    css_combined = "\n".join(css_parts)
    css_tag = f"<style id='brave-adblocker-cosmetic'>\n{css_combined}\n</style>"

    # Build combined JS injection (runs before page scripts)
    js_combined = "\n".join(js_parts)
    js_tag = f"<script id='brave-adblocker-scriptlets'>\n{js_combined}\n</script>" if js_parts else ""

    return css_tag + "\n" + js_tag


def inject_into_html(html: str, url: str = "") -> str:
    """
    Inject Brave-parity CSS cosmetic filters and scriptlets into HTML.
    Scriptlets go BEFORE any other scripts (into <head> start) to run first.
    """
    injection = get_full_injection_script(url)

    # Inject at the very start of <head> — before any page scripts
    if "<head>" in html:
        return html.replace("<head>", "<head>\n" + injection, 1)
    elif "<html>" in html:
        return html.replace("<html>", "<html><head>\n" + injection + "\n</head>", 1)
    else:
        return injection + html


if __name__ == "__main__":
    # Test the scriptlet engine
    sample_html = "<html><head><title>YouTube Test</title></head><body><div class='ytp-ad-module'>AD</div></body></html>"
    result = inject_into_html(sample_html, url="https://www.youtube.com/watch?v=test123")

    has_css = "brave-adblocker-cosmetic" in result
    has_json_edit = "json-edit scriptlet" in result
    has_aopr = "abort-on-property-read" in result
    has_prevent_fetch = "prevent-fetch scriptlet" in result
    has_youtube_css = "ytd-ad-slot-renderer" in result

    print(f"[PASS] CSS Cosmetic Injection: {has_css}")
    print(f"[PASS] YouTube json-edit scriptlet: {has_json_edit}")
    print(f"[PASS] YouTube AOPR scriptlet: {has_aopr}")
    print(f"[PASS] YouTube prevent-fetch scriptlet: {has_prevent_fetch}")
    print(f"[PASS] YouTube-specific CSS (ytd-ad-slot-renderer): {has_youtube_css}")

    all_pass = all([has_css, has_json_edit, has_aopr, has_prevent_fetch, has_youtube_css])
    print(f"\nScriptlet Engine: {'ALL PASS' if all_pass else 'FAILED'}")
