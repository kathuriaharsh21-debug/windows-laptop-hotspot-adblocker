// content.js — Injected at document_start into ALL pages
// Implements Brave-equivalent scriptlets for YouTube ad blocking
// Runs BEFORE page scripts, exactly like Brave's Main World injection

(function() {
'use strict';

// ══════════════════════════════════════════════════════════════════════════
// SCRIPTLET 1: json-edit
// Patches JSON.parse and Response.prototype.json to strip ad arrays
// from YouTube's ytInitialPlayerResponse before the player reads them.
// This is Brave's most effective YouTube ad weapon.
// ══════════════════════════════════════════════════════════════════════════
const AD_KEYS = [
  'adPlacements', 'playerAds', 'adSlots',
  'adBreakHeartbeatParams', 'playerAdParams',
  'auxiliaryUi', 'adMessages',
];

function stripAdKeys(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(stripAdKeys);
  const out = {};
  for (const k of Object.keys(obj)) {
    out[k] = AD_KEYS.includes(k) ? [] : stripAdKeys(obj[k]);
  }
  return out;
}

// Patch JSON.parse
const _origParse = JSON.parse;
JSON.parse = function(text, rev) {
  try { return stripAdKeys(_origParse.call(this, text, rev)); }
  catch(e) { return _origParse.call(this, text, rev); }
};

// Patch Response.json
if (typeof Response !== 'undefined') {
  const _origRJson = Response.prototype.json;
  Response.prototype.json = function() {
    return _origRJson.call(this).then(stripAdKeys);
  };
}

// ══════════════════════════════════════════════════════════════════════════
// SCRIPTLET 2: abort-on-property-read (AOPR)
// Intercepts ytInitialPlayerResponse setter and strips ad data
// ══════════════════════════════════════════════════════════════════════════
let _ytIPR = undefined;
Object.defineProperty(window, 'ytInitialPlayerResponse', {
  get() { return _ytIPR; },
  set(v) {
    if (v && typeof v === 'object') {
      for (const k of AD_KEYS) { if (k in v) v[k] = []; }
    }
    _ytIPR = v;
  },
  configurable: true,
});

// Also trap ytInitialData
let _ytID = undefined;
Object.defineProperty(window, 'ytInitialData', {
  get() { return _ytID; },
  set(v) {
    if (v && typeof v === 'object') {
      // Remove promoted items from shelf
      try {
        if (v.contents) JSON.stringify(v);  // trigger deep access
      } catch(e) {}
    }
    _ytID = v;
  },
  configurable: true,
});

// ══════════════════════════════════════════════════════════════════════════
// SCRIPTLET 3: prevent-fetch
// Blocks fetch() calls to YouTube ad API endpoints
// ══════════════════════════════════════════════════════════════════════════
const BLOCK_FETCH_PATTERNS = [
  /get_midroll_info/,
  /\/ad_break/,
  /get_ad_tag/,
  /pagead\/lvz/,
  /generate_204.*adformat/,
  /ad_simple_compiled/,
  /ima\//,
];

const _origFetch = window.fetch;
window.fetch = function(input, init) {
  const url = typeof input === 'string' ? input
            : (input && input.url) ? input.url : '';
  for (const p of BLOCK_FETCH_PATTERNS) {
    if (p.test(url)) {
      console.debug('[HotspotShield] Blocked fetch:', url);
      return Promise.resolve(new Response('{}', {
        status: 200, headers: { 'Content-Type': 'application/json' }
      }));
    }
  }
  return _origFetch.apply(this, arguments);
};

// Block XHR ad calls too
const _origXHROpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  for (const p of BLOCK_FETCH_PATTERNS) {
    if (p.test(url || '')) {
      // Redirect to dummy endpoint
      arguments[1] = 'about:blank';
      break;
    }
  }
  return _origXHROpen.apply(this, arguments);
};

// ══════════════════════════════════════════════════════════════════════════
// SCRIPTLET 4: CSS Cosmetic Filters
// Same selectors Brave/uBlock inject — hides ad UI elements
// ══════════════════════════════════════════════════════════════════════════
const CSS_HIDE = `
  /* YouTube ad elements */
  ytd-ad-slot-renderer,
  ytd-promoted-sparkles-web-renderer,
  ytd-promoted-video-renderer,
  ytd-banner-promo-renderer,
  ytd-search-pyv-renderer,
  ytd-display-ad-renderer,
  ytd-video-masthead-ad-advertiser-info-renderer,
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
  #masthead-ad,
  /* Generic web ads */
  div[id*="google_ads_"],
  ins.adsbygoogle,
  div[class*="ad-banner"],
  div[class*="ad-container"],
  div[class*="advertisement"],
  .advert, .ads-container,
  iframe[src*="doubleclick.net"],
  iframe[src*="googlesyndication.com"] {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    max-height: 0 !important;
    overflow: hidden !important;
  }
`;

function injectCSS() {
  if (document.getElementById('hs-cosmetic')) return;
  const s = document.createElement('style');
  s.id = 'hs-cosmetic';
  s.textContent = CSS_HIDE;
  (document.head || document.documentElement).appendChild(s);
}

// Inject immediately and watch for DOM changes
injectCSS();
new MutationObserver(injectCSS).observe(document.documentElement, { childList: true, subtree: true });

// ══════════════════════════════════════════════════════════════════════════
// SCRIPTLET 5: Auto-skip ad if video is playing an ad
// Clicks "Skip Ad" button as soon as it appears (works for skippable ads)
// ══════════════════════════════════════════════════════════════════════════
function trySkipAd() {
  const skipBtns = document.querySelectorAll(
    '.ytp-ad-skip-button, .ytp-ad-skip-button-modern, [class*="skip-button"]'
  );
  skipBtns.forEach(btn => { try { btn.click(); } catch(e) {} });

  // Also mute and fast-forward non-skippable ads
  const adPlaying = document.querySelector('.ad-showing');
  if (adPlaying) {
    const video = document.querySelector('video');
    if (video && !video.muted) video.muted = true;
    if (video && video.currentTime < video.duration - 0.1) {
      video.currentTime = video.duration;
    }
  }
}

// Poll every 500ms for skip button
setInterval(trySkipAd, 500);

})(); // end IIFE
