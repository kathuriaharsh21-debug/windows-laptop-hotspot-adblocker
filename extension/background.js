// background.js — Extension service worker
// Handles declarativeNetRequest rules for domain-level blocking

chrome.runtime.onInstalled.addListener(() => {
  console.log('[HotspotShield] Extension installed. Ad blocking active.');
});

// Report stats when popup requests them
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === 'getStats') {
    chrome.declarativeNetRequest.getMatchedRules({}, (rules) => {
      reply({ blocked: rules.rulesMatchedInfo ? rules.rulesMatchedInfo.length : 0 });
    });
    return true;
  }
});
