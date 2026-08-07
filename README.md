# 💻 Windows Laptop Hotspot Smart-TV Ad Blocker

A standalone, network-wide ad, telemetry, and SSAI video ad blocker that turns your **Windows Laptop Mobile Hotspot** into a complete ad-blocking router for Smart TVs (Samsung, LG WebOS, Roku, Fire TV, Android TV) without requiring any extra router hardware!

---

## 🌟 Features

1. **Zero Extra Router Needed**: Uses Windows built-in **Mobile Hotspot** feature to route all Smart TV traffic through your laptop.
2. **Layer 4 SNI SSAI Video Ad Engine**: Inspects `TLS ClientHello` packet headers to drop SonyLIV & Hotstar ad-serving subdomains without SSL certificate errors.
3. **Automated Windows Firewall Bypass Prevention**: Includes [`setup-windows-hotspot.ps1`](file:///d:/Study%20M/router_addBlocker/windows-laptop-hotspot-adblocker/setup-windows-hotspot.ps1) script that blocks outbound port 443/853 Google/Cloudflare DoH/DoT bypasses from connected TVs.
4. **Smart TV Manufacturer Blocklists**: Samsung Ads/ACR, LG WebOS SmartAd, Roku tracking, Amazon device metrics, and SSAI ad-node lists.
5. **Glassmorphism Command Center Dashboard**: Real-time query rate gauges, device manager, 1-click "An App Just Broke" candidate domain whitelist workflow, and SSAI load delay controls.

---

## 🚀 Quick Start on Windows

1. Right-click [`setup-windows-hotspot.ps1`](file:///d:/Study%20M/router_addBlocker/windows-laptop-hotspot-adblocker/setup-windows-hotspot.ps1) and select **Run with PowerShell** (as Administrator).
2. Open Windows Settings -> **Network & internet** -> **Mobile hotspot** -> Turn **ON**.
3. Connect your Smart TVs to your laptop's Mobile Hotspot Wi-Fi.
4. Double-click `start-adblocker.bat` and open **`http://localhost:3000`**.
