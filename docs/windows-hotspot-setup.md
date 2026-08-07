# 💻 Windows Laptop Hotspot Smart-TV Ad Blocker — Setup Guide

This standalone project turns your Windows laptop into a network-wide ad, telemetry, and SSAI video ad blocker for Smart TVs without needing any second router or hardware!

---

## 🌟 Topology: How It Works

```
 Internet 
    │
    ▼
┌─────────────────────────────────────────┐
│ JioFiber / ISP Router (Untouched)       │
└──────────────────┬──────────────────────┘
                   │ (Laptop Wi-Fi / LAN connection)
                   ▼
┌─────────────────────────────────────────┐
│ Your Windows Laptop                     │
│ (Runs Hotspot + AdGuard + Layer 4 SNI)  │
└──────────────────┬──────────────────────┘
                   │ (Windows Mobile Hotspot Wi-Fi)
                   ▼
┌─────────────────────────────────────────┐
│ Smart TVs (Samsung, LG, Roku, Fire TV)  │
│ (Connected to Laptop's Hotspot Wi-Fi)   │
└─────────────────────────────────────────┘
```

---

## 🚀 Quick Setup Instructions

### 1. Run PowerShell Setup Script (As Administrator)
Open PowerShell as Administrator in this folder and run:
```powershell
.\setup-windows-hotspot.ps1
```
This automatically configures Windows Firewall rules to block encrypted DoH/DoT bypasses from Smart TVs.

### 2. Turn On Windows Mobile Hotspot
1. Go to Windows **Settings** -> **Network & internet** -> **Mobile hotspot**.
2. Toggle **Mobile hotspot** to **ON**.
3. Set your Hotspot Wi-Fi name (e.g. `SmartTV-Hotspot`).

### 3. Connect Smart TVs to Laptop Hotspot
- Connect Samsung TV, LG WebOS TV, Roku, or Fire TV to `SmartTV-Hotspot`.

### 4. Start the Ad Blocker Dashboard & Microservices
Double-click `start-adblocker.bat` or run:
```bash
npm start
```
Open your browser at **`http://localhost:3000`**.

---

## 🎬 Hotstar & SonyLIV SSAI Video Ad Splicing
This system includes a dedicated **Layer 4 SNI Filter** (`services/firewall-manager/sni_filter.js`) that inspects TLS ClientHello headers and drops connection attempts to Hotstar & SonyLIV ad-serving subdomains without SSL certificate errors.

- **Initial Load Buffer**: Allow **3 to 5 seconds** when starting a stream on SonyLIV or Hotstar while the video player retries clean content segments.
