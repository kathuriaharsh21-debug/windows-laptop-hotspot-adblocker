# HotspotAdBlocker - Complete Windows Laptop Hotspot Ad Blocker
# Full rebuild - correct architecture that actually works

## WHY ADS WEREN'T BLOCKED (Root Cause)
# Windows Mobile Hotspot DHCP pushed NO DNS server to connected devices.
# Connected devices got DNS from JioFiber router (192.168.29.1), bypassing our sinkhole.
# 
## REAL SOLUTION ARCHITECTURE
#
# Layer 1: DNS Sinkhole (Port 53) — blocks 200k+ ad domains
#   - Runs on 0.0.0.0:53 (all interfaces)
#   - Windows Firewall rule FORCES all DNS (port 53 UDP) from hotspot subnet
#     through this server, even if devices are configured with other DNS
#
# Layer 2: Transparent HTTP Proxy (Port 8080)
#   - Injects Brave-equivalent scriptlets into HTML pages
#   - Strips ad JSON from YouTube API responses
#   - Windows netsh portproxy redirects port 80 traffic from hotspot subnet here
#
# Layer 3: Browser Extension (Chrome/Edge unpacked)
#   - For the laptop itself: blocks YouTube ads via DOM scriptlets
#   - Works exactly like Brave Shields inside the browser
#
# Layer 4: Dashboard (Port 3000)
#   - Real device detection via ARP + ICMP ping
#   - Live query log, blocked count, top blocked domains
#   - Default OFF, toggle to ON
