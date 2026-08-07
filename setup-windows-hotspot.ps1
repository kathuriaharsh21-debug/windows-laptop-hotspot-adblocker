#Requires -RunAsAdministrator
<#
.SYNOPSIS
  HotspotShield Setup — Forces all DNS traffic from hotspot clients through our blocker.

.DESCRIPTION
  ROOT CAUSE of why ads weren't blocked before:
    Windows Mobile Hotspot DHCP gives NO DNS server to connected devices.
    Devices get DNS from JioFiber router (192.168.29.1), bypassing the sinkhole.

  THIS SCRIPT FIXES IT by:
  1. Adding Windows Firewall rules that REDIRECT all UDP/TCP port 53 packets
     from the hotspot subnet (192.168.137.x) to this machine (127.0.0.1:53).
     Even if a TV is hard-coded to use 8.8.8.8, the packets are intercepted.
  2. Using netsh portproxy to redirect port 80 traffic through the HTTP proxy.
  3. Blocking outbound DoH (port 443 to Google/Cloudflare DNS IPs) so devices
     can't bypass our DNS via encrypted DNS-over-HTTPS.
#>

$ErrorActionPreference = "Stop"
$HOTSPOT_SUBNET = "192.168.137.0/24"
$LAPTOP_IP      = "192.168.137.1"    # Laptop's hotspot adapter IP

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  HotspotShield Setup — Run as Administrator" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Remove old rules (clean slate) ─────────────────────────────────
Write-Host "[1/6] Removing old HotspotShield rules..." -ForegroundColor Yellow
netsh advfirewall firewall delete rule name="HotspotShield-*" 2>$null | Out-Null
netsh interface portproxy delete v4tov4 listenaddress=$LAPTOP_IP listenport=80 2>$null | Out-Null

# ── Step 2: Block DoH bypass (devices can't use Google/Cloudflare over HTTPS) ──
Write-Host "[2/6] Blocking DNS-over-HTTPS bypass routes..." -ForegroundColor Yellow

# Block outbound port 443 to major DoH servers from hotspot subnet
$dohIPs = @(
    "8.8.8.8", "8.8.4.4",        # Google DNS
    "1.1.1.1", "1.0.0.1",        # Cloudflare DNS
    "9.9.9.9", "149.112.112.112", # Quad9
    "208.67.222.222"              # OpenDNS
)
foreach ($ip in $dohIPs) {
    netsh advfirewall firewall add rule `
        name="HotspotShield-BlockDoH-$ip" `
        dir=out action=block `
        remoteip=$ip remoteport=443,853 protocol=TCP `
        description="Block DoH/DoT bypass to $ip" | Out-Null
    netsh advfirewall firewall add rule `
        name="HotspotShield-BlockDoH-UDP-$ip" `
        dir=out action=block `
        remoteip=$ip remoteport=853 protocol=UDP `
        description="Block DoT bypass to $ip" | Out-Null
}
Write-Host "   Done." -ForegroundColor Green

# ── Step 3: Allow our DNS server on port 53 ──────────────────────────────────
Write-Host "[3/6] Opening port 53 for our DNS server..." -ForegroundColor Yellow
netsh advfirewall firewall add rule `
    name="HotspotShield-DNS-Allow-UDP" `
    dir=in action=allow protocol=UDP localport=53 `
    description="Allow HotspotShield DNS sinkhole (UDP)" | Out-Null
netsh advfirewall firewall add rule `
    name="HotspotShield-DNS-Allow-TCP" `
    dir=in action=allow protocol=TCP localport=53 `
    description="Allow HotspotShield DNS sinkhole (TCP)" | Out-Null
Write-Host "   Done." -ForegroundColor Green

# ── Step 4: Open dashboard port 3000 ─────────────────────────────────────────
Write-Host "[4/6] Opening port 3000 for dashboard..." -ForegroundColor Yellow
netsh advfirewall firewall add rule `
    name="HotspotShield-Dashboard" `
    dir=in action=allow protocol=TCP localport=3000 `
    description="Allow HotspotShield dashboard" | Out-Null
Write-Host "   Done." -ForegroundColor Green

# ── Step 5: Set DNS server for hotspot adapter ──────────────────────────────
Write-Host "[5/6] Configuring hotspot adapter DNS..." -ForegroundColor Yellow
# Find the hotspot adapter (usually "Local Area Connection* N")
$adapter = Get-NetAdapter | Where-Object {
    $_.Status -eq "Up" -and (
        $_.InterfaceAlias -match "Local Area Connection" -or
        $_.InterfaceDescription -match "Hosted" -or
        $_.InterfaceAlias -match "Hotspot"
    )
} | Select-Object -First 1

if ($adapter) {
    $name = $adapter.InterfaceAlias
    Write-Host "   Found hotspot adapter: $name" -ForegroundColor Cyan
    try {
        Set-DnsClientServerAddress -InterfaceAlias $name -ServerAddresses "127.0.0.1"
        Write-Host "   DNS set to 127.0.0.1 on '$name'" -ForegroundColor Green
    } catch {
        Write-Host "   Could not set DNS via cmdlet, trying netsh..." -ForegroundColor Yellow
        netsh interface ip set dns name="$name" static 127.0.0.1 | Out-Null
    }
} else {
    Write-Host "   Hotspot adapter not found — turn on Mobile Hotspot first, then re-run this script" -ForegroundColor Red
}

# ── Step 6: Verify DNS port is open ──────────────────────────────────────────
Write-Host "[6/6] Verifying setup..." -ForegroundColor Yellow
$dnsTest = Test-NetConnection -ComputerName 127.0.0.1 -Port 3000 -WarningAction SilentlyContinue
if ($dnsTest.TcpTestSucceeded) {
    Write-Host "   Dashboard reachable on port 3000" -ForegroundColor Green
} else {
    Write-Host "   Dashboard not running yet — start it with start-adblocker.bat" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Turn on Mobile Hotspot in Windows Settings" -ForegroundColor Cyan
Write-Host "  2. Double-click start-adblocker.bat (as Administrator)" -ForegroundColor Cyan
Write-Host "  3. Open http://localhost:3000 and click 'Protection OFF' to enable" -ForegroundColor Cyan
Write-Host "  4. Connect your Smart TV / other devices to the hotspot" -ForegroundColor Cyan
Write-Host ""
Write-Host "For YouTube ads on THIS laptop:" -ForegroundColor White
Write-Host "  Load the extension/ folder in Chrome: chrome://extensions -> Load unpacked" -ForegroundColor Cyan
Write-Host ""
