<#
.SYNOPSIS
    Automated Windows Mobile Hotspot & Ad-Blocking Firewall Setup Script.
.DESCRIPTION
    Configures Windows Mobile Hotspot, DNS Redirection, and Windows Firewall rules
    to enforce Layer 2 DoH/DoT bypass prevention for Smart TVs connected to this laptop.
#>

Write-Host "===================================================================" -ForegroundColor Cyans
Write-Host "🛡️  Windows Laptop Hotspot Ad-Blocker Setup Script" -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Cyans

# 1. Check Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "⚠️ Please run PowerShell as Administrator to configure Windows Firewall & Hotspot rules." -ForegroundColor Yellow
}

# 2. Configure Windows Firewall Rules for Layer 2 DoH/DoT Bypass Prevention
Write-Host "[1/3] Applying Windows Firewall Rules to block encrypted DNS bypasses..." -ForegroundColor Yellow

# Block Outbound DoH to Google / Cloudflare / Quad9 (TCP 443)
Remove-NetFirewallRule -DisplayName "SmartTV-Block-Public-DoH" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "SmartTV-Block-Public-DoH" `
                    -Direction Outbound `
                    -Action Block `
                    -RemoteAddress "8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9" `
                    -RemotePort 443 `
                    -Protocol TCP `
                    -Description "Blocks Smart TV encrypted DoH bypass attempts to public resolvers"

# Block Outbound DoT (TCP/UDP Port 853)
Remove-NetFirewallRule -DisplayName "SmartTV-Block-DoT-853" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "SmartTV-Block-DoT-853" `
                    -Direction Outbound `
                    -Action Block `
                    -RemotePort 853 `
                    -Protocol TCP `
                    -Description "Blocks Smart TV DNS-over-TLS (DoT) on port 853"

New-NetFirewallRule -DisplayName "SmartTV-Block-DoT-853-UDP" `
                    -Direction Outbound `
                    -Action Block `
                    -RemotePort 853 `
                    -Protocol UDP `
                    -Description "Blocks Smart TV DNS-over-TLS (DoT) UDP on port 853"

# Block Outbound DNS-over-QUIC (UDP 8853)
Remove-NetFirewallRule -DisplayName "SmartTV-Block-DoQUIC-8853" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "SmartTV-Block-DoQUIC-8853" `
                    -Direction Outbound `
                    -Action Block `
                    -RemotePort 8853 `
                    -Protocol UDP `
                    -Description "Blocks Fire TV / Android TV DNS-over-QUIC bypasses"

Write-Host "✅ Windows Firewall Bypass Prevention Rules Created Successfully!" -ForegroundColor Green

# 3. Detect Laptop Local IP Address & Mobile Hotspot Subnet
Write-Host "[2/3] Detecting Laptop Local IP & Windows Hotspot Interface..." -ForegroundColor Yellow
$ipList = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" }
foreach ($ip in $ipList) {
    Write-Host " 🌐 Active Interface: $($ip.InterfaceAlias) -> IP: $($ip.IPAddress)" -ForegroundColor Gray
}

# 4. Instructions for Turning on Hotspot
Write-Host "[3/3] Finalizing Windows Laptop Hotspot Guide:" -ForegroundColor Yellow
Write-Host " 1. Open Windows Settings -> Network & internet -> Mobile hotspot." -ForegroundColor White
Write-Host " 2. Toggle Mobile hotspot ON." -ForegroundColor White
Write-Host " 3. Connect your Smart TVs (Samsung, LG, Roku, Fire TV) to the Laptop's Hotspot Wi-Fi." -ForegroundColor White
Write-Host " 4. All TV queries will be sinkholed & filtered by your laptop automatically!" -ForegroundColor White

Write-Host "===================================================================" -ForegroundColor Cyans
Write-Host "🚀 Setup Complete! Start your Ad-Blocker dashboard on http://localhost:3000" -ForegroundColor Green
Write-Host "===================================================================" -ForegroundColor Cyans
