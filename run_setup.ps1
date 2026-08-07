# HotspotShield Windows Firewall Setup
param()

Write-Host "[1/5] Removing old HotspotShield firewall rules..."
netsh advfirewall firewall delete rule name="HotspotShield-DNS-UDP" 2>&1 | Out-Null
netsh advfirewall firewall delete rule name="HotspotShield-DNS-TCP" 2>&1 | Out-Null
netsh advfirewall firewall delete rule name="HotspotShield-Dashboard" 2>&1 | Out-Null
$dohIPs = @("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112")
foreach ($ip in $dohIPs) {
    netsh advfirewall firewall delete rule name="HotspotShield-BlockDoH-$ip" 2>&1 | Out-Null
    netsh advfirewall firewall delete rule name="HotspotShield-BlockDoH-UDP-$ip" 2>&1 | Out-Null
}

Write-Host "[2/5] Blocking DNS-over-HTTPS bypass routes..."
foreach ($ip in $dohIPs) {
    netsh advfirewall firewall add rule name="HotspotShield-BlockDoH-$ip" dir=out action=block remoteip=$ip remoteport=853 protocol=TCP | Out-Null
    netsh advfirewall firewall add rule name="HotspotShield-BlockDoH-UDP-$ip" dir=out action=block remoteip=$ip remoteport=853 protocol=UDP | Out-Null
}
Write-Host "   Done - DoH blocked"

Write-Host "[3/5] Opening port 53 for DNS sinkhole..."
netsh advfirewall firewall add rule name="HotspotShield-DNS-UDP" dir=in action=allow protocol=UDP localport=53 | Out-Null
netsh advfirewall firewall add rule name="HotspotShield-DNS-TCP" dir=in action=allow protocol=TCP localport=53 | Out-Null
Write-Host "   Done - port 53 open"

Write-Host "[4/5] Opening port 3000 for dashboard..."
netsh advfirewall firewall add rule name="HotspotShield-Dashboard" dir=in action=allow protocol=TCP localport=3000 | Out-Null
Write-Host "   Done - port 3000 open"

Write-Host "[5/5] Configuring hotspot adapter DNS..."
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and ($_.InterfaceAlias -match "Local Area Connection" -or $_.InterfaceDescription -match "Hosted" -or $_.InterfaceAlias -match "Hotspot") } | Select-Object -First 1
if ($adapter) {
    $name = $adapter.InterfaceAlias
    Write-Host "   Found adapter: $name"
    try {
        Set-DnsClientServerAddress -InterfaceAlias $name -ServerAddresses "127.0.0.1"
        Write-Host "   DNS set to 127.0.0.1"
    } catch {
        netsh interface ip set dns name="$name" static 127.0.0.1 | Out-Null
        Write-Host "   DNS set via netsh"
    }
} else {
    Write-Host "   No hotspot adapter active - turn on Mobile Hotspot and re-run this script"
}

Write-Host ""
Write-Host "SETUP COMPLETE" -ForegroundColor Green
