@echo off
TITLE Windows Laptop Hotspot Smart-TV Ad Blocker
COLOR 0A
echo ===================================================================
echo 🛡️  Starting Windows Laptop Hotspot Smart-TV Ad Blocker...
echo ===================================================================
echo.
echo 1. Starting API Gateway on http://localhost:8080...
start /b node services/api-gateway/index.js > gateway.log 2>&1

echo 2. Starting Layer 4 SNI SSAI Filter Module on port 8443...
start /b node services/firewall-manager/sni_filter.js > sni_filter.log 2>&1

echo 3. Starting Glassmorphism Command Center Dashboard on http://localhost:3000...
start /b node frontend/server.js > frontend.log 2>&1

echo.
echo ===================================================================
echo 🟢 All services running!
echo 🌐 Open Dashboard: http://localhost:3000
echo 📡 Turn on Windows Mobile Hotspot & Connect Smart TVs to Laptop Wi-Fi
echo ===================================================================
echo Press any key to stop all services...
pause > nul

taskkill /F /IM node.exe /T
