@echo off
TITLE Windows Laptop Hotspot Smart-TV Real Ad Blocker
COLOR 0A
echo ===================================================================
echo 🛡️  Starting REAL Windows Laptop Hotspot Smart-TV Ad Blocker...
echo ===================================================================
echo.
echo [1/2] Starting REAL DNS Sinkhole Server on UDP Port 53...
echo [2/2] Starting REAL Web Dashboard & REST API Server on http://localhost:3000...
echo.

python services\api_server.py

echo.
echo ===================================================================
echo Press any key to exit...
pause > nul
