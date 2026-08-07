@echo off
TITLE Smart-TV Ad Blocker Toggle Switch
COLOR 0B
echo ===================================================================
echo 🛡️  Smart-TV Ad Blocker — Desktop Toggle Switch
echo ===================================================================
echo.

curl -s -X POST http://localhost:8080/api/mode/toggle > temp_toggle.json

if exist temp_toggle.json (
    type temp_toggle.json
    del temp_toggle.json
) else (
    echo [ERROR] Could not connect to API Gateway on http://localhost:8080.
    echo Please make sure start-adblocker.bat is running first.
)

echo.
echo ===================================================================
pause
