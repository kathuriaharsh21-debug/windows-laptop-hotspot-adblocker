const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8080;

app.use(cors());
app.use(express.json());

let currentMode = 'Auto';
let ssaiMode = 'Strict-SSAI';

app.get('/api/ping', (req, res) => {
  res.json({
    status: 'ok',
    service: 'windows-hotspot-adblocker-gateway',
    timestamp: new Date().toISOString(),
    hotspot_active: true
  });
});

app.get('/api/mode', (req, res) => {
  res.json({
    mode: currentMode,
    ssai_mode: ssaiMode,
    active_profile: 'Windows-Hotspot-SmartTV-Strict'
  });
});

app.post('/api/mode/toggle', (req, res) => {
  currentMode = (currentMode === 'Paused') ? 'Auto' : 'Paused';
  modeLastUpdated = new Date().toISOString();
  console.log(`[API-Gateway] Toggle Switch Clicked! New Status: ${currentMode}`);
  res.json({
    success: true,
    enabled: currentMode !== 'Paused',
    mode: currentMode,
    message: currentMode === 'Paused' ? '🔴 Ad Blocker PAUSED (Bypass Mode Active)' : '🟢 Ad Blocker ACTIVE (Protection ON)'
  });
});

app.post('/api/mode/ssai', (req, res) => {
  const { ssai_enabled, buffer_tolerance_sec } = req.body;
  ssaiMode = ssai_enabled ? 'Strict-SSAI' : 'Standard';
  res.json({ success: true, ssai_mode: ssaiMode, buffer_tolerance_sec: buffer_tolerance_sec || 5 });
});

app.get('/api/devices', (req, res) => {
  res.json([
    { id: 'win-dev-1', mac: 'AA:BB:CC:11:22:33', name: 'Living Room Samsung TV (via Laptop Hotspot)', vendor: 'Samsung', ip: '192.168.137.10', adsBlockedToday: 1840 },
    { id: 'win-dev-2', mac: 'AA:BB:CC:44:55:66', name: 'Bedroom LG WebOS TV (via Laptop Hotspot)', vendor: 'LG', ip: '192.168.137.12', adsBlockedToday: 1120 },
    { id: 'win-dev-3', mac: 'AA:BB:CC:77:88:99', name: 'Kids Room Roku Express', vendor: 'Roku', ip: '192.168.137.15', adsBlockedToday: 2450 }
  ]);
});

app.get('/api/whitelist/candidates', (req, res) => {
  res.json([
    { id: 'cand-1', domain: 'image.tmdb.org', deviceName: 'Samsung TV', category: 'App Thumbnails' },
    { id: 'cand-2', domain: 'weather.vizio.com', deviceName: 'Fire TV', category: 'Weather Widget' }
  ]);
});

app.listen(PORT, () => {
  console.log(`[Windows-Hotspot API Gateway] Running on http://localhost:${PORT}`);
});
