#!/bin/bash
# Web Terminal Hub - Start Script
# Starts the hub server + Cloudflare tunnel

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLOUDFLARED="/c/Users/TRS001/bin/cloudflared.exe"
HUB_PORT="${HUB_PORT:-8080}"

echo "====================================="
echo "  Web Terminal Hub"
echo "====================================="
echo ""

# Kill any existing ttyd/hub processes
echo "[*] Cleaning up old processes..."
taskkill /F /IM ttyd.exe 2>/dev/null
taskkill /F /IM cloudflared.exe 2>/dev/null

# Start the hub server in background
echo "[*] Starting hub server on port $HUB_PORT..."
cd "$SCRIPT_DIR"
node server.js &
HUB_PID=$!
sleep 2

# Check if hub started
if ! kill -0 $HUB_PID 2>/dev/null; then
  echo "[!] Hub server failed to start!"
  exit 1
fi

echo "[*] Hub server running (PID: $HUB_PID)"

# Start Cloudflare tunnel
echo "[*] Starting Cloudflare tunnel..."
"$CLOUDFLARED" tunnel --url "http://localhost:$HUB_PORT" 2>&1 &
CF_PID=$!

echo ""
echo "[*] Waiting for tunnel URL..."
sleep 8

echo ""
echo "====================================="
echo "  Hub is ready!"
echo "  Local:  http://localhost:$HUB_PORT"
echo "  Check cloudflared output above for"
echo "  your public tunnel URL"
echo "====================================="
echo ""
echo "Press Ctrl+C to stop everything"

# Wait and cleanup on exit
trap "echo 'Shutting down...'; kill $HUB_PID $CF_PID 2>/dev/null; taskkill /F /IM ttyd.exe 2>/dev/null; exit 0" INT TERM
wait
