# Terminal Hub - Background Starter
# Usage: powershell -File start_bg.ps1 [-tunnel]

param(
    [switch]$tunnel
)

$hubDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = "$hubDir\logs"
if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# --- Kill old instances ---
$oldPid = Get-NetTCPConnection -LocalPort 9091 -State Listen -ErrorAction SilentlyContinue |
          Select-Object -ExpandProperty OwningProcess
if ($oldPid) {
    Write-Host "[hub] Killing old server (PID $oldPid)..." -ForegroundColor Yellow
    Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# --- Start server ---
$serverLog = "$logDir\server_$timestamp.log"
$proc = Start-Process -WindowStyle Hidden -PassThru -FilePath "node" `
    -ArgumentList "$hubDir\server.js" `
    -RedirectStandardOutput $serverLog `
    -RedirectStandardError "$logDir\server_${timestamp}_err.log"

Write-Host "[hub] Server started (PID $($proc.Id)) -> http://localhost:9091" -ForegroundColor Green
Write-Host "[hub] Log: $serverLog" -ForegroundColor DarkGray

# --- Optionally start tunnel (ngrok) ---
if ($tunnel) {
    $ngrok = "$env:LOCALAPPDATA\Microsoft\WinGet\Links\ngrok.exe"
    if (!(Test-Path $ngrok)) {
        Write-Host "[tunnel] ngrok not found at $ngrok" -ForegroundColor Red
        exit 1
    }

    # Kill old ngrok
    Stop-Process -Name ngrok -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $tunnelLog = "$logDir\tunnel_$timestamp.log"
    Start-Process -NoNewWindow -FilePath $ngrok `
        -ArgumentList "http 9091 --log stdout" `
        -RedirectStandardOutput $tunnelLog `
        -RedirectStandardError "$logDir\tunnel_${timestamp}_err.log"

    # Wait for tunnel URL via ngrok API
    Write-Host "[tunnel] Starting ngrok tunnel..." -ForegroundColor Cyan
    $url = $null
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        try {
            $resp = Invoke-RestMethod -Uri "http://127.0.0.1:4040/api/tunnels" -ErrorAction SilentlyContinue
            if ($resp.tunnels.Count -gt 0) {
                $url = $resp.tunnels[0].public_url
                if ($url) {
                    $url | Out-File -FilePath "$hubDir\tunnel_url.txt" -Encoding utf8
                    Write-Host "[tunnel] $url" -ForegroundColor Green
                    break
                }
            }
        } catch {}
    }
    if (!$url) {
        Write-Host "[tunnel] Started but URL not yet available. Check http://127.0.0.1:4040" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "To stop:  powershell -File `"$hubDir\stop.ps1`"" -ForegroundColor DarkGray
