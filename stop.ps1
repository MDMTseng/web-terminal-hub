# Terminal Hub - Stop all services

# Stop server
$serverPid = Get-NetTCPConnection -LocalPort 9091 -State Listen -ErrorAction SilentlyContinue |
             Select-Object -ExpandProperty OwningProcess
if ($serverPid) {
    Stop-Process -Id $serverPid -Force
    Write-Host "[hub] Server stopped (PID $serverPid)" -ForegroundColor Yellow
} else {
    Write-Host "[hub] Server not running" -ForegroundColor DarkGray
}

# Stop tunnel (ngrok or cloudflared)
$ng = Get-Process ngrok -ErrorAction SilentlyContinue
$cf = Get-Process cloudflared -ErrorAction SilentlyContinue
if ($ng) {
    Stop-Process -Name ngrok -Force
    Write-Host "[tunnel] ngrok stopped" -ForegroundColor Yellow
} elseif ($cf) {
    Stop-Process -Name cloudflared -Force
    Write-Host "[tunnel] cloudflared stopped" -ForegroundColor Yellow
} else {
    Write-Host "[tunnel] Tunnel not running" -ForegroundColor DarkGray
}
