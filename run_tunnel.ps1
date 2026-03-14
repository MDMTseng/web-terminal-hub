# Wrapper: starts ngrok and writes the tunnel URL to a file
$hubDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = "$hubDir\logs"
$urlFile = "$hubDir\tunnel_url.txt"
$ngrok = "$env:APPDATA\npm\node_modules\ngrok\bin\ngrok.exe"

if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

# Clear old URL
"starting..." | Out-File -FilePath $urlFile -Encoding utf8

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outLog = "$logDir\tunnel_${timestamp}.log"
$errLog = "$logDir\tunnel_${timestamp}_err.log"

# Start ngrok
$proc = Start-Process -NoNewWindow -PassThru -FilePath $ngrok `
    -ArgumentList "http 9091 --log stdout" `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError $errLog

# Wait for tunnel URL from ngrok API (up to 20s)
for ($i = 0; $i -lt 20; $i++) {
    Start-Sleep -Seconds 1
    try {
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:4040/api/tunnels" -ErrorAction SilentlyContinue
        if ($resp.tunnels.Count -gt 0) {
            $url = $resp.tunnels[0].public_url
            if ($url) {
                $url | Out-File -FilePath $urlFile -Encoding utf8
                break
            }
        }
    } catch {}
}

# Keep script alive while ngrok runs
if ($proc -and !$proc.HasExited) {
    $proc.WaitForExit()
}
