$ngrok = "C:\Users\TRS001\AppData\Local\Microsoft\WinGet\Links\ngrok.exe"
$logDir = "C:\Users\TRS001\Documents\workspace\claudePrj\cludefiles\web-terminal-hub\logs"

for ($i = 0; $i -lt 8; $i++) {
    Write-Host "Attempt $($i + 1)..."
    $p = Start-Process -FilePath $ngrok -ArgumentList "http","9091" -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 8
    if (-not $p.HasExited) {
        Write-Host "ngrok started! PID: $($p.Id)"
        # Get tunnel URL
        Start-Sleep -Seconds 2
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:4040/api/tunnels" -UseBasicParsing
            $data = $resp.Content | ConvertFrom-Json
            Write-Host "Tunnel URL: $($data.tunnels[0].public_url)"
        } catch {
            Write-Host "Could not get tunnel URL yet"
        }
        exit 0
    } else {
        Write-Host "ngrok exited, retrying in 15s..."
        Start-Sleep -Seconds 15
    }
}
Write-Host "Failed to start ngrok after 8 attempts"
exit 1
