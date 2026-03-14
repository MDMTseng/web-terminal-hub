# Terminal Hub - Install as Windows Scheduled Task
# Run this once: powershell -ExecutionPolicy Bypass -File install_service.ps1
# Options:
#   -WithTunnel   Also start cloudflare tunnel
#   -Uninstall    Remove the scheduled tasks

param(
    [switch]$WithTunnel,
    [switch]$Uninstall
)

$taskNameServer = "TerminalHub-Server"
$taskNameTunnel = "TerminalHub-Tunnel"
$hubDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$logDir = "$hubDir\logs"

if ($Uninstall) {
    Write-Host "Removing scheduled tasks..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskNameServer -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskNameTunnel -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Done. Tasks removed." -ForegroundColor Green
    exit 0
}

# Ensure log dir
if (!(Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

# --- Server Task ---
Write-Host "Creating task: $taskNameServer" -ForegroundColor Cyan

# Remove old if exists
Unregister-ScheduledTask -TaskName $taskNameServer -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction `
    -Execute "node.exe" `
    -Argument "`"$hubDir\server.js`"" `
    -WorkingDirectory $hubDir

# Trigger: at user logon + allow manual start
$trigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365)

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskNameServer `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Web Terminal Hub - node server on port 9091" | Out-Null

Write-Host "[OK] Server task created - starts at logon" -ForegroundColor Green

# --- Tunnel Task (optional) ---
if ($WithTunnel) {
    $cloudflared = "$env:USERPROFILE\bin\cloudflared.exe"
    if (!(Test-Path $cloudflared)) {
        Write-Host "[SKIP] cloudflared not found at $cloudflared" -ForegroundColor Red
    } else {
        Write-Host "Creating task: $taskNameTunnel" -ForegroundColor Cyan

        Unregister-ScheduledTask -TaskName $taskNameTunnel -Confirm:$false -ErrorAction SilentlyContinue

        $tunnelAction = New-ScheduledTaskAction `
            -Execute "powershell.exe" `
            -Argument "-ExecutionPolicy Bypass -File `"$hubDir\run_tunnel.ps1`"" `
            -WorkingDirectory $hubDir

        # Start 5 seconds after server (delayed trigger)
        $tunnelTrigger = New-ScheduledTaskTrigger -AtLogOn
        $tunnelTrigger.Delay = 'PT10S'  # 10 second delay after logon

        Register-ScheduledTask `
            -TaskName $taskNameTunnel `
            -Action $tunnelAction `
            -Trigger $tunnelTrigger `
            -Settings $settings `
            -Principal $principal `
            -Description "Web Terminal Hub - Cloudflare tunnel" | Out-Null

        Write-Host "[OK] Tunnel task created - starts 10s after logon" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor White
Write-Host "Tasks will auto-start at login. You can also run manually:" -ForegroundColor DarkGray
Write-Host "  Start:  schtasks /run /tn `"$taskNameServer`"" -ForegroundColor DarkGray
if ($WithTunnel) {
    Write-Host "  Start:  schtasks /run /tn `"$taskNameTunnel`"" -ForegroundColor DarkGray
}
Write-Host "  Stop:   powershell -File `"$hubDir\stop.ps1`"" -ForegroundColor DarkGray
Write-Host "  Remove: powershell -File `"$hubDir\install_service.ps1`" -Uninstall" -ForegroundColor DarkGray
