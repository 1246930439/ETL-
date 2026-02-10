# PowerShell script to start server with auto-restart
Write-Host "Starting server with auto-restart..."

while ($true) {
    Write-Host "Starting web_scheduler.py..."
    $process = Start-Process -FilePath "python" -ArgumentList "web_scheduler.py" -PassThru -Wait
    
    Write-Host "Server stopped at $(Get-Date) with exit code $($process.ExitCode)"
    Write-Host "Restarting in 5 seconds..."
    Start-Sleep -Seconds 5
}