param([int]$Port = 8765, [switch]$Demo)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "Disk Atlas - http://127.0.0.1:$Port/?theme=dark"
Write-Host "Keep this window open. Press Ctrl+C to stop the server."
$serverArgs = @(".\server.py", "--port", $Port)
if ($Demo) { $serverArgs += "--demo" }
python @serverArgs
