$ErrorActionPreference = "Stop"

Set-Location "C:\dev\orchestrator\broker"

Write-Host "Starting Codex Worker Broker..."
Write-Host "Listening only on 127.0.0.1"
Write-Host ""

node ".\broker.js"
