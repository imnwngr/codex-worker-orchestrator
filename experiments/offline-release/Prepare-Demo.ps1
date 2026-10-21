param([string]$OutputRoot = (Join-Path $env:LOCALAPPDATA ('Temp/offline-demo-'+[guid]::NewGuid().ToString('N'))))
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$root = Assert-StagingPath $OutputRoot $repo
if (Test-Path -LiteralPath $root) { throw 'DEMO_DESTINATION_EXISTS' }
$null = New-Item -ItemType Directory -Path $root
Invoke-Native dotnet @('run','--no-build','--no-restore','-c','Release','--project',(Join-Path $repo 'approval-agent/ApprovalAgent.MockTests'),'--','--demo',$root)
@{status='OFFLINE_DEMO_ACCEPTANCE_PASS';authorized=$false;productionAuthorization='DEFAULT_DENY';directory=$root;
    note='Automated fixtures consumed. In WPF create another fresh demo for hands-on use; saved responses are instance-bound and intentionally stale.'} | ConvertTo-Json
