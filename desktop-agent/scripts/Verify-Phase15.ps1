param([Parameter(Mandatory)][string]$OutputRoot)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$root = [IO.Path]::GetFullPath($OutputRoot)
if (-not [IO.Path]::IsPathFullyQualified($OutputRoot) -or $root.StartsWith('\\') -or
    $root.StartsWith($repo + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    $root.Equals($repo, [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $root)) { throw 'NEW_EXTERNAL_OUTPUT_REQUIRED' }
for ($dir = [IO.DirectoryInfo]::new($root); $null -ne $dir; $dir = $dir.Parent) {
    if ($dir.Exists -and ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'REPARSE_DENIED' }
}
$null = New-Item -ItemType Directory -Path $root
$results = [Collections.Generic.List[object]]::new()
function Check([string]$Name, [string]$Program, [string[]]$Arguments) {
    $start = [DateTimeOffset]::UtcNow
    $log = Join-Path $root ($Name + '.log')
    & $Program @Arguments 2>&1 | Out-File -LiteralPath $log -Encoding utf8
    $exit = $LASTEXITCODE
    $results.Add([ordered]@{name=$Name;exitCode=$exit;status=$(if($exit -eq 0){'VERIFIED'}else{'FAILED'});
        durationMs=([DateTimeOffset]::UtcNow-$start).TotalMilliseconds;log=[IO.Path]::GetFileName($log);
        sha256=(Get-FileHash -LiteralPath $log).Hash.ToLowerInvariant()})
    Write-Output "$Name : exit $exit"
}
Push-Location $repo
try {
    Check 'node-regression' 'node' @('--test')
    Check 'agent-build' 'dotnet' @('build','desktop-agent/DesktopAgent.Windows','-c','Release')
    Check 'fixture-build' 'dotnet' @('build','desktop-agent/DesktopAgent.Fixture','-c','Release')
    Check 'wpf-build' 'dotnet' @('build','approval-agent/ApprovalAgent.Mock','-c','Release')
    Check 'desktop-core-tests' 'dotnet' @('run','--project','desktop-agent/DesktopAgent.Tests','-c','Release')
    Check 'approval-regression' 'dotnet' @('run','--project','approval-agent/ApprovalAgent.MockTests','-c','Release')
    Check 'webauthn-fake-lab' 'dotnet' @('run','--project','experiments/webauthn-windows-lab','-c','Release')
    Check 'offline-assurance' 'dotnet' @('run','--project','experiments/webauthn-offline-assurance','-c','Release','--','--self-test',
        'experiments/webauthn-windows-lab/experimental-readiness.json','experiments/webauthn-offline-assurance/invariant-registry.json',
        'experiments/webauthn-offline-assurance/fixtures','.')
    Check 'release-tool-regression' 'pwsh' @('-NoProfile','-File','experiments/offline-release/Test-ReleaseTools.ps1')
    Check 'fresh-demo-headless' 'pwsh' @('-NoProfile','-File','experiments/offline-release/Prepare-Demo.ps1')
    Check 'real-agent-ipc-denial-only' 'node' @('desktop-agent/scripts/probe-and-deny.js')
    Check 'diff-check' 'git' @('diff','--check')
    $summary = [ordered]@{schemaVersion=1;sourceRevision=(& git rev-parse HEAD);observedAt=[DateTimeOffset]::UtcNow;
        scope='SYNTHETIC_AND_IPC_ONLY';realGui='NOT_RUN';production='DEFAULT_DENY';checks=$results.ToArray()}
    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root 'summary.json') -Encoding utf8
    if (@($results | Where-Object exitCode -ne 0).Count) { exit 1 }
} finally { Pop-Location }
