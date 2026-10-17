param([switch]$SupplementalNode)
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Push-Location $repository
try {
    function Invoke-Checked {
        param([Parameter(Position=0)][string]$program, [Parameter(Position=1,ValueFromRemainingArguments=$true)][string[]]$arguments)
        & $program @arguments
        if ($LASTEXITCODE -ne 0) { throw "$program failed with exit code $LASTEXITCODE" }
    }
    $baseline = 'c3f5a9c32563f1f218d592dc2e74e961ecd373ad'
    if ((git rev-parse HEAD) -ne $baseline) { throw 'Exact disposable baseline required' }
    Invoke-Checked git @('diff', '--check')
    foreach ($project in @('approval-agent/ApprovalAgent.Mock', 'approval-agent/ApprovalAgent.MockTests', 'experiments/webauthn-windows-lab', 'experiments/webauthn-offline-assurance')) {
        Invoke-Checked dotnet @('build', $project, '-c', 'Release', '-p:NuGetAudit=false')
    }
    Invoke-Checked dotnet @('run', '--no-build', '--no-restore', '-c', 'Release', '--project', 'approval-agent/ApprovalAgent.MockTests')
    Invoke-Checked dotnet @('run', '--no-build', '--no-restore', '-c', 'Release', '--project', 'experiments/webauthn-windows-lab')
    $assurance = @('run', '--no-build', '--no-restore', '-c', 'Release', '--project', 'experiments/webauthn-offline-assurance', '--')
    Invoke-Checked dotnet ($assurance + @('--self-test', 'experiments/webauthn-windows-lab/experimental-readiness.json', 'experiments/webauthn-offline-assurance/invariant-registry.json', 'experiments/webauthn-offline-assurance/fixtures', '.'))
    Invoke-Checked dotnet ($assurance + @('--policy-check', 'experiments/webauthn-windows-lab/experimental-readiness.json', 'experiments/webauthn-offline-assurance/invariant-registry.json'))
    if ($SupplementalNode) {
        Write-Output 'SUPPLEMENTAL PER-FILE NODE EXECUTION; NOT STANDARD NODE CI EQUIVALENCE'
        foreach ($file in Get-ChildItem broker, experiments -Recurse -Filter '*.test.js' -File | Sort-Object FullName) {
            Invoke-Checked node @('--test-reporter=tap', $file.FullName)
        }
    } else { Invoke-Checked node @('--test', '--test-reporter=tap') }
    $candidateRoot = Join-Path ([IO.Path]::GetTempPath()) ('phase78-candidates-' + [guid]::NewGuid().ToString('N'))
    foreach ($name in @('first', 'second')) {
        $destination = Join-Path $candidateRoot $name
        Invoke-Checked dotnet ($assurance + @('--candidate-create', '.', $baseline, $destination))
        Invoke-Checked dotnet ($assurance + @('--candidate-audit', '.', $baseline, $destination))
    }
    foreach ($file in Get-ChildItem (Join-Path $candidateRoot 'first') -File) {
        $other = Join-Path (Join-Path $candidateRoot 'second') $file.Name
        if ((Get-FileHash -Algorithm SHA256 $file.FullName).Hash -ne (Get-FileHash -Algorithm SHA256 $other).Hash) { throw 'Candidate reproducibility mismatch' }
    }
    Write-Output "PASS candidate member/inventory byte reproducibility: $candidateRoot"
} finally { Pop-Location }
