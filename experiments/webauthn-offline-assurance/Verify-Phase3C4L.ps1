param(
    [Parameter(Mandatory=$true)][string]$Repository,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Baseline,
    [Parameter(Mandatory=$true)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $Repository).Path
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Output directory must be new' }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
Push-Location -LiteralPath $repo
try {
    function Invoke-Logged([string]$Name, [string]$Executable, [string[]]$Arguments) {
        $lines = & $Executable @Arguments 2>&1
        $code = $LASTEXITCODE
        $lines | Set-Content -LiteralPath (Join-Path $output "$Name.log") -Encoding utf8
        if ($code -ne 0) { throw "$Name failed with exit $code; inspect its log" }
        return $lines
    }
    $projects = @(
        'approval-agent/ApprovalAgent.Mock/ApprovalAgent.Mock.csproj',
        'approval-agent/ApprovalAgent.MockTests/ApprovalAgent.MockTests.csproj',
        'experiments/webauthn-windows-lab/WebAuthn.WindowsLab.csproj',
        'experiments/webauthn-offline-assurance/WebAuthn.OfflineAssurance.csproj'
    )
    for ($i=0; $i -lt $projects.Count; $i++) {
        $null = Invoke-Logged "build-$i" dotnet @('build',$projects[$i],'-c','Release','--source',(Join-Path $env:ProgramFiles 'dotnet/packs'))
    }
    $common = @('run','--no-build','--no-restore','-c','Release','--project')
    $mock = Invoke-Logged 'mock' dotnet ($common + @($projects[1]))
    $lab = Invoke-Logged 'lab' dotnet ($common + @($projects[2]))
    $assurance = $common + @($projects[3],'--')
    $manifest = 'experiments/webauthn-windows-lab/experimental-readiness.json'
    $registry = 'experiments/webauthn-offline-assurance/invariant-registry.json'
    $self = Invoke-Logged 'assurance' dotnet ($assurance + @('--self-test',$manifest,$registry,'experiments/webauthn-offline-assurance/fixtures','.'))
    $null = Invoke-Logged 'policy' dotnet ($assurance + @('--policy-check',$manifest,$registry))
    $node = Invoke-Logged 'node' node @('--test','--test-reporter=tap')
    foreach ($name in @('candidate-a','candidate-b')) {
        $path = Join-Path $output $name
        $null = Invoke-Logged "$name-create" dotnet ($assurance + @('--candidate-create',$repo,$Baseline,$path))
        $null = Invoke-Logged "$name-audit" dotnet ($assurance + @('--candidate-audit',$repo,$Baseline,$path))
    }
    $first = Join-Path $output 'candidate-a'
    $second = Join-Path $output 'candidate-b'
    foreach ($file in Get-ChildItem -LiteralPath $first -File) {
        if ((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath (Join-Path $second $file.Name) -Algorithm SHA256).Hash) { throw 'Candidate bytes differ' }
    }
    $selfSummary = ($self -join "`n") | ConvertFrom-Json
    $nodeCount = [regex]::Match(($node -join "`n"), '(?m)^# tests (\d+)').Groups[1].Value
    $summary = [ordered]@{
        baseline = $Baseline; observation = 'LOCAL_EXECUTION_REPORTED_UNVERIFIED'
        mockPassed = @($mock | Where-Object { "$_" -like 'PASS *' }).Count
        labPassed = @($lab | Where-Object { "$_" -like 'PASS *' }).Count
        assurancePassed = $selfSummary.passed; assuranceFailures = $selfSummary.failures
        nodeTests = $nodeCount; builds = '4 succeeded'; candidateBytes = 'identical; both audited'
        productionAuthorization = 'DEFAULT_DENY'; realCredentialOperations = 'NO_GO'
    }
    $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'summary.json') -Encoding utf8
    $summary | ConvertTo-Json
} finally { Pop-Location }
