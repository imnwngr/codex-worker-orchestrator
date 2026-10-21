. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Push-Location $repo
try {
    $unchanged = @('broker','rules','approval-agent/ApprovalAgent.Mock/Services/OfflineTrustProtocol.cs','approval-agent/ApprovalAgent.Mock/Services/BrowserPreviewFiles.cs','approval-agent/ApprovalAgent.Mock/Services/ReviewJson.cs','approval-agent/ApprovalAgent.Mock/Services/OfflineReviewValidator.cs','approval-agent/ApprovalAgent.Mock/Services/WebAuthnCapabilityDiagnostics.cs','approval-agent/ApprovalAgent.Mock/Models/HybridMethods.cs','experiments/integration-contracts')
    foreach ($scope in $unchanged) {
        & git diff --exit-code $script:Baseline -- $scope | Out-Null
        if ($LASTEXITCODE) { throw 'PRODUCTION_OR_STRICT_BOUNDARY_CHANGED' }
    }
    $changed = @(& git diff --name-only $script:Baseline)
    if ($LASTEXITCODE) { throw 'SECURITY_DIFF_FAILED' }
    foreach ($name in $changed | Where-Object { $_ -match '^approval-agent/ApprovalAgent.Mock/.*\.cs$' }) {
        $text = [IO.File]::ReadAllText((Join-Path $repo $name))
        if ($text -match 'DllImport|LibraryImport|HttpClient|TcpClient|WebRequest|Process\.Start|MakeCredential|GetAssertion|EnumerateCredentials|DeleteCredential') { throw 'FORBIDDEN_ACTIVATION_API' }
    }
    foreach ($name in $changed) {
        if ($name -match '(?i)(^|/)(\.env|secrets?|credentials?)(\.|/|$)|\.(pfx|pem|key|p12)$') { throw 'SECRET_FILE_GATE_FAILED' }
        $text = [IO.File]::ReadAllText((Join-Path $repo $name))
        if ($text -match '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|ghp_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{40,}') { throw 'SECRET_PATTERN_GATE_FAILED' }
    }
    @{status='OFFLINE_SECURITY_GATES_PASS';productionStatus='PRODUCTION_AUTHORIZATION_NO_GO';scope='source-diff and conservative activation/secret patterns; not a security certification'} | ConvertTo-Json
} finally { Pop-Location }
