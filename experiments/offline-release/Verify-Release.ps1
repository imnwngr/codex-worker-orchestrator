param([string]$OutputRoot = (Join-Path $env:LOCALAPPDATA 'Temp/phase-9-12-release-candidate'),
    [ValidateSet('PatchReview','CommittedRelease')][string]$Mode='PatchReview', [string]$ExpectedSourceSha256, [string]$ExpectedRevision,[string]$IntegrationManifest,[string]$ExpectedIntegrationManifestSha256)
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$null = Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256
$pins = @('-Mode',$Mode,'-ExpectedSourceSha256',$ExpectedSourceSha256)
if ($ExpectedRevision) { $pins += @('-ExpectedRevision',$ExpectedRevision) }
if ($IntegrationManifest) { $pins += @('-IntegrationManifest',$IntegrationManifest) }
if ($ExpectedIntegrationManifestSha256) { $pins += @('-ExpectedIntegrationManifestSha256',$ExpectedIntegrationManifestSha256) }
Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot '../browser-preview/Verify-Workflow.ps1')) + $pins)
Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Test-Security.ps1'))
Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Test-ReleaseTools.ps1'))
Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Test-SourceLifecycle.ps1')) + $pins)
if($Mode -ceq 'CommittedRelease'){Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Test-IntegrationChain.ps1'))+$pins)}
Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Prepare-Demo.ps1'))
Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Build-Release.ps1'),'-OutputRoot',$OutputRoot) + $pins)
'PASS OFFLINE_RC_READY; INTEGRATED_OFFLINE_RC_VERIFICATION; PRODUCTION_AUTHORIZATION_NO_GO'
