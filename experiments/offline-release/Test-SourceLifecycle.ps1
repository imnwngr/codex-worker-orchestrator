param([ValidateSet('PatchReview','CommittedRelease')][string]$Mode='PatchReview',[string]$ExpectedSourceSha256,[string]$ExpectedRevision,[string]$IntegrationManifest,[string]$ExpectedIntegrationManifestSha256)
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$null=Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256
$passed=0
function Rejected([scriptblock]$Action,[string]$Category) {
    $rejected=$false
    try { $null=& $Action } catch { $rejected=$_.Exception.Message.StartsWith($Category,[StringComparison]::Ordinal) }
    if(-not $rejected){throw "SOURCE_NEGATIVE_CASE_FAILED: $Category"}
}
$null=Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256; ++$passed
Rejected {Assert-ReleaseSource $repository $Mode '' $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256} 'REVIEWED_SOURCE_CHECKSUM_REQUIRED';++$passed
Rejected {Assert-ReleaseSource $repository $Mode ('0'*64) $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256} $(if($Mode -eq 'CommittedRelease'){'INTEGRATION_APPROVAL_IDENTITY_MISMATCH'}else{'REVIEWED_SOURCE_CHECKSUM_MISMATCH'});++$passed
Rejected {Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 ('0'*40) $IntegrationManifest $ExpectedIntegrationManifestSha256} 'EXPECTED_REVISION_MISMATCH';++$passed
if($Mode -eq 'PatchReview') {
    Rejected {Assert-ReleaseSource $repository 'CommittedRelease' $ExpectedSourceSha256 ''} 'VERIFIED_INTEGRATION_REVISION_REQUIRED'
} else {
    Rejected {Assert-ReleaseSource $repository 'PatchReview' $ExpectedSourceSha256 ''} 'EXACT_PATCH_REVIEW_BASELINE_REQUIRED'
};++$passed
$probe=Join-Path $repository ('release-untracked-'+[guid]::NewGuid().ToString('N')+'.txt')
try {
    Write-NewUtf8 $probe 'synthetic-source-test'
    Rejected {Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256} 'UNTRACKED_SOURCE_REJECTED';++$passed
} finally {if(Test-Path -LiteralPath $probe){[IO.File]::Delete($probe)}}
$file=Join-Path $repository 'README.md';$original=[IO.File]::ReadAllBytes($file)
try {
    [IO.File]::WriteAllBytes($file,($original + [byte[]](10)))
    $category=if($Mode -eq 'CommittedRelease'){'DIRTY_COMMITTED_SOURCE_REJECTED'}else{'REVIEWED_CHANGE_INVENTORY_MISMATCH'}
    Rejected {Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256} $category;++$passed
    Invoke-Native git @('-C',$repository,'add','--','README.md')
    Rejected {Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256} 'STAGED_SOURCE_REJECTED';++$passed
} finally {
    Invoke-Native git @('-C',$repository,'reset','--','README.md')
    [IO.File]::WriteAllBytes($file,$original)
}
$changedFile=Join-Path $repository 'approval-agent/ApprovalAgent.Mock/ViewModels/ApprovalMethodSelection.cs'
$changedOriginal=[IO.File]::ReadAllBytes($changedFile)
try {
    [IO.File]::WriteAllBytes($changedFile,($changedOriginal + [byte[]](10)))
    $category=if($Mode -eq 'CommittedRelease'){'DIRTY_COMMITTED_SOURCE_REJECTED'}else{'REVIEWED_SOURCE_CHECKSUM_MISMATCH'}
    Rejected {Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256} $category;++$passed
} finally { [IO.File]::WriteAllBytes($changedFile,$changedOriginal) }
$null=Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256;++$passed
Write-Output "$passed/$passed source lifecycle checks passed ($Mode); original bytes/index restored."
