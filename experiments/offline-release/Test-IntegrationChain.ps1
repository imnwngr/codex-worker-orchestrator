param([ValidateSet('PatchReview','CommittedRelease')][string]$Mode='CommittedRelease',[string]$ExpectedSourceSha256,[string]$ExpectedRevision,[string]$IntegrationManifest,[string]$ExpectedIntegrationManifestSha256)
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$null=Assert-ReleaseSource $repo $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256
$approved=Read-IntegrationApproval $IntegrationManifest $ExpectedIntegrationManifestSha256
$root=Assert-StagingPath (Join-Path $env:LOCALAPPDATA ('Temp/phase912-chain-tests-'+[guid]::NewGuid().ToString('N'))) $repo
$null=New-Item -ItemType Directory -Path $root
$original=$approved|ConvertTo-Json -Depth 8
$count=1
function Reject-Chain([string]$Name,[scriptblock]$Mutate){
    $copy=$original|ConvertFrom-Json -AsHashtable
    & $Mutate $copy
    $file=Join-Path $root ($Name+'.json')
    [IO.File]::WriteAllText($file,($copy|ConvertTo-Json -Depth 8))
    $rejected=$false
    try {$null=Assert-ReleaseSource $repo $Mode $ExpectedSourceSha256 $ExpectedRevision $file ((Get-FileHash $file).Hash)}catch{$rejected=$true}
    if(-not $rejected){throw "INVALID_APPROVED_CHAIN_ACCEPTED: $Name"}
    $script:count++
    Write-Output "PASS integration chain rejects $Name even when modified manifest has a matching checksum"
}
Reject-Chain 'missing' {param($c) $c.commits=@($c.commits|Select-Object -Skip 1)}
if($approved.commits.Count -gt 1){Reject-Chain 'reordered' {param($c) [Array]::Reverse($c.commits)}}
Reject-Chain 'substituted' {param($c) $c.commits[0].sha='f'*40}
Reject-Chain 'inserted' {param($c) $c.commits=@($c.commits[0])+$c.commits}
Reject-Chain 'altered-parent' {param($c) $c.commits[0].parent='0'*40}
Reject-Chain 'altered-tree' {param($c) $c.commits[0].tree='e'*40}
Reject-Chain 'altered-tip' {param($c) $c.finalTip='d'*40}
Reject-Chain 'altered-final-tree' {param($c) $c.finalTree='b'*40}
Reject-Chain 'altered-source' {param($c) $c.sourceContentSha256='0'*64}
Reject-Chain 'unknown-field' {param($c) $c.unreviewed=$true}
$rejected=$false
try{$null=Assert-ReleaseSource $repo $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest ('0'*64)}catch{$rejected=$true}
if(-not $rejected){throw 'WRONG_EXTERNAL_APPROVAL_PIN_ACCEPTED'};$count++
$null=Assert-ReleaseSource $repo $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256
Write-Output "$count/$count integration chain checks passed; immutable original approval file retained."
