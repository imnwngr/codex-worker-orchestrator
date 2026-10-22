param([Parameter(Mandatory)][ValidateSet('Plan','Create','Rollback','CleanupRC')][string]$Mode,
    [Parameter(Mandatory)][string]$Destination, [string]$Package,[string]$ExpectedManifestSha256,[string]$ExpectedArchiveSha256,[string]$ExpectedSourceSha256,[string]$ExpectedRevision,[string]$ExpectedIntegrationManifestSha256)
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$root = Assert-StagingPath $Destination $repository
$verifyPins = @()
foreach ($name in @('ExpectedManifestSha256','ExpectedArchiveSha256','ExpectedSourceSha256','ExpectedRevision','ExpectedIntegrationManifestSha256')) {
    $value = Get-Variable -Name $name -ValueOnly
    if ($value) { $verifyPins += @(('-'+$name),$value) }
}
if ($Mode -in @('Plan','Create')) {
    if (-not $Package) { throw 'PACKAGE_REQUIRED' }
    if (Test-Path -LiteralPath $root) { throw 'DESTINATION_ALREADY_EXISTS' }
    Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Verify-Package.ps1'),'-Package',$Package,'-RequireRuntime','-Destination',$root) + $verifyPins)
    $plan = [ordered]@{schemaVersion=1;designation='OFFLINE_STAGING_PLAN_ONLY';productionAuthorization='DEFAULT_DENY';authorized=$false;
        archiveSha256=(Get-FileHash -LiteralPath $Package -Algorithm SHA256).Hash;installed=$false;extracted=$false;priorVersionModified=$false;rollback='Remove only this owned empty planning directory.'}
    if ($Mode -eq 'Create') {
        $null = New-Item -ItemType Directory -Path $root
        Write-NewUtf8 (Join-Path $root '.offline-stage-owned.json') '{"designation":"DISPOSABLE_OFFLINE_PLAN"}'
        Write-NewUtf8 (Join-Path $root 'deployment-plan.json') ($plan | ConvertTo-Json)
    }
    $plan | ConvertTo-Json
} elseif ($Mode -eq 'Rollback') {
    $null = Assert-LocalPath $root -MustExist
    $files = @(Get-ChildItem -LiteralPath $root -Force)
    if ($files.Count -ne 2 -or @($files | Where-Object { $_.PSIsContainer -or $_.Name -cnotin @('.offline-stage-owned.json','deployment-plan.json') }).Count) { throw 'ROLLBACK_UNKNOWN_CONTENT' }
    foreach ($item in $files) { $null = Assert-LocalPath $item.FullName -MustExist }
    if ((Read-LocalOwnerJson (Join-Path $root '.offline-stage-owned.json') 1024 @('designation')).designation -cne 'DISPOSABLE_OFFLINE_PLAN') { throw 'ROLLBACK_OWNERSHIP_INVALID' }
    $plan = Read-LocalOwnerJson (Join-Path $root 'deployment-plan.json') 16384 @('schemaVersion','designation','productionAuthorization','authorized','archiveSha256','installed','extracted','priorVersionModified','rollback')
    if ($plan.designation -cne 'OFFLINE_STAGING_PLAN_ONLY' -or $plan.installed -ne $false -or $plan.extracted -ne $false) { throw 'ROLLBACK_PLAN_INVALID' }
    foreach ($item in $files) { Remove-Item -LiteralPath $item.FullName }
    Remove-Item -LiteralPath $root
    if (Test-Path -LiteralPath $root) { throw 'ROLLBACK_INCOMPLETE' }
    'PASS OFFLINE_PLAN_ROLLBACK; no installation changed'
} else {
    if ([IO.Path]::GetFileName($root) -notmatch '^phase-9-12-release-candidate(?:-[A-Za-z0-9-]+)?$') { throw 'CLEANUP_NAME_REJECTED' }
    $null = Assert-LocalPath $root -MustExist
    $marker = Join-Path $root '.offline-rc-owned.json'
    $null = Assert-LocalPath $marker -MustExist
    $owner = Read-LocalOwnerJson $marker 1024 @('schemaVersion','designation','sourceRevision')
    if ($owner.designation -cne 'DISPOSABLE_OFFLINE_RC' -or $owner.sourceRevision -cnotmatch '^[0-9a-f]{40}$') { throw 'CLEANUP_OWNERSHIP_INVALID' }
    $archive = Join-Path $root 'OFFLINE-SYNTHETIC-RC-NOT-PRODUCTION-AUTHORIZED.zip'
    Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Verify-Package.ps1'),'-Package',$archive) + $verifyPins)
    $manifestPath = Join-Path $root 'package/manifest.json'
    $manifest = Read-StrictManifest ([IO.File]::ReadAllBytes($manifestPath))
    if ($owner.sourceRevision -cne $manifest.sourceRevision) { throw 'CLEANUP_PROVENANCE_MISMATCH' }
    $directoryPins = @('-ExpectedManifestSha256',(Get-FileHash -LiteralPath $manifestPath).Hash,'-ExpectedSourceSha256',$ExpectedSourceSha256)
    if ($ExpectedRevision) { $directoryPins += @('-ExpectedRevision',$ExpectedRevision) }
    if ($ExpectedIntegrationManifestSha256) { $directoryPins += @('-ExpectedIntegrationManifestSha256',$ExpectedIntegrationManifestSha256) }
    Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Verify-Package.ps1'),'-Package',(Join-Path $root 'package')) + $directoryPins)
    $allowedFiles = @('.offline-rc-owned.json','SHA256SUMS.txt','OFFLINE-SYNTHETIC-RC-NOT-PRODUCTION-AUTHORIZED.zip','package/manifest.json') + @($script:PackageFiles | ForEach-Object { 'package/'+$_ }) + @($script:PackageFiles | Where-Object { $_ -like 'app/*' } | ForEach-Object { 'publish/'+$_.Substring(4) })
    $allowedDirs = @('package','package/app','package/browser','package/tools','publish')
    $entries = @(Get-ChildItem -LiteralPath $root -Force -Recurse)
    foreach ($item in $entries) {
        $null = Assert-LocalPath $item.FullName -MustExist
        $relative = [IO.Path]::GetRelativePath($root,$item.FullName).Replace('\','/')
        if (($item.PSIsContainer -and $relative -cnotin $allowedDirs) -or (-not $item.PSIsContainer -and $relative -cnotin $allowedFiles)) { throw 'CLEANUP_UNKNOWN_CONTENT' }
    }
    foreach ($item in $entries | Where-Object { -not $_.PSIsContainer }) { Remove-Item -LiteralPath $item.FullName }
    foreach ($item in $entries | Where-Object PSIsContainer | Sort-Object { $_.FullName.Length } -Descending) { Remove-Item -LiteralPath $item.FullName }
    Remove-Item -LiteralPath $root
    if (Test-Path -LiteralPath $root) { throw 'CLEANUP_INCOMPLETE' }
    'PASS OWNED_RC_CLEANUP'
}
