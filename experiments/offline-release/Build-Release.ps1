param([string]$OutputRoot = (Join-Path $env:LOCALAPPDATA 'Temp/phase-9-12-release-candidate'), [ValidateSet('PatchReview','CommittedRelease')][string]$Mode='PatchReview', [string]$ExpectedSourceSha256, [string]$ExpectedRevision,[string]$IntegrationManifest,[string]$ExpectedIntegrationManifestSha256)
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$root = Assert-StagingPath $OutputRoot $repository
if (Test-Path -LiteralPath $root) { $root = Assert-StagingPath ($root + '-' + [guid]::NewGuid().ToString('N')) $repository }
Push-Location $repository
try {
    $sourceIdentity = Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256
    $architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    if ($architecture -ne 'X64') { throw 'WINDOWS_X64_BUILD_REQUIRED' }
    $sdk = & dotnet --version
    if ($LASTEXITCODE -or $sdk -notmatch '^8\.') { throw 'DOTNET8_SDK_REQUIRED' }
    Invoke-Native git @('diff','--check')
    $changed = @(& git diff --name-only $script:Baseline)
    if ($LASTEXITCODE) { throw 'SOURCE_DIFF_FAILED' }
    if (@($changed | Where-Object { $_ -notmatch '^(approval-agent/ApprovalAgent\.Mock(?:Tests)?/|experiments/(offline-release|browser-preview)/|docs/PHASE_9_12_RELEASE_READINESS\.md$)' }).Count) { throw 'RELEASE_SCOPE_GATE_FAILED' }
    Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Test-Security.ps1'))
    $null = New-Item -ItemType Directory -Path $root
    Write-NewUtf8 (Join-Path $root '.offline-rc-owned.json') ('{"schemaVersion":1,"designation":"DISPOSABLE_OFFLINE_RC","sourceRevision":"'+$sourceIdentity.sourceRevision+'"}')
    $publish = Join-Path $root 'publish'
    Invoke-Native dotnet @('publish','approval-agent/ApprovalAgent.Mock','-c','Release','--no-self-contained','-p:NuGetAudit=false','-p:ContinuousIntegrationBuild=true',"-p:PathMap=$repository=/_/orchestrator",'-p:DebugType=None','-p:DebugSymbols=false','-o',$publish)
    $package = Join-Path $root 'package'
    $null = New-Item -ItemType Directory -Path $package
    foreach ($relative in $script:PackageFiles) {
        $target = Join-Path $package $relative
        $null = New-Item -ItemType Directory -Path (Split-Path $target) -Force
        $source = switch -Regex ($relative) {
            '^app/' { Join-Path $publish ($relative.Substring(4)); break }
            '^browser/' { Join-Path $repository ('experiments/browser-preview/' + $relative.Substring(8)); break }
            '^tools/' { Join-Path $PSScriptRoot ($relative.Substring(6)); break }
            '^QUICKSTART.md$' { Join-Path $repository 'docs/PHASE_9_12_RELEASE_READINESS.md'; break }
            default { throw 'PACKAGE_SOURCE_INVALID' }
        }
        $null = Assert-LocalPath $source -MustExist
        Copy-Item -LiteralPath $source -Destination $target
    }
    $published = @(Get-ChildItem -LiteralPath $publish -Recurse -File | ForEach-Object { 'app/' + [IO.Path]::GetRelativePath($publish,$_.FullName).Replace('\','/') })
    if (@(Compare-Object ($published | Sort-Object) (@($script:PackageFiles | Where-Object { $_ -like 'app/*' }) | Sort-Object)).Count) { throw 'UNEXPECTED_PUBLISH_PAYLOAD' }
    $inventory = @($script:PackageFiles | Sort-Object -CaseSensitive | ForEach-Object {
        $item = Get-Item -LiteralPath (Join-Path $package $_)
        [ordered]@{path=$_; bytes=$item.Length; sha256=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    $manifest = [ordered]@{schemaVersion=3;version='0.9.0-offline-rc.1';designation='OFFLINE_SYNTHETIC_RELEASE_CANDIDATE';sourceMode=$Mode;sourceBaseline=$script:Baseline;sourceRevision=$sourceIdentity.sourceRevision;
        sourceContentSha256=$sourceIdentity.sourceContentSha256;sourceTree=$sourceIdentity.sourceTree;integrationManifestSha256=$sourceIdentity.integrationManifestSha256;runtime='Microsoft.WindowsDesktop.App 8.0.x';architecture='x64';signed=$false;authorized=$false;productionAuthorization='DEFAULT_DENY';files=$inventory}
    Write-NewUtf8 (Join-Path $package 'manifest.json') ($manifest | ConvertTo-Json -Depth 6)
    $manifestHash = (Get-FileHash -LiteralPath (Join-Path $package 'manifest.json')).Hash
    $verifyPins = @('-ExpectedManifestSha256',$manifestHash,'-ExpectedSourceSha256',$ExpectedSourceSha256)
    if ($ExpectedRevision) { $verifyPins += @('-ExpectedRevision',$ExpectedRevision) }
    if ($ExpectedIntegrationManifestSha256) { $verifyPins += @('-ExpectedIntegrationManifestSha256',$ExpectedIntegrationManifestSha256) }
    Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Verify-Package.ps1'),'-Package',$package,'-RequireRuntime') + $verifyPins)
    $archive = Join-Path $root 'OFFLINE-SYNTHETIC-RC-NOT-PRODUCTION-AUTHORIZED.zip'
    $stream = [IO.FileStream]::new($archive,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create,$false)
    try {
        foreach ($name in (@($script:PackageFiles)+@('manifest.json') | Sort-Object -CaseSensitive)) {
            $entry = $zip.CreateEntry($name,[IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = [DateTimeOffset]::new(2020,1,1,0,0,0,[TimeSpan]::Zero)
            $inputStream = [IO.File]::OpenRead((Join-Path $package $name)); $outputStream=$entry.Open()
            try { $inputStream.CopyTo($outputStream) } finally { $inputStream.Dispose(); $outputStream.Dispose() }
        }
    } finally { $zip.Dispose(); $stream.Dispose() }
    $null = Assert-ReleaseSource $repository $Mode $ExpectedSourceSha256 $ExpectedRevision $IntegrationManifest $ExpectedIntegrationManifestSha256
    Invoke-Native pwsh (@('-NoProfile','-File',(Join-Path $PSScriptRoot 'Verify-Package.ps1'),'-Package',$archive,'-RequireRuntime','-Destination',(Join-Path $root 'planned-local-stage')) + $verifyPins)
    $checksums = foreach ($file in @($archive,(Join-Path $package 'manifest.json'))) { (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + [IO.Path]::GetRelativePath($root,$file) }
    Write-NewUtf8 (Join-Path $root 'SHA256SUMS.txt') ($checksums -join "`n")
    @{status='OFFLINE_RC_PACKAGED';productionStatus='PRODUCTION_AUTHORIZATION_NO_GO';root=$root;archive=$archive;archiveSha256=(Get-FileHash $archive -Algorithm SHA256).Hash;manifestSha256=(Get-FileHash (Join-Path $package 'manifest.json') -Algorithm SHA256).Hash} | ConvertTo-Json
} finally { Pop-Location }
