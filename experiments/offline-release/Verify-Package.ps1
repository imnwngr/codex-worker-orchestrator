param([Parameter(Mandatory)][string]$Package, [string]$Destination, [switch]$RequireRuntime, [string]$ExpectedArchiveSha256, [string]$ExpectedManifestSha256, [string]$ExpectedSourceSha256, [string]$ExpectedRevision,[string]$ExpectedIntegrationManifestSha256)
. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$selected = Assert-LocalPath $Package -MustExist
if (-not $ExpectedArchiveSha256 -and -not $ExpectedManifestSha256) { throw 'EXTERNAL_PACKAGE_CHECKSUM_REQUIRED' }
if ($ExpectedManifestSha256 -and $ExpectedManifestSha256 -cnotmatch '^[A-Fa-f0-9]{64}$') { throw 'EXPECTED_MANIFEST_HASH_MISMATCH' }
if ($ExpectedArchiveSha256) {
    if ($ExpectedArchiveSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or -not (Test-Path -LiteralPath $selected -PathType Leaf) -or
        (Get-FileHash -LiteralPath $selected -Algorithm SHA256).Hash -ine $ExpectedArchiveSha256) { throw 'EXPECTED_ARCHIVE_HASH_MISMATCH' }
}
$items = @{}
$zip = $null
try {
    if (Test-Path -LiteralPath $selected -PathType Container) {
        $all = @(Get-ChildItem -LiteralPath $selected -Recurse -Force)
        foreach ($entry in $all) {
            $null = Assert-LocalPath $entry.FullName -MustExist
            if ($entry.PSIsContainer) {
                $directoryName = [IO.Path]::GetRelativePath($selected,$entry.FullName).Replace('\','/')
                if ($directoryName -cnotin @('app','browser','tools')) { throw 'UNEXPECTED_PACKAGE_DIRECTORY' }
                continue
            }
            $name = [IO.Path]::GetRelativePath($selected,$entry.FullName).Replace('\','/')
            if ($name -cnotin ($script:PackageFiles + @('manifest.json')) -or $items.ContainsKey($name) -or $entry.Length -gt 67108864) { throw 'UNEXPECTED_PACKAGE_MEMBER' }
            $items[$name] = $entry.FullName
        }
    } else {
        if ([IO.Path]::GetExtension($selected) -cne '.zip' -or (Get-Item -LiteralPath $selected).Length -gt 134217728) { throw 'ARCHIVE_INVALID' }
        $zip = [IO.Compression.ZipFile]::OpenRead($selected)
        if ($zip.Entries.Count -ne $script:PackageFiles.Count + 1) { throw 'ARCHIVE_INVENTORY_INVALID' }
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ($name -cnotin ($script:PackageFiles + @('manifest.json')) -or $items.ContainsKey($name) -or $entry.Length -gt 67108864 -or
                (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) { throw 'UNEXPECTED_ARCHIVE_MEMBER' }
            $items[$name] = $entry
        }
    }
    if ($items.Count -ne $script:PackageFiles.Count + 1 -or -not $items.ContainsKey('manifest.json')) { throw 'PACKAGE_INVENTORY_INVALID' }
    function Read-Member([string]$Name, [long]$Limit) {
        if (-not $items.ContainsKey($Name)) { throw 'PACKAGE_MEMBER_MISSING' }
        $inputStream = if ($zip) { $items[$Name].Open() } else { [IO.File]::OpenRead($items[$Name]) }
        $output = [IO.MemoryStream]::new()
        try {
            $buffer = [byte[]]::new(8192)
            while (($count = $inputStream.Read($buffer,0,$buffer.Length)) -ne 0) {
                if ($output.Length + $count -gt $Limit) { throw 'PACKAGE_MEMBER_OVERSIZED' }
                $output.Write($buffer,0,$count)
            }
            return ,$output.ToArray()
        } finally { $inputStream.Dispose(); $output.Dispose() }
    }
    $manifestBytes = Read-Member 'manifest.json' 65536
    if ($ExpectedManifestSha256 -and ($ExpectedManifestSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or (Get-Sha256 $manifestBytes) -ine $ExpectedManifestSha256)) { throw 'EXPECTED_MANIFEST_HASH_MISMATCH' }
    $manifest = Read-StrictManifest $manifestBytes
    Assert-PackagePins $manifest $ExpectedSourceSha256 $ExpectedRevision $ExpectedIntegrationManifestSha256
    $total = 0L
    foreach ($member in $manifest.files) {
        $bytes = Read-Member $member.path $member.bytes
        $total += $bytes.Length
        if ($total -gt 134217728 -or $bytes.Length -ne $member.bytes -or (Get-Sha256 $bytes) -cne $member.sha256) { throw 'PACKAGE_HASH_MISMATCH' }
        if ($member.path -in @('app/ApprovalAgent.Mock.exe','app/ApprovalAgent.Mock.dll') -and
            ($bytes.Length -lt 2 -or $bytes[0] -ne 77 -or $bytes[1] -ne 90)) { throw 'PACKAGE_PE_INVALID' }
    }
    $runtimeReady = $false
    if (Get-Command dotnet -ErrorAction SilentlyContinue) {
        $runtimes = & dotnet --list-runtimes
        if ($LASTEXITCODE -eq 0) { $runtimeReady = @($runtimes | Where-Object { $_ -match '^Microsoft.WindowsDesktop.App 8\.0\.' }).Count -gt 0 }
    }
    if ($RequireRuntime -and (-not $runtimeReady -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64')) { throw 'WINDOWS_X64_DESKTOP_RUNTIME_REQUIRED' }
    $plan = $null
    if ($Destination) {
        $destinationPath = Assert-StagingPath $Destination ''
        if (Test-Path -LiteralPath $destinationPath) { throw 'DESTINATION_ALREADY_EXISTS' }
        $plan = @{ mode='READ_ONLY_DRY_RUN'; destination=$destinationPath; createDirectory=$false; extractArchive=$false;
            rollback='Discard only the separately created owned disposable staging directory; retain the previous package unchanged.';
            priorInstallationModified=$false }
    }
    @{ status='OFFLINE_PACKAGE_INTEGRITY_PASS'; productionStatus='PRODUCTION_AUTHORIZATION_NO_GO'; authorized=$false;
        sourceMode=$manifest.sourceMode;sourceRevision=$manifest.sourceRevision;sourceContentSha256=$manifest.sourceContentSha256; signed=$false; runtimeReady=$runtimeReady; manifestSha256=(Get-Sha256 $manifestBytes); files=$manifest.files.Count; plan=$plan } | ConvertTo-Json -Depth 5
} finally { if ($zip) { $zip.Dispose() } }