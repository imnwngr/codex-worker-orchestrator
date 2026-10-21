Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Baseline = '2f3c61fd283261a0d5f1dbdcaa30b39433c9d97b'
$script:PackageFiles = @('app/ApprovalAgent.Mock.exe','app/ApprovalAgent.Mock.dll','app/ApprovalAgent.Mock.deps.json','app/ApprovalAgent.Mock.runtimeconfig.json','browser/index.html','browser/preview.css','browser/preview.js','browser/ui.js','QUICKSTART.md','tools/Verify-Package.ps1','tools/Release.Common.ps1')
function Invoke-Native {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "NATIVE_COMMAND_FAILED: $Program exit $LASTEXITCODE" }
}
function Assert-DriveClassification {
    param([System.IO.DriveType]$Type)
    if ($Type -ne [IO.DriveType]::Fixed) { throw 'LOCAL_FIXED_VOLUME_REQUIRED' }
}
function Assert-LocalPath {
    param([string]$Path, [switch]$MustExist)
    if (-not $IsWindows -or -not [IO.Path]::IsPathFullyQualified($Path) -or $Path -notmatch '^[A-Za-z]:[\\/]' -or
        $Path.Substring(2).Contains(':') -or $Path -match '[\x00-\x1f\x7f]' -or
        @($Path -split '[\\/]' | Where-Object { $_ -in @('.','..') -or $_ -match '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)' -or $_ -match '[. ]$' }).Count) { throw 'LOCAL_PATH_INVALID' }
    $full = [IO.Path]::GetFullPath($Path)
    try { Assert-DriveClassification ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)).DriveType) } catch { throw 'LOCAL_FIXED_VOLUME_REQUIRED' }
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) { throw 'LOCAL_PATH_MISSING' }
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if (([IO.File]::GetAttributes($current) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_PATH_REJECTED' }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
    return $full
}
function Assert-StagingPath {
    param([string]$Path, [string]$Repository)
    $full = Assert-LocalPath $Path
    $temp = Assert-LocalPath ([IO.Path]::GetTempPath().TrimEnd('\','/')) -MustExist
    if (-not $full.StartsWith($temp + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'STAGING_OUTSIDE_TEMP' }
    if ($Repository -and ($full.Equals($Repository,[StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($Repository.TrimEnd('\','/')+'\',[StringComparison]::OrdinalIgnoreCase))) { throw 'STAGING_INSIDE_SOURCE' }
    if ($full -eq $temp) { throw 'STAGING_ROOT_REJECTED' }
    return $full
}
function Write-NewUtf8 {
    param([string]$Path, [string]$Text)
    $null = Assert-LocalPath $Path
    $bytes = [Text.UTF8Encoding]::new($false,$true).GetBytes($Text)
    $output = [IO.FileStream]::new($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $output.Write($bytes); $output.Flush($true) } finally { $output.Dispose() }
}
function Assert-JsonKeys {
    param([System.Text.Json.JsonElement]$Element, [string[]]$Names)
    if ($Element.ValueKind -ne [Text.Json.JsonValueKind]::Object) { throw 'MANIFEST_TYPE_INVALID' }
    $actual = @($Element.EnumerateObject() | ForEach-Object Name)
    if ($actual.Count -ne $Names.Count -or @($actual | Sort-Object -Unique).Count -ne $actual.Count -or
        @(Compare-Object ($Names | Sort-Object) ($actual | Sort-Object)).Count) { throw 'MANIFEST_FIELDS_INVALID' }
}
function Read-StrictManifest {
    param([byte[]]$Bytes)
    if ($Bytes.Length -gt 65536) { throw 'MANIFEST_OVERSIZED' }
    $text = [Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
    $doc = [Text.Json.JsonDocument]::Parse($text)
    try {
        $r = $doc.RootElement
        Assert-JsonKeys $r @('schemaVersion','version','designation','sourceMode','sourceBaseline','sourceRevision','sourceContentSha256','sourceTree','integrationManifestSha256','runtime','architecture','signed','authorized','productionAuthorization','files')
        if ($r.GetProperty('schemaVersion').GetRawText() -cne '3' -or $r.GetProperty('version').GetString() -cne '0.9.0-offline-rc.1' -or
            $r.GetProperty('designation').GetString() -cne 'OFFLINE_SYNTHETIC_RELEASE_CANDIDATE' -or
            $r.GetProperty('sourceBaseline').GetString() -cne $script:Baseline -or
            $r.GetProperty('sourceMode').GetString() -cnotin @('PatchReview','CommittedRelease') -or
            $r.GetProperty('sourceRevision').GetString() -cnotmatch '^[0-9a-f]{40}$' -or
            ($r.GetProperty('sourceMode').GetString() -ceq 'PatchReview' -and $r.GetProperty('sourceRevision').GetString() -cne $script:Baseline) -or
            ($r.GetProperty('sourceMode').GetString() -ceq 'CommittedRelease' -and $r.GetProperty('sourceRevision').GetString() -ceq $script:Baseline) -or
            $r.GetProperty('sourceContentSha256').GetString() -cnotmatch '^[0-9a-f]{64}$' -or
            $r.GetProperty('runtime').GetString() -cne 'Microsoft.WindowsDesktop.App 8.0.x' -or
            $r.GetProperty('architecture').GetString() -cne 'x64' -or
            $r.GetProperty('signed').GetRawText() -cne 'false' -or $r.GetProperty('authorized').GetRawText() -cne 'false' -or
            $r.GetProperty('productionAuthorization').GetString() -cne 'DEFAULT_DENY') { throw 'MANIFEST_CONTRACT_INVALID' }
        if($r.GetProperty('sourceMode').GetString() -ceq 'PatchReview') {
            if($r.GetProperty('sourceTree').ValueKind -ne [Text.Json.JsonValueKind]::Null -or $r.GetProperty('integrationManifestSha256').ValueKind -ne [Text.Json.JsonValueKind]::Null){throw 'MANIFEST_REVIEW_PROVENANCE_INVALID'}
        } else {
            if($r.GetProperty('sourceTree').GetString() -cnotmatch '^[0-9a-f]{40}$' -or $r.GetProperty('integrationManifestSha256').GetString() -cnotmatch '^[0-9a-f]{64}$'){throw 'MANIFEST_COMMITTED_PROVENANCE_INVALID'}
        }
        $members = $r.GetProperty('files')
        if ($members.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $members.GetArrayLength() -ne $script:PackageFiles.Count) { throw 'MANIFEST_INVENTORY_INVALID' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($member in $members.EnumerateArray()) {
            Assert-JsonKeys $member @('path','bytes','sha256')
            $name = $member.GetProperty('path').GetString()
            if ($name -cnotin $script:PackageFiles -or -not $seen.Add($name) -or
                $member.GetProperty('bytes').GetRawText() -cnotmatch '^(0|[1-9][0-9]*)$' -or
                $member.GetProperty('bytes').GetInt64() -gt 67108864 -or
                $member.GetProperty('sha256').GetString() -cnotmatch '^[0-9a-f]{64}$') { throw 'MANIFEST_MEMBER_INVALID' }
        }
        return $text | ConvertFrom-Json -AsHashtable
    } finally { $doc.Dispose() }
}
function Get-Sha256 {
    param([byte[]]$Bytes)
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Read-LocalOwnerJson {
    param([string]$Path, [int]$MaximumBytes, [string[]]$Names)
    $null = Assert-LocalPath $Path -MustExist
    $inputStream = [IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $bytes = [byte[]]::new($MaximumBytes+1); $count=0
        while ($count -lt $bytes.Length) {
            $n=$inputStream.Read($bytes,$count,$bytes.Length-$count)
            if ($n -eq 0) { break }; $count+=$n
        }
        if ($count -gt $MaximumBytes) { throw 'OWNERSHIP_JSON_OVERSIZED' }
        $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes,0,$count)
        $doc = [Text.Json.JsonDocument]::Parse($text)
        try { Assert-JsonKeys $doc.RootElement $Names } finally { $doc.Dispose() }
        return $text | ConvertFrom-Json
    } finally { $inputStream.Dispose() }
}
# Pins come from independent review, never automatic discovery during release.
$script:ReviewedChanges = @(
    'approval-agent/ApprovalAgent.Mock/ApprovalAgent.Mock.csproj',
    'approval-agent/ApprovalAgent.Mock/OfflineReviewWindow.xaml',
    'approval-agent/ApprovalAgent.Mock/OfflineReviewWindow.xaml.cs',
    'approval-agent/ApprovalAgent.Mock/Services/ApprovalMethodPreferences.cs',
    'approval-agent/ApprovalAgent.Mock/Services/OfflineDemoFiles.cs',
    'approval-agent/ApprovalAgent.Mock/ViewModels/ApprovalMethodSelection.cs',
    'approval-agent/ApprovalAgent.Mock/ViewModels/OfflineReviewViewModel.cs',
    'approval-agent/ApprovalAgent.MockTests/ApprovalAgent.MockTests.csproj',
    'approval-agent/ApprovalAgent.MockTests/Program.cs',
    'approval-agent/ApprovalAgent.MockTests/ReleaseReadinessTests.cs',
    'docs/PHASE_9_12_RELEASE_READINESS.md',
    'experiments/browser-preview/Verify-Workflow.ps1',
    'experiments/offline-release/Build-Release.ps1',
    'experiments/offline-release/demo-contract.js',
    'experiments/offline-release/Inspect-Source.ps1',
    'experiments/offline-release/Manage-Staging.ps1',
    'experiments/offline-release/Prepare-Demo.ps1',
    'experiments/offline-release/Release.Common.ps1',
    'experiments/offline-release/release.test.js',
    'experiments/offline-release/Test-ReleaseTools.ps1',
    'experiments/offline-release/Test-Security.ps1',
    'experiments/offline-release/Test-SourceLifecycle.ps1',
    'experiments/offline-release/Test-IntegrationChain.ps1',
    'experiments/offline-release/Verify-Package.ps1',
    'experiments/offline-release/Verify-Release.ps1'
)
function Get-SourceIdentity {
    param([string]$Repository)
    Push-Location $Repository
    try {
        $unknown = @(& git ls-files --others --exclude-standard)
        if ($LASTEXITCODE) { throw 'SOURCE_INVENTORY_FAILED' }
        if ($unknown.Count) { throw 'UNTRACKED_SOURCE_REJECTED: use a clean isolated release checkout; do not delete or stage unrelated original files.' }
        [string[]]$files = @(& git ls-files)
        if ($LASTEXITCODE -or -not $files.Count) { throw 'SOURCE_INVENTORY_FAILED' }
        [Array]::Sort($files,[StringComparer]::Ordinal)
        $modes = @{}
        foreach ($entry in @(& git ls-files --stage)) {
            if ($entry -cnotmatch '^([0-9]{6}) [0-9a-f]{40} 0\t(.+)$') { throw 'SOURCE_INDEX_INVALID' }
            $modes[$Matches[2]] = $Matches[1]
        }
        if ($LASTEXITCODE) { throw 'SOURCE_INDEX_INVALID' }
        $inventory = foreach ($file in $files) {
            $full = Assert-LocalPath (Join-Path $Repository $file) -MustExist
            if ($modes[$file] -ne '100644' -and $modes[$file] -ne '100755') { throw 'SOURCE_MODE_REJECTED' }
            $modes[$file] + ':' + $file + ':' + (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        $head = & git rev-parse HEAD
        if ($LASTEXITCODE -or $head -cnotmatch '^[0-9a-f]{40}$') { throw 'SOURCE_REVISION_INVALID' }
        return [pscustomobject]@{sourceRevision=$head;sourceContentSha256=(Get-Sha256 ([Text.Encoding]::UTF8.GetBytes(($inventory -join ([string][char]10)))));files=$files.Count}
    } finally { Pop-Location }
}
function Assert-ReleaseSource {
    param([string]$Repository, [ValidateSet('PatchReview','CommittedRelease')][string]$Mode='PatchReview',
        [string]$ExpectedSourceSha256, [string]$ExpectedRevision,[string]$IntegrationManifest,[string]$ExpectedIntegrationManifestSha256)
    Push-Location $Repository
    try {
        $identity = Get-SourceIdentity $Repository
        if ($ExpectedSourceSha256 -cnotmatch '^[0-9a-fA-F]{64}$') { throw 'REVIEWED_SOURCE_CHECKSUM_REQUIRED' }
        & git diff --cached --quiet
        if ($LASTEXITCODE) { throw 'STAGED_SOURCE_REJECTED' }
        $approval=$null
        if ($Mode -ceq 'PatchReview') {
            if($IntegrationManifest -or $ExpectedIntegrationManifestSha256){throw 'PATCH_REVIEW_INTEGRATION_ARGS_REJECTED'}
            if ($identity.sourceRevision -cne $script:Baseline) { throw 'EXACT_PATCH_REVIEW_BASELINE_REQUIRED' }
            if ($ExpectedRevision -and $ExpectedRevision -cne $script:Baseline) { throw 'EXPECTED_REVISION_MISMATCH' }
        } else {
            if ($ExpectedRevision -cnotmatch '^[0-9a-f]{40}$' -or $ExpectedRevision -ceq $script:Baseline) { throw 'VERIFIED_INTEGRATION_REVISION_REQUIRED' }
            if ($identity.sourceRevision -cne $ExpectedRevision) { throw 'EXPECTED_REVISION_MISMATCH' }
            $approval=Assert-IntegrationChain $Repository $IntegrationManifest $ExpectedIntegrationManifestSha256 $ExpectedRevision $ExpectedSourceSha256
            & git diff --quiet
            if ($LASTEXITCODE) { throw 'DIRTY_COMMITTED_SOURCE_REJECTED: use a clean isolated release checkout.' }
        }
        $actual = @(& git -c core.quotePath=false diff --name-only --no-renames $script:Baseline)
        if ($LASTEXITCODE -or @(Compare-Object ($script:ReviewedChanges | Sort-Object -CaseSensitive) ($actual | Sort-Object -CaseSensitive) -CaseSensitive).Count) { throw 'REVIEWED_CHANGE_INVENTORY_MISMATCH' }
        if ($identity.sourceContentSha256 -ine $ExpectedSourceSha256) { throw 'REVIEWED_SOURCE_CHECKSUM_MISMATCH' }
        return [pscustomobject]@{sourceMode=$Mode;sourceBaseline=$script:Baseline;sourceRevision=$identity.sourceRevision;sourceContentSha256=$identity.sourceContentSha256;sourceTree=$(if($approval){$approval.finalTree}else{$null});integrationManifestSha256=$(if($approval){$ExpectedIntegrationManifestSha256.ToLowerInvariant()}else{$null})}
    } finally { Pop-Location }
}
function Assert-PackagePins {
    param($Manifest, [string]$ExpectedSourceSha256, [string]$ExpectedRevision,[string]$ExpectedIntegrationManifestSha256)
    if ($ExpectedSourceSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or $Manifest.sourceContentSha256 -ine $ExpectedSourceSha256) { throw 'EXPECTED_SOURCE_CHECKSUM_MISMATCH' }
    if ($Manifest.sourceMode -ceq 'CommittedRelease') {
        if($ExpectedIntegrationManifestSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or $Manifest.integrationManifestSha256 -ine $ExpectedIntegrationManifestSha256){throw 'EXPECTED_INTEGRATION_MANIFEST_HASH_REQUIRED_OR_MISMATCH' }
        if ($ExpectedRevision -cnotmatch '^[0-9a-f]{40}$' -or $Manifest.sourceRevision -cne $ExpectedRevision) { throw 'EXPECTED_INTEGRATION_REVISION_REQUIRED_OR_MISMATCH' }
    } elseif ($ExpectedRevision -and $Manifest.sourceRevision -cne $ExpectedRevision) { throw 'EXPECTED_REVISION_MISMATCH' }
}
function Read-IntegrationApproval {
    param([string]$Path,[string]$ExpectedSha256)
    if ($ExpectedSha256 -cnotmatch '^[0-9a-fA-F]{64}$') { throw 'INTEGRATION_MANIFEST_PIN_REQUIRED' }
    $full=Assert-LocalPath $Path -MustExist
    $stream=[IO.FileStream]::new($full,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $buffer=[byte[]]::new(262145);$count=0
        while($count -lt $buffer.Length){$n=$stream.Read($buffer,$count,$buffer.Length-$count);if(-not $n){break};$count+=$n}
        if($count -gt 262144){throw 'INTEGRATION_MANIFEST_OVERSIZED'}
        $bytes=[byte[]]::new($count);[Array]::Copy($buffer,$bytes,$count)
        if((Get-Sha256 $bytes) -ine $ExpectedSha256){throw 'INTEGRATION_MANIFEST_HASH_MISMATCH'}
        $text=[Text.UTF8Encoding]::new($false,$true).GetString($buffer,0,$count)
        $doc=[Text.Json.JsonDocument]::Parse($text)
        try {
            $root=$doc.RootElement
            Assert-JsonKeys $root @('schemaVersion','designation','baseline','finalTip','finalTree','sourceContentSha256','commits')
            if($root.GetProperty('schemaVersion').GetRawText() -cne '1' -or $root.GetProperty('designation').GetString() -cne 'PHASE_9_12_APPROVED_LINEAR_INTEGRATION' -or
                $root.GetProperty('baseline').GetString() -cne $script:Baseline -or $root.GetProperty('finalTip').GetString() -cnotmatch '^[0-9a-f]{40}$' -or
                $root.GetProperty('finalTree').GetString() -cnotmatch '^[0-9a-f]{40}$' -or $root.GetProperty('sourceContentSha256').GetString() -cnotmatch '^[0-9a-f]{64}$') {throw 'INTEGRATION_MANIFEST_CONTRACT_INVALID'}
            $commits=$root.GetProperty('commits')
            if($commits.ValueKind -ne [Text.Json.JsonValueKind]::Array -or $commits.GetArrayLength() -lt 1 -or $commits.GetArrayLength() -gt 512){throw 'INTEGRATION_MANIFEST_COMMIT_COUNT_INVALID'}
            $previous=$script:Baseline;$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach($commit in $commits.EnumerateArray()){
                Assert-JsonKeys $commit @('sha','parent','tree','purpose','emptyJustification')
                $sha=$commit.GetProperty('sha').GetString();$tree=$commit.GetProperty('tree').GetString();$purpose=$commit.GetProperty('purpose').GetString()
                $reason=$commit.GetProperty('emptyJustification')
                if($sha -cnotmatch '^[0-9a-f]{40}$' -or -not $seen.Add($sha) -or $sha -ceq $script:Baseline -or
                    $commit.GetProperty('parent').GetString() -cne $previous -or $tree -cnotmatch '^[0-9a-f]{40}$' -or
                    [string]::IsNullOrWhiteSpace($purpose) -or $purpose.Length -gt 240 -or $purpose -match '[\x00-\x1f\x7f]'){throw 'INTEGRATION_MANIFEST_ORDER_OR_COMMIT_INVALID'}
                if($reason.ValueKind -ne [Text.Json.JsonValueKind]::Null -and
                    ($reason.ValueKind -ne [Text.Json.JsonValueKind]::String -or [string]::IsNullOrWhiteSpace($reason.GetString()) -or $reason.GetString().Length -gt 512 -or $reason.GetString() -match '[\x00-\x1f\x7f]')){throw 'INTEGRATION_EMPTY_JUSTIFICATION_INVALID'}
                $previous=$sha
            }
            if($previous -cne $root.GetProperty('finalTip').GetString() -or $commits[$commits.GetArrayLength()-1].GetProperty('tree').GetString() -cne $root.GetProperty('finalTree').GetString()){throw 'INTEGRATION_MANIFEST_TIP_INVALID'}
        } finally {$doc.Dispose()}
        return $text|ConvertFrom-Json -AsHashtable
    } finally {$stream.Dispose()}
}
function Assert-IntegrationChain {
    param([string]$Repository,[string]$ManifestPath,[string]$ExpectedManifestSha256,[string]$ExpectedRevision,[string]$ExpectedSourceSha256)
    if(-not $ManifestPath){throw 'EXTERNAL_INTEGRATION_MANIFEST_REQUIRED'}
    $full=Assert-LocalPath $ManifestPath -MustExist
    $repoFull=[IO.Path]::GetFullPath($Repository).TrimEnd('\','/')
    if($full.StartsWith($repoFull+'\',[StringComparison]::OrdinalIgnoreCase) -or $full.Equals($repoFull,[StringComparison]::OrdinalIgnoreCase)){throw 'INTEGRATION_MANIFEST_MUST_BE_EXTERNAL'}
    $approval=Read-IntegrationApproval $full $ExpectedManifestSha256
    if($approval.finalTip -cne $ExpectedRevision -or $approval.sourceContentSha256 -ine $ExpectedSourceSha256){throw 'INTEGRATION_APPROVAL_IDENTITY_MISMATCH'}
    Push-Location $Repository
    try {
        & git --no-pager --no-replace-objects merge-base --is-ancestor $script:Baseline HEAD
        if($LASTEXITCODE){throw 'INTEGRATION_ANCESTRY_REJECTED'}
        $actual=@(& git --no-pager --no-replace-objects rev-list --first-parent --reverse ($script:Baseline+'..HEAD'))
        if($LASTEXITCODE -or ($actual -join ',') -cne (@($approval.commits|ForEach-Object {$_.sha}) -join ',')){throw 'INTEGRATION_CHAIN_MISMATCH'}
        foreach($commit in $approval.commits){
            $raw=@(& git --no-pager --no-replace-objects cat-file -p $commit.sha)
            if($LASTEXITCODE){throw 'INTEGRATION_COMMIT_OBJECT_REJECTED'}
            $boundary=[Array]::IndexOf($raw,'')
            if($boundary -lt 1){throw 'INTEGRATION_COMMIT_OBJECT_REJECTED'}
            $headers=@($raw|Select-Object -First $boundary)
            $parents=@($headers|Where-Object {$_ -cmatch '^parent [0-9a-f]{40}$'})
            $objectTrees=@($headers|Where-Object {$_ -cmatch '^tree [0-9a-f]{40}$'})
            if($parents.Count -ne 1 -or $parents[0].Substring(7) -cne $commit.parent -or $objectTrees.Count -ne 1 -or $objectTrees[0].Substring(5) -cne $commit.tree){throw 'INTEGRATION_PARENT_OR_MERGE_REJECTED'}
            $tree=& git --no-pager --no-replace-objects rev-parse ($commit.sha+'^{tree}')
            if($LASTEXITCODE -or $tree -cne $commit.tree){throw 'INTEGRATION_TREE_MISMATCH'}
            $paths=@(& git --no-pager --no-replace-objects -c core.quotePath=false diff-tree --no-commit-id --name-only -r --no-renames $commit.parent $commit.sha)
            if($LASTEXITCODE -or @($paths|Where-Object {$_ -cnotin $script:ReviewedChanges}).Count){throw 'INTEGRATION_COMMIT_SCOPE_REJECTED'}
            if(-not $paths.Count -and [string]::IsNullOrWhiteSpace($commit.emptyJustification)){throw 'INTEGRATION_EMPTY_COMMIT_UNJUSTIFIED'}
            if($paths.Count -and $null -ne $commit.emptyJustification){throw 'INTEGRATION_NONEMPTY_EXCEPTION_REJECTED'}
        }
        $tipTree=& git --no-pager --no-replace-objects rev-parse 'HEAD^{tree}'
        if($LASTEXITCODE -or $tipTree -cne $approval.finalTree){throw 'INTEGRATION_FINAL_TREE_MISMATCH'}
        return $approval
    } finally {Pop-Location}
}