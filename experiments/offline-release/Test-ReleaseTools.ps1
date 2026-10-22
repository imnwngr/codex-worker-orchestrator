. (Join-Path $PSScriptRoot 'Release.Common.ps1')
$root = Assert-StagingPath (Join-Path $env:LOCALAPPDATA ('Temp/release-tools-test-'+[guid]::NewGuid().ToString('N'))) ''
$null = New-Item -ItemType Directory -Path $root
$package = Join-Path $root 'package'
$null = New-Item -ItemType Directory -Path $package
$script:Passed = 0
function Check([string]$Name, [scriptblock]$Action) { & $Action; ++$script:Passed; Write-Output "PASS $Name" }
function Reject([scriptblock]$Action) { $rejected=$false;try { & $Action } catch { $rejected=$true };if(-not $rejected){throw 'NEGATIVE_TEST_ACCEPTED'} }
function Verify([string]$Target,[bool]$Expected) {
    $output = & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $Target -ExpectedManifestSha256 ((Get-FileHash -LiteralPath $manifestPath).Hash) -ExpectedSourceSha256 ('a'*64) 2>&1
    $exit = $LASTEXITCODE
    if (($exit -eq 0) -ne $Expected) { $output | Write-Output; throw 'PACKAGE_EXPECTATION_FAILED' }
}
foreach ($name in $script:PackageFiles) {
    $target = Join-Path $package $name
    $null = New-Item -ItemType Directory -Path (Split-Path $target) -Force
    $bytes = if ($name -in @('app/ApprovalAgent.Mock.exe','app/ApprovalAgent.Mock.dll')) { [byte[]](77,90,1) } else { [Text.Encoding]::UTF8.GetBytes('synthetic-test-only') }
    [IO.File]::WriteAllBytes($target,$bytes)
}
$inventory = @($script:PackageFiles | ForEach-Object { $p=Join-Path $package $_; @{path=$_;bytes=(Get-Item $p).Length;sha256=(Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant()} })
$manifest = @{schemaVersion=3;sourceTree=$null;integrationManifestSha256=$null;sourceMode='PatchReview';sourceBaseline=$script:Baseline;version='0.9.0-offline-rc.1';designation='OFFLINE_SYNTHETIC_RELEASE_CANDIDATE';sourceRevision=$script:Baseline;sourceContentSha256=('a'*64);runtime='Microsoft.WindowsDesktop.App 8.0.x';architecture='x64';signed=$false;authorized=$false;productionAuthorization='DEFAULT_DENY';files=$inventory}
$manifestPath = Join-Path $package 'manifest.json'
$valid = $manifest | ConvertTo-Json -Depth 6
[IO.File]::WriteAllText($manifestPath,$valid)
Check 'fixed volume accepted' { Assert-DriveClassification ([IO.DriveType]::Fixed) }
foreach ($kind in @([IO.DriveType]::Network,[IO.DriveType]::Unknown,[IO.DriveType]::NoRootDirectory,[IO.DriveType]::Ram,[IO.DriveType]::Removable,[IO.DriveType]::CDRom)) {
    Check "unsupported or network volume rejected: $kind" { Reject { Assert-DriveClassification $kind } }
}
foreach ($bad in @('relative.zip','\\server\share\file.zip','\\?\C:\device.zip','C:\folder\..\file.zip','C:\file.zip:stream','C:\NUL.zip')) {
    Check "unsafe path rejected: $bad" { Reject { $null=Assert-LocalPath $bad } }
}
Check 'directory exact manifest and hashes accepted' { Verify $package $true }
$archive = Join-Path $root 'valid.zip'
[IO.Compression.ZipFile]::CreateFromDirectory($package,$archive)
Check 'archive independent read-back accepted' { Verify $archive $true }
Check 'extra executable rejected' { $p=Join-Path $package 'extra.exe';[IO.File]::WriteAllText($p,'MZ');try{Verify $package $false}finally{[IO.File]::Delete($p)} }
Check 'tampered member rejected' {
    $p=Join-Path $package 'browser/ui.js';$bytes=[IO.File]::ReadAllBytes($p);try{[IO.File]::WriteAllText($p,'forged');Verify $package $false}finally{[IO.File]::WriteAllBytes($p,$bytes)}
}
foreach ($field in @('authorized','schemaVersion','version','sourceRevision','productionAuthorization','files')) {
    Check "invalid manifest $field rejected" {
        $candidate=$valid | ConvertFrom-Json -AsHashtable
        $candidate[$field]=switch($field){'authorized'{$true};'schemaVersion'{4};'version'{'1.0-production'};'sourceRevision'{('0'*40)};'productionAuthorization'{'ALLOW'};'files'{@()}}
        try { [IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6));Verify $package $false }finally{[IO.File]::WriteAllText($manifestPath,$valid)}
    }
}
Check 'duplicate manifest field rejected' { try{[IO.File]::WriteAllText($manifestPath,$valid.Replace('{','{"schemaVersion":1,', [StringComparison]::Ordinal));Verify $package $false}finally{[IO.File]::WriteAllText($manifestPath,$valid)} }
Check 'invalid UTF-8 rejected' { try{[IO.File]::WriteAllBytes($manifestPath,[byte[]](255));Verify $package $false}finally{[IO.File]::WriteAllText($manifestPath,$valid)} }
Check 'oversized manifest rejected' { try{[IO.File]::WriteAllText($manifestPath,(' '*65537));Verify $package $false}finally{[IO.File]::WriteAllText($manifestPath,$valid)} }
Check 'zip traversal member rejected without extraction' {
    $bad=Join-Path $root 'bad.zip';[IO.File]::Copy($archive,$bad)
    $z=[IO.Compression.ZipFile]::Open($bad,[IO.Compression.ZipArchiveMode]::Update)
    try{$null=$z.CreateEntry('../outside.exe')}finally{$z.Dispose()}
    Verify $bad $false
    if(Test-Path (Join-Path $root 'outside.exe')){throw 'UNEXPECTED_EXTRACTION'}
}
Check 'case-colliding duplicate archive member rejected' {
    $bad=Join-Path $root 'duplicate.zip';[IO.File]::Copy($archive,$bad)
    $z=[IO.Compression.ZipFile]::Open($bad,[IO.Compression.ZipArchiveMode]::Update)
    try{$null=$z.CreateEntry('APP/ApprovalAgent.Mock.exe')}finally{$z.Dispose()}
    Verify $bad $false
}
Check 'staging create and rollback preserve archive' {
    $stage=Join-Path $root 'planned'
    Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Manage-Staging.ps1'),'-Mode','Create','-Destination',$stage,'-Package',$archive,'-ExpectedManifestSha256',((Get-FileHash $manifestPath).Hash),'-ExpectedSourceSha256',('a'*64))
    if(-not(Test-Path $stage)){throw 'STAGING_NOT_CREATED'}
    Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Manage-Staging.ps1'),'-Mode','Rollback','-Destination',$stage)
    if((Test-Path $stage) -or -not(Test-Path $archive)){throw 'ROLLBACK_WRONG_IMPACT'}
}
Check 'staging CLI rejects its own source checkout for every mode' {
    # Copy only the CLI and shared guard into a disposable Temp checkout shape.
    # A helper-only test would not catch missing repository wiring in the CLI.
    $fakeRepository = Join-Path $root 'source-checkout'
    $fakeTools = Join-Path $fakeRepository 'experiments/offline-release'
    $null = New-Item -ItemType Directory -Path $fakeTools -Force
    foreach ($file in @('Manage-Staging.ps1','Release.Common.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination (Join-Path $fakeTools $file)
    }
    foreach ($mode in @('Plan','Create','Rollback','CleanupRC')) {
        foreach ($destination in @($fakeRepository,(Join-Path $fakeRepository 'phase-9-12-release-candidate-probe'))) {
            $output = & pwsh -NoProfile -File (Join-Path $fakeTools 'Manage-Staging.ps1') -Mode $mode -Destination $destination -Package $archive 2>&1
            if ($LASTEXITCODE -eq 0 -or -not (($output | Out-String).Contains('STAGING_INSIDE_SOURCE'))) {
                throw "SOURCE_STAGING_GUARD_BYPASSED: $mode"
            }
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $fakeTools 'Manage-Staging.ps1'))) {
        throw 'SOURCE_GUARD_TEST_CHANGED_SOURCE'
    }
}
Check 'externally pinned archive and manifest hashes accepted' {
    $a=(Get-FileHash $archive -Algorithm SHA256).Hash
    $m=(Get-FileHash $manifestPath -Algorithm SHA256).Hash
    Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Verify-Package.ps1'),'-Package',$archive,'-ExpectedArchiveSha256',$a,'-ExpectedManifestSha256',$m,'-ExpectedSourceSha256',('a'*64))
}
Check 'wrong externally pinned checksum rejected' {
    $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $archive -ExpectedArchiveSha256 ('0'*64) 2>&1
    if($LASTEXITCODE -eq 0){throw 'WRONG_EXTERNAL_HASH_ACCEPTED'}
}
Check 'unexpected empty package directory rejected' {
    $extra=Join-Path $package 'unexpected';$null=New-Item -ItemType Directory -Path $extra
    try{Verify $package $false}finally{[IO.Directory]::Delete($extra)}
}
Check 'oversized ownership input rejected with no deletion' {
    $stage=Join-Path $root 'oversized-owner'
    $null=New-Item -ItemType Directory -Path $stage
    [IO.File]::WriteAllText((Join-Path $stage '.offline-stage-owned.json'),(' '*1025))
    [IO.File]::WriteAllText((Join-Path $stage 'deployment-plan.json'),'{}')
    $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Manage-Staging.ps1') -Mode Rollback -Destination $stage 2>&1
    if($LASTEXITCODE -eq 0 -or -not(Test-Path $stage)){throw 'OVERSIZED_OWNERSHIP_ACCEPTED'}
}
Check 'unowned cleanup rejected' {
    $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Manage-Staging.ps1') -Mode CleanupRC -Destination $root 2>&1
    if($LASTEXITCODE -eq 0 -or -not(Test-Path $root)){throw 'UNOWNED_CLEANUP_ACCEPTED'}
}

Check 'package checksum pin is mandatory' {
    $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $archive -ExpectedSourceSha256 ('a'*64) 2>&1
    if($LASTEXITCODE -eq 0){throw 'MISSING_PACKAGE_PIN_ACCEPTED'}
}
Check 'source pin is mandatory' {
    $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $archive -ExpectedManifestSha256 ((Get-FileHash $manifestPath).Hash) 2>&1
    if($LASTEXITCODE -eq 0){throw 'MISSING_SOURCE_PIN_ACCEPTED'}
}
Check 'wrong source pin rejected' {
    $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $archive -ExpectedManifestSha256 ((Get-FileHash $manifestPath).Hash) -ExpectedSourceSha256 ('b'*64) 2>&1
    if($LASTEXITCODE -eq 0){throw 'WRONG_SOURCE_PIN_ACCEPTED'}
}
Check 'committed manifest accepts externally verified revision without Git access' {
    $candidate=$valid | ConvertFrom-Json -AsHashtable
    $candidate.sourceMode='CommittedRelease';$candidate.sourceRevision='1'*40;$candidate.sourceTree='3'*40;$candidate.integrationManifestSha256='2'*64
    try {
        [IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6))
        Invoke-Native pwsh @('-NoProfile','-File',(Join-Path $PSScriptRoot 'Verify-Package.ps1'),'-Package',$package,'-ExpectedManifestSha256',((Get-FileHash $manifestPath).Hash),'-ExpectedSourceSha256',('a'*64),'-ExpectedRevision',('1'*40),'-ExpectedIntegrationManifestSha256',('2'*64))
    } finally {[IO.File]::WriteAllText($manifestPath,$valid)}
}
Check 'committed manifest requires external revision' {
    $candidate=$valid|ConvertFrom-Json -AsHashtable;$candidate.sourceMode='CommittedRelease';$candidate.sourceRevision='1'*40;$candidate.sourceTree='3'*40;$candidate.integrationManifestSha256='2'*64
    try{[IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6));Verify $package $false}finally{[IO.File]::WriteAllText($manifestPath,$valid)}
}
Check 'committed manifest cannot claim original baseline' {
    $candidate=$valid|ConvertFrom-Json -AsHashtable;$candidate.sourceMode='CommittedRelease'
    try{[IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6));Verify $package $false}finally{[IO.File]::WriteAllText($manifestPath,$valid)}
}
Check 'unsupported source mode rejected' {
    $candidate=$valid|ConvertFrom-Json -AsHashtable;$candidate.sourceMode='AnyDescendant'
    try{[IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6));Verify $package $false}finally{[IO.File]::WriteAllText($manifestPath,$valid)}
}
Check 'committed manifest wrong external revision rejected' {
    $candidate=$valid|ConvertFrom-Json -AsHashtable;$candidate.sourceMode='CommittedRelease';$candidate.sourceRevision='1'*40;$candidate.sourceTree='3'*40;$candidate.integrationManifestSha256='2'*64
    try{
        [IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6))
        $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $package -ExpectedManifestSha256 ((Get-FileHash $manifestPath).Hash) -ExpectedSourceSha256 ('a'*64) -ExpectedRevision ('2'*40) -ExpectedIntegrationManifestSha256 ('2'*64) 2>&1
        if($LASTEXITCODE -eq 0){throw 'WRONG_REVISION_PIN_ACCEPTED'}
    }finally{[IO.File]::WriteAllText($manifestPath,$valid)}
}


Check 'committed package requires integration approval pin' {
    $candidate=$valid|ConvertFrom-Json -AsHashtable;$candidate.sourceMode='CommittedRelease';$candidate.sourceRevision='1'*40;$candidate.sourceTree='3'*40;$candidate.integrationManifestSha256='2'*64
    try {
        [IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6))
        $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $package -ExpectedManifestSha256 ((Get-FileHash $manifestPath).Hash) -ExpectedSourceSha256 ('a'*64) -ExpectedRevision ('1'*40) 2>&1
        if($LASTEXITCODE -eq 0 -or -not (($result|Out-String).Contains('EXPECTED_INTEGRATION_MANIFEST_HASH_REQUIRED_OR_MISMATCH'))){throw 'MISSING_INTEGRATION_PIN_ACCEPTED'}
    }finally{[IO.File]::WriteAllText($manifestPath,$valid)}
}
Check 'committed package rejects altered integration approval pin' {
    $candidate=$valid|ConvertFrom-Json -AsHashtable;$candidate.sourceMode='CommittedRelease';$candidate.sourceRevision='1'*40;$candidate.sourceTree='3'*40;$candidate.integrationManifestSha256='2'*64
    try {
        [IO.File]::WriteAllText($manifestPath,($candidate|ConvertTo-Json -Depth 6))
        $result=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'Verify-Package.ps1') -Package $package -ExpectedManifestSha256 ((Get-FileHash $manifestPath).Hash) -ExpectedSourceSha256 ('a'*64) -ExpectedRevision ('1'*40) -ExpectedIntegrationManifestSha256 ('4'*64) 2>&1
        if($LASTEXITCODE -eq 0){throw 'WRONG_INTEGRATION_PIN_ACCEPTED'}
    }finally{[IO.File]::WriteAllText($manifestPath,$valid)}
}
$approvalPath=Join-Path $root 'approval.json'
$approval=@{schemaVersion=1;designation='PHASE_9_12_APPROVED_LINEAR_INTEGRATION';baseline=$script:Baseline;finalTip=('1'*40);finalTree=('3'*40);sourceContentSha256=('a'*64);commits=@(@{sha=('1'*40);parent=$script:Baseline;tree=('3'*40);purpose='Test fixture for the reviewed Phase 9-12 implementation';emptyJustification=$null})}
$approvalText=$approval|ConvertTo-Json -Depth 8
function Parse-Approval([string]$Text){[IO.File]::WriteAllText($approvalPath,$Text);return Read-IntegrationApproval $approvalPath ((Get-FileHash $approvalPath).Hash)}
Check 'integration manifest single-commit schema accepted' {$null=Parse-Approval $approvalText}
foreach($field in @('baseline','finalTip','finalTree','sourceContentSha256','commits','designation')){
    Check "integration manifest invalid $field rejected" {
        $copy=$approvalText|ConvertFrom-Json -AsHashtable
        $copy[$field]=switch($field){'baseline'{'0'*40};'finalTip'{'0'*40};'finalTree'{'0'*40};'sourceContentSha256'{'bad'};'commits'{@()};'designation'{'FUTURE_PHASE_APPROVAL'}}
        Reject {$null=Parse-Approval ($copy|ConvertTo-Json -Depth 8)}
    }
}
Check 'integration manifest duplicate fields rejected' {Reject {$null=Parse-Approval ($approvalText.Replace('{','{"schemaVersion":1,',[StringComparison]::Ordinal))}}
Check 'integration manifest checksum mismatch rejected' {[IO.File]::WriteAllText($approvalPath,$approvalText);Reject {$null=Read-IntegrationApproval $approvalPath ('0'*64)}}
Check 'integration manifest oversized input rejected' {[IO.File]::WriteAllText($approvalPath,(' '*262145));Reject {$null=Read-IntegrationApproval $approvalPath ((Get-FileHash $approvalPath).Hash)}}
Check 'integration manifest invalid UTF-8 rejected' {[IO.File]::WriteAllBytes($approvalPath,[byte[]](255));Reject {$null=Read-IntegrationApproval $approvalPath ((Get-FileHash $approvalPath).Hash)}}

Write-Output "$script:Passed/$script:Passed release-tool checks passed. Disposable evidence: $root"
