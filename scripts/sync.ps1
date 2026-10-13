<#
.SYNOPSIS
    Run tests, commit only already staged changes, and push the active branch.
.EXAMPLE
    git add broker/providers/approval-core.js broker/test/approval-core.test.js
    .\scripts\sync.ps1 -Message "feat: update approval core"
.EXAMPLE
    .\scripts\sync.ps1  # Push commits that already exist locally
#>
[CmdletBinding()]
param(
    [string]$Message = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-LastExit([string]$Step) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed (exit code $LASTEXITCODE). No further synchronization was attempted."
    }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $repoRoot
try {
    & git rev-parse --is-inside-work-tree | Out-Null
    Assert-LastExit "Git repository check"

    & git remote get-url origin | Out-Null
    Assert-LastExit "Git origin check (create/connect the GitHub repository first)"

    $branch = (& git branch --show-current).Trim()
    Assert-LastExit "Git branch lookup"
    if (-not $branch) { throw "Cannot push a detached HEAD." }

    Write-Host "`n[1/4] Test suite" -ForegroundColor Cyan
    & node --test
    Assert-LastExit "Node test suite"

    Write-Host "`n[2/4] Staged changes" -ForegroundColor Cyan
    $staged = @(& git diff --cached --name-only)
    Assert-LastExit "Git staged-files check"
    if ($staged.Count -gt 0) {
        $staged | ForEach-Object { Write-Host "  $_" }

        # This is an intentionally conservative filename check, not a secret scanner.
        $sensitive = @($staged | Where-Object {
            $_ -match '(?i)(^|/)(\.env($|\.)|approval-state|approval-logs|private[-_]?key)' -or
            $_ -match '(?i)\.(pem|key|p12|pfx)$'
        })
        if ($sensitive.Count -gt 0) {
            throw "Potentially sensitive staged paths. Remove them from the index before pushing: $($sensitive -join ', ')"
        }

        & git diff --cached --check
        Assert-LastExit "Git whitespace/diff check"
        if ([string]::IsNullOrWhiteSpace($Message)) {
            throw "There are staged changes. Supply -Message 'type: description' to commit them."
        }
        & git commit -m $Message
        Assert-LastExit "Git commit"
    }
    elseif (-not [string]::IsNullOrWhiteSpace($Message)) {
        Write-Warning "No staged changes; no new commit will be created."
    }

    Write-Host "`n[3/4] Working tree" -ForegroundColor Cyan
    & git status --short
    Assert-LastExit "Git status"
    Write-Host "Unstaged/untracked files are not automatically included." -ForegroundColor DarkYellow

    Write-Host "`n[4/4] Push $branch to origin" -ForegroundColor Cyan
    & git push -u origin $branch
    Assert-LastExit "Git push"
    Write-Host "`nSync completed successfully." -ForegroundColor Green
}
finally {
    Pop-Location
}
