# Phase 9–12 — offline Windows release readiness

This release is **OFFLINE SYNTHETIC RELEASE CANDIDATE — NOT PRODUCTION AUTHORIZED**.
Source baseline: `2f3c61fd283261a0d5f1dbdcaa30b39433c9d97b`.
`OFFLINE_RC_READY` applies only after the integrated verification command passes.
`PRODUCTION_AUTHORIZATION_NO_GO` always applies. Every synthetic result retains
`authorized:false` and `DEFAULT_DENY`. There is no trusted consent proof.

## Implemented workstreams

| Phase | Delivery |
|---|---|
| 9A | Existing WPF review desk, guided empty/pending/recovery/terminal states, fresh-demo action, accessible labels and existing system-color support |
| 9B | Canonical A decisions, B fake initialization/consent/failure/crash/recovery, C local file/browser response workflow retained and exercised |
| 9C | Failed default-save retry fixed without another generation/deadline; corrupt recovery, reset, policy and stale-dialog checks retained; local preference locations checked |
| 9D | Fresh embedded synthetic template re-bound to explicit time/unique IDs, canonical rehash and full validator; executable .NET/Node/browser acceptance |
| 10A | .NET 8 framework-dependent x64 Windows publish, strict payload allowlist, bounded manifest, fixed archive timestamps, SHA-256 and independent archive read-back |
| 10B | Read-only preflight/plan, optional owned empty staging directory, verified rollback, restricted owned RC cleanup; no extraction or installation |
| 10C | Source revision/content inventory hash, version, runtime/architecture inventory, unsigned designation; bounded memory-only non-content transition diagnostics |
| 10D | This quick-start, error categories, prerequisites, rollback, cleanup, limits and hands-on checklist |
| 11A | Existing strict lifecycle and race regressions retained; stale dialog expiry and save-retry checks added; explicit UTF-8 subprocess interoperability |
| 11B | At most 32 immutable transition snapshots, sequence/category/method/generation only, no IDs/tasks/digests/principals; no persisted audit authority |
| 11C | Fixed-volume/reparse/traversal/ADS/device guards, create-new outputs, strict bounded manifest/ZIP read without extraction; collision-safe staging |
| 11D | Executable unchanged Broker/parser/protocol/native diagnostic boundaries, forbidden activation/secret patterns, exact package inventory; distinct offline and production gates |
| 12A | Full existing regression runner plus product, Node demo and release-tool adversarial tests |
| 12B | Fresh A/B/C acceptance, switching, response/replay, staging and rollback automation; hands-on GUI checklist below remains manual |
| 12C | WPF output + four standalone browser assets + quick-start + offline verifier/common tools + manifest in an unsigned local archive |
| 12D | Independent exact-baseline patch replay, full verification and independently built package comparison required for delivery; results in delivery report |

## Prerequisites and build

Use Windows x64, .NET 8 SDK for builds, PowerShell 7 and installed Node.js for
source verification. The published app needs the x64 **Microsoft.WindowsDesktop.App
8.0.x** runtime. It does not need Node for manual A/B/C use or creating a fresh demo
from WPF. Package inspection needs PowerShell 7; `-RequireRuntime` enforces launch
prerequisites. Tools do not install runtimes or dependencies. Use existing approved
runtime distributions separately if the prerequisite is missing.

Run from an isolated source checkout in one of the two externally pinned modes below.
For PatchReview, new delivery files must be visible to Git (intent-to-add only). CommittedRelease requires a clean index/worktree. The builder rejects
untracked material rather than copying it. The original checkout must remain intact.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    foreach ($project in @('approval-agent/ApprovalAgent.Mock','approval-agent/ApprovalAgent.MockTests','experiments/webauthn-windows-lab','experiments/webauthn-offline-assurance')) {
        dotnet build $project -c Release -p:NuGetAudit=false
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $project" }
    }
    pwsh -NoProfile -File experiments/offline-release/Verify-Release.ps1 -Mode PatchReview -ExpectedSourceSha256 REVIEWED_SOURCE_SHA256
    if ($LASTEXITCODE -ne 0) { throw 'Integrated verification failed' }
}
```

Publish outputs are outside the checkout, beneath the Windows Temp directory. The
builder uses a unique suffixed directory if the requested RC directory exists.
It permits exactly four WPF publish files and refuses additional publish payloads.
The manifest lists every payload member's path, byte length and SHA-256; it omits
itself to avoid a circular hash. `SHA256SUMS.txt` beside the archive hashes the ZIP
and its embedded manifest. Save an independently reviewed checksum separately.

## Hands-on demonstration

Launch the published `package/app/ApprovalAgent.Mock.exe`, then choose **Offline
Review Preview**. First-run selection is optional; Settings controls future defaults.
Choose **Create fresh demo**, save a new `.review.json` on a local fixed drive, and
review the generated action. The action uses reserved `.invalid` destinations and
five minutes from creation. The generated file follows the normal file validator.
It is never a production request. No new native operation is called by the demo.
The existing main window's read-only capability diagnostic remains unchanged.

- **A / Local Desktop:** inspect complete task, destination, wire body and digest;
  Approve Mock, Reject, or Cancel. Terminal state cannot be changed. Create another
  review for another outcome.
- **B / Protected Windows simulation:** Change Method, initialize/negotiate the fake
  component, then synthetic approve/deny/cancel. Crash leads to Unknown; explicitly
  abandon/recover. Failure/unavailable requires switching away and back or abandoning.
  No protected service, Windows Hello or authenticated IPC exists.
- **C / Remote Browser simulation:** Change Method, register/deliver fake request,
  export a new `.browser.json`. Open `package/browser/index.html` directly in a browser,
  select the package, review its read-only action, export a synthetic response, then
  import the downloaded `.response.json` into the same active WPF request before its
  deadline. The active .NET validator enforces exact instance/generation/session/action
  and consumes once. No network connection or trusted remote identity is established.
- While Pending, exercise A → B → C → A and A → C → B → A. Changing the future default
  never changes this request. Exported responses become stale after switching.

Prepare an automated fresh demo from source without opening a window:

```powershell
& {
    $ErrorActionPreference = 'Stop'
    pwsh -NoProfile -File experiments/offline-release/Prepare-Demo.ps1
    if ($LASTEXITCODE -ne 0) { throw 'Fresh demo acceptance failed' }
}
```

This verifies a fresh .NET-generated file through Node, actual A/B canonical outcomes,
both switching orders, .NET package → browser JS response → .NET file import and replay
rejection. Saved responses belong to that consumed process instance and are deliberately
unusable in a different WPF instance. Create another fresh demo for hands-on review.
Golden vectors are injected-clock regression data, not renewable live approvals.

## Package verification and dry-run distribution

From the source checkout (or use `package/tools/Verify-Package.ps1`), inspect the
archive without extracting it. Replace the checksum with the independently supplied
value; do not substitute an unreviewed checksum embedded alongside untrusted files.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $rc = Join-Path $env:LOCALAPPDATA 'Temp/phase-9-12-release-candidate'
    $zip = Join-Path $rc 'OFFLINE-SYNTHETIC-RC-NOT-PRODUCTION-AUTHORIZED.zip'
    pwsh -NoProfile -File experiments/offline-release/Verify-Package.ps1 -Package $zip -RequireRuntime -ExpectedSourceSha256 REVIEWED_SOURCE_SHA256 -ExpectedManifestSha256 REVIEWED_MANIFEST_SHA256
    if ($LASTEXITCODE -ne 0) { throw 'Package rejected' }
    $destination = Join-Path $env:LOCALAPPDATA ('Temp/offline-plan-'+[guid]::NewGuid().ToString('N'))
    pwsh -NoProfile -File experiments/offline-release/Manage-Staging.ps1 -Mode Create -Package $zip -Destination $destination -ExpectedSourceSha256 REVIEWED_SOURCE_SHA256 -ExpectedManifestSha256 REVIEWED_MANIFEST_SHA256
    if ($LASTEXITCODE -ne 0) { throw 'Staging plan failed' }
    pwsh -NoProfile -File experiments/offline-release/Manage-Staging.ps1 -Mode Rollback -Destination $destination
    if ($LASTEXITCODE -ne 0) { throw 'Plan rollback failed' }
}
```

You must supply `-ExpectedSourceSha256 <64-hex>` and at least one of `-ExpectedArchiveSha256 <64-hex>` / `-ExpectedManifestSha256 <64-hex>` to pin
known reviewed values. A matching hash is content integrity, not publisher identity.
The archive is unsigned, is not an installer and cannot update an installed version.
Read-only `-Mode Plan` makes no destination; `Create` creates only two planning files,
not an app installation. Rollback removes only those two verified owned files and an
otherwise empty planning directory; previous packages and versions remain untouched.

Cleanup is explicit and restricted to a recognized owned RC root under Temp with
verified archive/package and no unexpected/reparse entries. It refuses unrelated,
partial, corrupted or modified directories. Retain partial evidence for inspection.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $ownedRc = Join-Path $env:LOCALAPPDATA 'Temp/phase-9-12-release-candidate-REPLACE-WITH-OWNED-SUFFIX'
    pwsh -NoProfile -File experiments/offline-release/Manage-Staging.ps1 -Mode CleanupRC -Destination $ownedRc -ExpectedSourceSha256 REVIEWED_SOURCE_SHA256 -ExpectedManifestSha256 REVIEWED_MANIFEST_SHA256
    if ($LASTEXITCODE -ne 0) { throw 'Cleanup refused; inspect ownership/content' }
}
```

## Diagnostics, errors and recovery

WPF diagnostics retain at most 32 transitions in memory. They contain only sequence,
canonical/simulation state category, selected method, generation and fixed non-authority
fields. They omit task/request/session/digest/identity/path content. Countdown updates
are deduplicated. There are no audit files or telemetry. Process interruption loses
all review/session/diagnostic state; restart requires explicit reloading and a new
session. There is no durable approval or replay guarantee across restarts.

- Missing runtime: `WINDOWS_X64_DESKTOP_RUNTIME_REQUIRED`; install nothing through
  these scripts. Obtain the approved x64 .NET 8 Desktop Runtime separately.
- Invalid/expired file: keep the current valid review; create a fresh demo. Check UTC
  deadline and system clock. Switching/default preferences cannot extend expiry.
- Stale response: use the same active instance/method/generation. Re-export for a new
  session; do not edit a response or attempt to replay a consumed one.
- Save failure: choose a writable new local filename. Settings defaults remain unchanged
  on failure; method switching may already have succeeded and the feedback says so.
- `LOCAL_FIXED_VOLUME_REQUIRED`, `REPARSE_PATH_REJECTED`, unsafe output or permission
  failure: use an ordinary owned local fixed-volume Temp path. Do not disable safeguards.
- `MANIFEST_*`, `UNEXPECTED_*`, `PACKAGE_HASH_MISMATCH`: reject the artifact; rebuild in
  a fresh staging root. Never execute an artifact with failed integrity checks.
- Node `spawn EPERM`: report the exact error. Supplemental per-file Node execution is
  not standard Node CI equivalence; run the normal command on an authorized Windows host.
- Interrupted publish: no ready status is emitted; partial root remains diagnostic
  evidence and is not a Release Candidate. Re-run into a new unique root.

## Security and provenance limits

Windows Fixed classification is not physical-locality proof. Synchronization clients,
virtualized fixed volumes and concurrent filesystem changes can defeat locality
assumptions. Reparse checks and create-new files reduce accidental redirection and
overwrite, but check/open/rename/cleanup races and hard links remain a same-user attacker
risk. No native race-resistant file handle boundary is claimed. ZIP paths are allowlisted,
size bounded and hashed without extraction; there is no zip-slip extraction surface.
The verifier never executes package payloads. Package verifier scripts themselves must
come from independently reviewed source. A modified manifest plus modified payload can
match hashes unless a separately trusted checksum is pinned.

Fixed ZIP timestamps, ordering, deterministic .NET flags and source path mapping improve
same-host reproducibility. Independent same-host builds must be compared before making
that claim. SDK/runtime/OS or compiler differences across machines are not proven
reproducible. The source content hash identifies ordinal-sorted Git paths, index file modes and raw working-file SHA-256 values joined with LF;
it is not cryptographic build provenance or external certification. Remote CI is not
run by this batch and no new GitHub CI success is claimed. Pattern/diff security gates
are scoped regression checks, not proof of the absence of all secrets or vulnerabilities.

Production remains NO-GO pending USER decisions about trusted requester/UI/approver
identity, signed distribution, privileged installation, authenticated local/remote
channels, browser origin/device enrollment, credential lifecycle, trusted time,
durable atomic replay/consumption, administrator/same-user threat model and Broker
proof verification. Each live boundary needs separate authorization and review.

## Hands-on Windows acceptance — pending genuine observation

- Fresh demo, file replacement, Settings save/reset, denied policy, failure and retry.
- A/B/C all outcomes, both switching orders, expiry while method/file dialog is open.
- C actual browser import/download and WPF re-import; empty selection/cancel/stale read.
- Keyboard only: Tab/Shift+Tab, mnemonics, Escape, visible focus and restoration.
- 100/150/200% DPI, minimum window size, scrolling, long Unicode tasks, readable disabled states.
- Narrator announcement of action/status without countdown chatter; Windows high contrast
  and browser forced colors; browser 200% zoom and two ordinary browser engines.
- Confirm browser developer tools show no network requests. Source checks do not establish
  this observed behavior. No visual/accessibility result is marked PASS without observation.
## Phase 9–12 multi-commit integration contract (package manifest schema 3)

This contract applies only to the reviewed Phase 9–12 batch and the exact baseline
`2f3c61fd283261a0d5f1dbdcaa30b39433c9d97b`. It does not change general commit or release
policy for later phases. The final USER integration plan is prepared separately after
independent patch review. No number of commits, future commit SHA or historical date
is prescribed by release code. Do not backdate commits or rewrite published history.

`PatchReview` remains the default: exact original HEAD, no real staged changes, no
unknown untracked source, exact reviewed 25-file inventory and externally reviewed
source SHA-256. Intent-to-add is allowed for the known new files. Integration approval
arguments are rejected in this mode rather than silently ignored.

`CommittedRelease` accepts a linear chain of one or more approved non-merge commits
from that exact baseline, with a clean tracked index/worktree and no unknown untracked
files. It requires all of these externally supplied values:

- `-ExpectedRevision`: independently verified final integration tip, lower-case full SHA.
- `-ExpectedSourceSha256`: independently reviewed raw source identity from patch review.
- `-IntegrationManifest`: an existing bounded strict UTF-8 JSON approval file outside
  the repository under verification, on an ordinary local fixed volume without reparse
  ancestry. It is read-only input and is not copied into the source or RC package.
- `-ExpectedIntegrationManifestSha256`: SHA-256 of the exact externally reviewed manifest
  bytes. A matching locally generated file is not approval; independent review supplies
  the pin. The release workflow never generates or silently approves its own manifest.

The final USER-side PowerShell integration script should produce a draft only after
making the independently approved scoped commits in a disposable rehearsal or actual
approved integration workflow. Obtain independent review of the exact manifest, commit
deltas/purposes, final tree, tip and source identity; then pass its immutable checksum
as an external release input. This package does not implement or activate that final
integration script. Test-only fixtures are explicitly not production approvals.

External integration-manifest schema 1 has exactly these root fields:

```json
{
  "schemaVersion": 1,
  "designation": "PHASE_9_12_APPROVED_LINEAR_INTEGRATION",
  "baseline": "2f3c61fd283261a0d5f1dbdcaa30b39433c9d97b",
  "finalTip": "APPROVED_FINAL_40_HEX_SHA",
  "finalTree": "APPROVED_FINAL_40_HEX_GIT_TREE",
  "sourceContentSha256": "REVIEWED_64_HEX_SOURCE_PIN",
  "commits": [
    {
      "sha": "APPROVED_FIRST_40_HEX_SHA",
      "parent": "2f3c61fd283261a0d5f1dbdcaa30b39433c9d97b",
      "tree": "APPROVED_FIRST_40_HEX_GIT_TREE",
      "purpose": "Human-reviewed purpose within the Phase 9–12 implementation",
      "emptyJustification": null
    }
  ]
}
```

The illustrated single record is a shape example, not a required count or final plan.
For additional records, parent must equal the preceding SHA, in oldest-to-newest order.
The last record's SHA/tree must equal finalTip/finalTree. Commit lists are bounded to
512 entries and manifests to 262144 bytes for parser safety, not a required batch size.
Purposes are required nonempty text up to 240 characters without control codes.
`emptyJustification` must be null for a nonempty commit; an actual empty commit requires
an explicit independently reviewed justification of up to 512 characters. Unlisted or
unjustified empty descendants fail even when their final source tree is identical.
Out-of-scope file changes always fail; a prose justification cannot widen the reviewed
file scope. Intermediate in-scope edits are bound by exact approved commit/tree SHAs;
semantic relevance is assessed by the external reviewer, not guessed by a script.

The checker compares the exact first-parent sequence, every actual single parent from raw commit headers and
intermediate tree, and the final Git tree with the manifest. Git replacement objects
are ignored for ancestry checks. Missing/reordered/inserted/substituted commits, merges,
altered parents/trees and unrelated descendants fail closed. Combined baseline-to-tip
file inventory and complete raw source identity must reproduce the reviewed implementation.
A later commit is not accepted by merely updating ExpectedRevision; its approval manifest,
source identity, scope and any explicit empty exception also require independent review.

Source identity remains `SHA256_ORDINAL_MODE_PATH_RAW_FILE_SHA256_LF_JOIN_V1`: sort tracked
paths ordinally; form `mode:path:lowercase-file-sha256`, join by LF without trailing LF,
and SHA-256 the UTF-8 bytes. It covers all tracked files, including unchanged baseline
material. HEAD and external manifest are excluded. Git checkout line-ending differences
change this pin intentionally. `Inspect-Source.ps1` prints inspection data, not approval.

Package manifest schema 3 adds `sourceTree` and `integrationManifestSha256`. Both are
null in PatchReview; both are required, typed hashes in CommittedRelease. Actual HEAD
and its ProductVersion remain accurate. The shipped verifier needs no Git checkout;
it requires the externally reviewed artifact checksum, source identity and, for committed
packages, final revision plus integration-manifest checksum. It validates these claims
and payload hashes; only source preflight establishes ancestry and external approval
contents. Unsigned hashes are integrity evidence, not authenticated publisher provenance.

Use explicit reviewed values after independent review (never discover-and-approve HEAD):

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $tip = 'REPLACE_WITH_APPROVED_FINAL_40_HEX_SHA'
    $source = 'REPLACE_WITH_REVIEWED_64_HEX_SOURCE_PIN'
    $approval = 'C:\dev\temp\externally-reviewed-phase912-chain.json'
    $approvalHash = 'REPLACE_WITH_EXTERNAL_64_HEX_MANIFEST_PIN'
    if ($tip -notmatch '^[a-f0-9]{40}$' -or $source -notmatch '^[a-f0-9]{64}$' -or $approvalHash -notmatch '^[a-f0-9]{64}$') { throw 'Supply independently reviewed pins' }
    pwsh -NoProfile -File experiments/offline-release/Verify-Release.ps1 -Mode CommittedRelease -ExpectedRevision $tip -ExpectedSourceSha256 $source -IntegrationManifest $approval -ExpectedIntegrationManifestSha256 $approvalHash
    if ($LASTEXITCODE -ne 0) { throw 'Pinned chain release verification failed' }
}
```

For committed package verification/staging/cleanup, pass `-ExpectedRevision` and
`-ExpectedIntegrationManifestSha256` alongside the source and archive/manifest pins.
They do not require the external approval file or Git for offline package inspection.
One-commit compatibility is preserved through the same explicit manifest schema; there
is no unapproved single-commit bypass. Same-mode/same-tip reproducibility is tested.
Cross-mode binaries can differ because .NET embeds the actual revision in product versions.

The original repository's unrelated untracked material must remain untouched. Release
preflight instructs use of a clean isolated checkout. Never stage/delete/move user files
to satisfy this gate. Production remains DEFAULT_DENY / PRODUCTION_AUTHORIZATION_NO_GO.