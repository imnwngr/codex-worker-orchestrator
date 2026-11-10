# Phase 14 acceptance on an isolated desktop

The source supplies runnable drivers, not a claim that GUI acceptance passed.
Run only on a dedicated unlocked Windows account/VM authorized for these tests.
No script creates a Windows account, changes Narrator/High Contrast/scaling,
switches desktops, or elevates privileges.

Build and independently verify the development package as described in
[the agent setup](../README.md). Copy config.example.json outside the source,
set packageRoot and its reviewed manifest hash, and set isolatedDesktop=true
only after the session has been separately authorized. The launcher refuses
a non-input/default desktop and an account with an existing ApprovalAgent.Mock
method-preference file. It launches the packaged WPF executable only.
It never resets or edits an existing preference file.

```powershell
node desktop-agent/acceptance/run.js C:\dev\temp\phase15-a11y01.phase15-local.json
```

A11Y01 creates a fresh synthetic WPF review through the actual save dialog,
checks Tab/Shift+Tab, Enter opening the method picker, Escape closing that
dialog, restored focus and preserved Pending state. It captures actual
window images. Even if those behaviors verify, the case returns PARTIAL until
the visible focus indicator is independently reviewed in the captured images.

For A11Y05 set case to A11Y05 and supply both pinned driver paths/hashes.
The launcher runs Edge and Firefox separately with fresh profiles/download
directories and new WPF request IDs. No headless option is supplied, and a
reported Firefox headless session is rejected.

Obtain drivers from official sources, matching the installed browser:

- Edge WebDriver: https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/
- Firefox geckodriver: https://github.com/mozilla/geckodriver/releases

Install only into a project-local tools directory when needed. Review the
download origin, version and SHA-256 before populating the config. A hash
computed from an unreviewed download is not publisher identity. No drivers
are downloaded by the launcher and no browser versions are changed.

The WebDriver process binds loopback on a temporary port and is never exposed
through the production broker. It is a test adapter for an isolated account,
not a protected authenticated service. Same-user/local-port interference is
outside its security guarantee. Use the isolated environment to prevent
personal profile access and unrelated startup network activity.

Each browser imports the WPF-exported package into the actual local HTML page,
clicks Synthetic Approve, verifies the exported status, captures a browser image,
waits for its new response download, and imports that response through WPF.
Request/session/context/batch/instance/generation/challenge/nonce/expiry must
match exactly; WPF must visibly reach ApprovedMock. No consumed response is
reused. Both case results must use distinct IDs and artifact names.

Native file-dialog UIA IDs may differ by Windows version/localization. Current
drivers expect edit 1001 and accept button 1; WPF selectors use existing
AutomationIds or accessible names. Missing, duplicate, offscreen or disabled
controls fail closed. Inspect a scoped observation and update the reviewed
test selectors for that environment; do not invent a GUI PASS or replace
actions with a direct view-model call.

GUI13 and A11Y02-A11Y04 are represented in the output as BLOCKED until an
appropriately isolated, authorized configuration is available. Their actual
configuration-dependent behaviors have not been automated or verified here.
They are not converted to PASS by unit tests, source inspection or screenshots.

The generic synthetic counter runner proves the orchestration mechanism when
run successfully. It does not substitute for any Phase 14 case.
