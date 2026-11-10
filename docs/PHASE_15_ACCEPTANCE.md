# Phase 14 acceptance: evidence boundary after Phase 15

Review date: 2026-11-11 (Asia/Bangkok). Baseline:
`662a864f03adabd09ede33ba1bbad20a2e83faf3`.

The retained baseline documentation lists hands-on acceptance as pending. The
Phase 14 temporary directories found on this machine contain no readable report,
image or pinned release package in the current sandbox view. Historical case
outcomes therefore cannot be reconstructed or re-certified here. No historical
PASS is promoted to a newly observed PASS.

| Case | Historical evidence available now | Phase 15 implementation | Newly observed result |
| --- | --- | --- | --- |
| A11Y01 | No retained case report available for re-verification | Real WPF driver: fresh request, Tab/Shift+Tab, method picker, Escape, focus restoration, Pending and request/context checks, PNG evidence | BLOCKED on real desktop; driver unverified. Even a successful driver run remains PARTIAL until visible focus is reviewed |
| A11Y05 Edge | No retained browser/WPF result available for re-verification | Visible WebDriver session, fresh profile/request, import/review/export, WPF import, nine binding fields, final ApprovedMock | BLOCKED; no actual Edge GUI run |
| A11Y05 Firefox | No retained browser/WPF result available for re-verification | Separate driver/profile/request/response; rejects reported headless execution and response reuse | BLOCKED; no actual Firefox GUI run |
| GUI13 | No retained configuration evidence | Shared agent/evidence infrastructure and explicit blocked-case record | BLOCKED: isolated authorized configuration required |
| A11Y02 | No retained configuration evidence | Shared infrastructure; configuration-specific behavior not implemented | BLOCKED: isolated authorized configuration required |
| A11Y03 | No retained configuration evidence | Shared infrastructure; configuration-specific behavior not implemented | BLOCKED: isolated authorized configuration required |
| A11Y04 | No retained configuration evidence | Shared infrastructure; configuration-specific behavior not implemented | BLOCKED: isolated authorized configuration required |

The current direct probe reports a `CodexSandboxDesktop-*` desktop and
`inputDesktop=false`. No desktop switch, UIAccess, elevation for GUI input,
scheduled task, Windows preference change, Narrator change or High Contrast/DPI
configuration change was attempted by this implementation.

An earlier denial-only IPC test reported WinSta0/Default. Its policy was disabled
or its session was intentionally wrong. It did not observe windows or send input;
it cannot establish real-GUI acceptance or authorization for the desktop.

The 151 WPF model tests, browser headless interoperability test, fake backend
tests and nonblank synthetic pixel test remain separate evidence categories.
They do not verify keyboard focus rendering, real browser download dialogs,
Windows UIA selectors or actual WPF client capture.

To finish acceptance, use the [isolated-session procedure](../desktop-agent/acceptance/README.md).
Supply reviewed package/driver pins, run each browser with a new request, preserve
its request/context/response identities, review actual images, and record the
session and OS/browser versions. The fixture workflow is an orchestration test;
it is not an A11Y01/A11Y05 substitute.
