# Windows Approval Agent — Mock Prototype

> **MOCK PROTOTYPE.** This application does not authorize provider calls.

This isolated WPF prototype displays a fixed, synthetic proposal and allows
the user to record an in-memory mock outcome. Its destination uses the
reserved `.invalid` domain. The application has no Broker or provider
reference, HTTP client, IPC, Windows Hello integration, signing code, or
persistent storage.

The proposal is synthetic. The transmission warning describes what approval
would mean in a future system; this prototype sends nothing outside the
process. A mock approval is not an approval grant and cannot authorize
production batch dispatch.

## Requirements

- Windows
- .NET 8 SDK with the Windows Desktop targeting pack

No third-party NuGet packages are used. The `ApprovalAgent.MockTests` project
is a package-free console test harness. It links the pure model and view-model
source files directly, so it does not require WPF to test domain behavior.

## Read-only WebAuthn capability diagnostics

The application reports whether the Windows `webauthn.dll` and required API
functions are available, the reported API version, and the result of the
platform-authenticator availability query. It does not create or enumerate
credentials, sign data, request an assertion, or show a Windows Hello prompt.

This result is not evidence that Windows Hello is enrolled, that a credential
exists, that the USER is present, or that an approval occurred. Native
capability reporting also does not establish whether an enrolled credential
uses an algorithm accepted by the offline verifier.

The offline verifier requires trusted credential registration, ES256 or
RS256-compatible public keys, an exact `clientDataJSON` challenge, and pinned
origin/RP ID values. A desktop application still has no established trusted
origin/RP ID convention in this project. See
[`WEBAUTHN_OFFLINE_PROTOCOL.md`](../broker/docs/WEBAUTHN_OFFLINE_PROTOCOL.md)
for its remaining enrollment and trust requirements.


## Build and run

Run from the repository root in regular Windows PowerShell:

```powershell
dotnet build .\approval-agent\ApprovalAgent.Mock\ApprovalAgent.Mock.csproj
dotnet run --project .\approval-agent\ApprovalAgent.MockTests\ApprovalAgent.MockTests.csproj
dotnet run --project .\approval-agent\ApprovalAgent.Mock\ApprovalAgent.Mock.csproj
```

The proposal expires ten minutes after the application creates it. The task
text, task hash, displayed proposal, and mock outcome exist only in memory.
Closing the application discards the mock outcome.

## Security limits

- The fixed proposal is demonstration data, not a real task or trusted request.
- Approve Mock and Reject only change local in-memory state.
- A mock outcome proves neither informed user approval nor Windows Hello user
  presence or verification.
- This UI does not protect against same-user process interference, UI
  automation, impersonation, window spoofing, or application replacement.
- This project is not connected to the Broker. Production batch authorization
  remains deny-all.

Do not use this prototype to authorize external transmission. Real credential
enrollment, protected IPC, application integrity, durable replay protection,
and independent security review remain future work.

## UI / UX design (Hallmark)

The WPF mock now uses a native desktop review-desk layout: the synthetic-only
warning and local decision status are always visible, complete task text has
priority over diagnostic output, and read-only diagnostics are behind an
expandable disclosure. Keyboard access keys, the Escape-to-reject behavior,
read-only text fields and original mock state transitions are unchanged.

The documented design rationale, accessibility review and Windows manual
acceptance checklist are in [`UX_DESIGN.md`](UX_DESIGN.md). The layout is
informed by Hallmark's design rules adapted to WPF; this is not a browser
implementation. No fonts, third-party packages, credentials, endpoints or
production dispatch capabilities were added.
