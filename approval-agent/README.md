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
