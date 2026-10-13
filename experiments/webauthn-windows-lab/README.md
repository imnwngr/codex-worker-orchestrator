# INTEROPERABILITY LAB — NO APPROVAL

This is a package-free, fake-only Windows WebAuthn harness shell. It has no
native WebAuthn imports, `DllImport`, `NativeLibrary.Load`, network or IPC
code, persistent credential store, cryptographic signing, or authorization
grant path. The fake methods named for registration, assertion, and cleanup
operate only on in-memory synthetic data.

The standalone console project does not reference the WPF mock approval
agent, Broker, provider dispatch, or offline verifier. It cannot authorize
external transmission. “Assertion matched” means only that synthetic fields
matched the fake contract. It does not mean a signature was checked.

## Architecture and trust boundaries

- `NativeAbi.cs` contains layout snapshots and version metadata derived from
  the installed Windows SDK `webauthn.h`. It does not declare callable native
  entry points.
- `FakeNativeWebAuthn` simulates registration, assertion, cancellation,
  failures, fake result allocation, and cleanup in process memory.
- `RecoveryJournal` records versioned synthetic operation IDs, states,
  outcomes, fixed test RP/origin, fake credential metadata, cleanup attempts,
  and consumed challenge/nonce identifiers in memory only.
- `CborCose.cs` strictly parses a small bounded CBOR subset and validates the
  shape and supported algorithm parameters of synthetic ES256 and RS256 COSE
  keys. It is not an attestation validator or a signature verifier.
- `ClientData.cs` rejects duplicate JSON properties and compares challenge
  and origin exactly while retaining the original JSON bytes.
- `LabWorkflow.cs` models deterministic test states, ambiguous outcomes,
  explicit fake inventory reconciliation, expiration, and journal-backed
  in-process replay checks.
  No state represents actual approval.

The fake public-key fingerprint is SHA-256 over encoded COSE bytes, not a
canonicalized public key identity and not a production trust anchor.

No project file contains native imports or a live backend. There is no path
in this executable that can load or call MakeCredential, GetAssertion, or
DeletePlatformCredential.

## Installed SDK ABI facts used by the layout tests

The inspected header was:

```text
C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\webauthn.h
```

It defines `WINAPI` as `__stdcall` when not already defined and declares the
WebAuthn functions with that convention. Its version table maps API versions
1 through 9 to structure versions. The project records that table and tests
the x64 layouts of selected v1 structure prefixes against their header
fields. It does not infer the installed DLL's runtime API version from the
SDK header.

The snapshots use Windows x64 pointer width, default sequential alignment,
32-bit `DWORD`/`LONG`/`BOOL`, and pointer-sized handles. Build and run the
layout suite as x64. Layout results from this project do not establish that
the installed runtime accepts those structures or versions.

The host has `webauthn.dll` file version `10.0.22621.5624`; this shell does
not load it or query `WebAuthNGetApiVersionNumber`. Runtime API version,
export availability, and compatibility with the newer SDK header remain
unverified.

## Test-only RP and origin

Synthetic client-data values use:

```text
RP ID: lab.example.test (DNS identifier, not a URL)
Origin: https://approval.lab.example.test
```

These values are fixed fixtures, not production trust anchors. Native
`WEBAUTHN_CLIENT_DATA` accepts caller-provided UTF-8 JSON bytes. A caller can
write an HTTPS-looking `origin` into those bytes; this does not prove browser
origin, executable identity, application integrity, or what the user saw.
The RP ID scopes credentials and is hashed into authenticator data; it does
not authenticate the desktop application.

## Deterministic fake test plan

The package-free console runner covers:

- x64 `Marshal.SizeOf` and field offsets for header-confirmed v1 layouts;
- installed-header API-to-structure version mappings, unsupported API and
  structure versions, WINAPI metadata, and exact `S_OK` interpretation;
- duplicate client-data JSON keys, exact challenge/origin comparison, and
  retention of original bytes;
- truncated, indefinite-length, duplicate-key, trailing, and oversized CBOR;
- accepted ES256 P-256 and RS256 RSA COSE shapes plus unsupported algorithms,
  curves, and malformed key lengths;
- fake-owned result buffers, copying and deterministic release;
- enrollment failure, pre-start cancellation, unknown outcomes, cancellation
  racing with successful fake registration, created-but-unpinned recovery,
  and fake inventory reconciliation;
- revocation before cleanup, cleanup failure, response loss after synthetic
  deletion, explicit retry, inventory verification, and idempotent outcomes;
- fake credential ID, encoded-COSE-key fingerprint and algorithm mismatches;
- fake challenge expiry, one-use replay rejection across gates sharing one
  journal, and an explicit demonstration that a fresh journal has no durable
  replay history;
- rejection of any RP ID/origin override from untrusted input;
- JavaScript-compatible trimming of fixture task text and the exact resulting
  UTF-8 bytes/hash used as the displayed effective task.

The fake assertion contains no valid signature. No signing or offline
cryptographic assertion verification occurs. Existing verifier behavior is
covered by the separate Node contract lab and is not changed here.

Run from the repository root in regular Windows PowerShell:

```powershell
dotnet run --project .\experiments\webauthn-windows-lab\WebAuthn.WindowsLab.csproj
```

No package installation or network access is needed. This command was not run
when preparing this proposed diff.

## Limitations and future real-credential cleanup

The shell does not establish trusted enrollment, a trusted desktop origin,
application integrity, or independent USER approval. Same-user malware can
inspect or replace user-writable binaries, automate or spoof UI, and make its
own WebAuthn requests. A native caller-supplied origin does not prevent that.
There is no protected caller channel and no durable replay state across
process restarts. The new recovery journal is deliberately in-memory only.
Sharing it between fake workflow instances simulates a restart handoff; it
does not persist across an actual process restart and does not resist
same-user tampering. A completely fresh journal accepts previously consumed
challenge/nonce pairs because it has no prior history.

Unknown enrollment and cleanup outcomes must remain blocked until fake
inventory reconciliation. An inventory result is synthetic and cannot
establish the behavior or completeness of a Windows credential inventory.

There is no real credential to clean up. A future separately authorized
experiment must treat an interrupted MakeCredential operation as potentially
having created a persistent credential even if the app did not pin its key.
It must record enough test-only recovery information, disable use before
revocation cleanup, and require separate explicit confirmation before any
authenticator deletion. `WebAuthNDeletePlatformCredential` only addresses a
platform credential by ID; it does not clean an external authenticator.
Failed or uncertain cleanup requires manual recovery. No cleanup can be
claimed based only on a local registry entry being removed.

## Readiness

**READY** for compiling and running this fake-only shell after review.
**BLOCKED** for any real Windows Hello test until a later phase explicitly
authorizes credential creation and addresses runtime API version, trusted
test enrollment, recovery after interruption, authenticator selection,
origin/RP behavior, same-user process risk, and cleanup. A prompt or valid
signature must never be treated as independent USER approval.

Recovery ambiguity is modeled for both pinned credentials and known unpinned
orphans. A deletion response loss, cancellation after deletion, or inability to
check fake inventory blocks further cleanup attempts until reconciliation.
The fake inventory is not a reliable real authenticator inventory, and an
in-memory journal cannot survive an actual process restart.
