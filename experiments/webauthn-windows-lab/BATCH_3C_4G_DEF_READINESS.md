# Phase 3C.4G-D/E/F — Read-only and synthetic readiness

**Scope:** fake-only recovery tests, read-only runtime capability reporting, XAML binding
contract checks and a WPF build in Windows CI. No native credential access is introduced.

## Evidence, not authorization

- The USER separately observed **WebAuthn API version 7** on Windows 11 build **22631**, x64,
  using a read-only `WebAuthNGetApiVersionNumber` call. This is specific to that machine and
  does not establish availability of any credential-operation export or authenticator.
- The repository's WPF diagnostics query **only** the API version and the UV-capable platform
  authenticator availability. Both are read-only. A version gate of **4 or higher** is a
  documented header prerequisite for platform inventory/deletion, not validation of the
  exports, execution, selected authenticator or cleanup.
- The RecoveryJournal and SyntheticInventory exist only in memory. They are not durable,
  credential inventories, attestations or authorization trust stores; a new process loses
  their state. Tests simulate reconciliation and do not provide hardware evidence.
- The WPF binding regression test statically checks the XAML contract. The Windows CI job
  builds the real WPF project. Headless CI does **not** assert a live UI window opened.

## Credential safety boundary

- No `MakeCredential`, `GetAssertion`, platform inventory, deletion, real credential prompt,
  approval grant, Broker integration, IPC, network client or dispatch is included.
- Unknown inventory, duplicate/invalid credential IDs and ambiguous cleanup fail closed.
  Absence in synthetic inventory does not prove deletion from a real authenticator.
- Platform inventory/deletion are not external-authenticator cleanup APIs. Synced passkeys,
  locked authenticators and third-party stores require separate verification.
- Same-user hostile processes, binary/UI spoofing and compromised registries remain risks.
  A caller-provided HTTPS origin and even a valid signature do not prove executable identity,
  displayed task bytes or independent USER authorization.
- Production authorization must stay **default-deny**. No real enrollment, assertion,
  inventory or deletion is approved by this batch.

## Explicit separate gates for any future live experiment

1. USER selects a disposable test machine/profile and dedicated non-production authenticator.
2. USER separately approves one exact test RP ID/origin, and an independently reviewed
   enrollment/orphan-recovery mechanism **before creating** a credential.
3. USER separately approves assertion scope, one-use challenge, exact immutable bytes and
   crash-durable replay plan; no production grant is accepted.
4. USER separately approves deletion of one exact ID; the plan includes pre/post inventory,
   lock/sync uncertainty, native ownership, ambiguous responses and manual recovery.
5. Real credential operations remain **NO-GO** pending those independent gates.
