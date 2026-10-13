# Offline WebAuthn contract lab

This package-free Node.js harness tests bounded synthetic registration data
and assertion interoperability with
`broker/providers/webauthn-approval.js`. It is separate from the WPF mock
approval agent, Broker HTTP handling, and provider dispatch.

It performs no network access, native WebAuthn calls, credential ceremonies,
credential storage, approval issuance, or production authorization. RSA keys
are generated ephemerally during tests; a fixed synthetic P-256 private scalar
is also used. None of these test keys are enrolled credentials.

## Contracts covered

- Definite-length CBOR only; bounded input, nesting, item count, maps, arrays,
  strings, and byte strings; duplicate map keys and trailing bytes rejected.
- Only synthetic `fmt: "none"` attestation objects with an empty statement.
- Registration authenticator data must have UP, UV, and AT flags; the RP ID
  hash must match the explicit test policy; extensions and trailing bytes are
  rejected.
- Credential IDs are canonical base64url and 16–512 bytes.
- COSE public keys are limited to ES256 (`-7`, EC2/P-256, 32-byte coordinates)
  and RS256 (`-257`, RSA, 2048–4096-bit modulus, bounded exponent).
- Registration client data is retained as its original byte sequence and
  checked as `webauthn.create` against explicit synthetic expected values.
- Synthetic assertions use raw `clientDataJSON` bytes and are submitted to the
  existing offline verifier. The verifier remains the authority for assertion
  challenge, origin, RP hash, UP/UV, credential pinning, signature, and replay
  checks.

The expected origin `https://approval.example.test` and RP ID `example.test`
are fixture values only. A caller-controlled native desktop application does
not acquire a trusted browser HTTPS origin by placing one in client data.
An RP ID scopes a credential and is hashed into authenticator data; it does
not identify the executable or prove which application displayed a task.
The authenticator-bound private key and credential ID establish a
cryptographic relationship only after a trusted registration path has pinned
the public key and ID. None of these values alone proves application
integrity or informed, independent USER approval.

## Task bytes and normalization

`broker/providers/batch-security.js` currently returns `target.task.trim()`
from `validateBatch`; the downstream batch handler hashes that normalized
string. Approval data must bind the exact UTF-8 bytes of that effective
transmitted string. Hashing the raw request string before validation can
therefore bind different content. This lab demonstrates the difference and
does not change production validation or the protocol.

## Run

From the repository root, with Node.js already installed:

```powershell
node --test .\experiments\webauthn-contract-lab\contracts.test.js
```

No package installation or build step is needed.

## Future real enrollment lifecycle: design only

This lab does not execute this lifecycle. A separately approved experiment
would need a conspicuous test-only scope and explicit USER consent before
enrollment. It would use a reviewed test RP ID and origin policy, a unique
test user handle, an explicit platform-versus-external-authenticator policy,
and a setup record that pins the returned credential ID, selected algorithm,
and public key. Credential material would never come from a request or
proposal.

Treat enrollment as a recoverable state machine: `not_started`,
`ceremony_started`, `credential_created_unpinned`, `pinned`, and `revoked`.
After interruption, a `credential_created_unpinned` credential must never be
used; show its test identifier and require a separately approved cleanup
action. Revocation must remove the credential from the trusted registry
first. Authenticator deletion, if considered later, requires a distinct
explicit user action and confirmation; this lab does not call
`WebAuthNDeletePlatformCredential`. Provide manual recovery guidance if
authenticator cleanup cannot be confirmed. Platform availability does not
prove enrollment; Windows API selection may also involve an external
authenticator unless the experiment can establish and enforce its policy.

Even a successful real assertion would not establish independent approval
without a protected approval UI, reviewed application integrity and IPC,
trusted enrollment, exact displayed-to-signed-byte binding, and durable
replay handling. Production batch dispatch remains deny-all.
