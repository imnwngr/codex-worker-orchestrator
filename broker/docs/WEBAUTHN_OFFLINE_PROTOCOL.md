# WebAuthn approval protocol — offline prototype (Phase 3C.3C)

> **Not production authorization.** This is a synthetic, isolated verification
> prototype. It does not enroll credentials, prompt Windows Hello, establish
> user presence, provide protected Windows IPC, issue grants, or authorize
> outbound requests. `POST /v1/analyze/batch` remains deny-by-default.

## Threat boundary

`OfflineWebAuthnApprovalVerifier` accepts trusted configuration *only at
construction*:

- `origin`: exact HTTPS origin that the approval application is entitled to use;
- `rpId`: DNS relying-party ID, related to that origin;
- `credentials`: previously enrolled credential IDs, permitted COSE algorithms,
  and pinned public keys; this module **does not enroll** credentials;
- `sessionId`: fresh broker boot-session identifier;
- `configFingerprint`: digest of the **resolved destination and configuration
  actually used for dispatch**, computed by trusted broker code;
- `now`: the trusted clock (mocked only in tests).

**The repository has no trusted startup, enrollment, or protected IPC that
satisfies these preconditions.** Creating an instance with caller/Codex-provided
values would not be independent USER approval. The production broker must not
instantiate this class from HTTP JSON, worker output, or dynamic client options.

## Synthetic envelope (v1)

```json
{
  "version": 1,
  "approvalData": {
    "version": 1,
    "approvalId": "...",
    "providerId": "...",
    "modelId": "...",
    "taskSha256": "64 hex characters",
    "configFingerprint": "64 hex characters",
    "batchId": "...",
    "batchSha256": "64 hex characters",
    "nonce": "base64url of exactly 32 bytes",
    "sessionId": "...",
    "expiresAt": 1800000030000
  },
  "assertion": {
    "credentialId": "base64url",
    "credentialAlgorithm": -7,
    "clientDataJSON": "base64url",
    "authenticatorData": "base64url",
    "signature": "base64url"
  }
}
```

This format is distinct from the existing Ed25519 grant, which remains
unchanged. An additional `batchSha256` commits each grant to the exact ordered
set of provider/model/task-hash tuples so a subset or reordering cannot use
an already signed batch. Normalization of the task text **must precede**
hashing and be identical to what is transmitted to a provider. Any future
broker integration must prove that invariant and include effective destination
and routing settings in `configFingerprint`.

```text
challenge = BASE64URL(SHA256(
    UTF8("orchestrator-approval-webauthn-v1\0") ||
    UTF8(canonicalJson(approvalData))
))

batchSha256 = HEX(SHA256(
    UTF8("orchestrator-approval-batch-v1\0") ||
    UTF8(canonicalJson([
      { providerId, modelId, taskSha256 }, ...
    ]))
))

signedBytes = authenticatorData || SHA256(raw clientDataJSON)
```

The verifier checks strict schemas and canonical base64url encodings,
`clientDataJSON.type == "webauthn.get"`, the exact origin and challenge,
absence of cross-origin use, `SHA256(rpId)` in authenticator data, UP and UV
flags, no unsupported attested credential/extensions in assertion data,
credential ID and algorithm matching a trusted registry, and the WebAuthn
signature. Supported algorithms are ES256 (`-7`, P-256) and RS256 (`-257`,
RSA-2048+) only. The code does **not** assume Windows Hello's actual algorithm.

After *every* member of a batch verifies, this verifier synchronously marks
approval IDs and nonces consumed and updates optional signature counters.
This offers atomic in-memory one-time consumption **within one instance** only.
It is not cross-process/durable replay protection or crash recovery. The audit
callback receives redacted metadata, not task text, keys, or assertion bytes.

## Security limits and required work

1. Verify Windows Hello / WebAuthn algorithms and ceremony behavior on target
   machines, with explicit user verification for each approval.
2. Build an OS-protected, independently operated approval UI and IPC with
   reviewed identity/ACL protections. Same-user process separation is not enough.
3. Implement trusted enrollment and pinned credential lifecycle, RP ID/origin
   registration and validation; do not accept credential keys from request JSON.
4. Implement a trusted runtime derivation of resolved provider destination and
   configuration fingerprint, bound to **exact transmitted** task bytes.
5. Implement durable atomic consumption and integrity-protected audit with
   cross-process crash/restart semantics.
6. Perform security review before considering any production authorizer wiring.

The synthetic tests only establish the behavior of this standalone module.
The existing HTTP broker and Ed25519 Approval Core are unchanged.
