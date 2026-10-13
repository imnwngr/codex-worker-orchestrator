# Security policy

This repository is a security-sensitive **prototype**. Please do not assume it is production ready.

## Current trust model

- Only Codex orchestrates AI work; Antigravity and API models are advisory-only.
- The local HTTP Broker is bound to loopback and authenticates the batch route separately from API provider credentials.
- External batch dispatch is **denied by default**. HTTP authentication is not independent user approval.
- The Ed25519 approval core is **not wired to the production endpoint**. It has no independent Windows signing UI, no protected IPC, and no durable cross-process replay store.
- Controlled Execution Broker (CEB) is not implemented. Never expose an arbitrary shell or filesystem-write endpoint in its place.

## Handling credentials

Never commit provider API keys, batch tokens, approval signing keys, `.env` files, private logs or real client tasks. `.gitignore` reduces accidental staging but **does not remove secrets from existing commits** or guarantee secret safety.

Before publishing the repository, inspect the **entire Git history** and enable GitHub secret scanning and push protection wherever available. If a credential has ever been committed, rotate/revoke it; merely deleting the file is not sufficient.

## Reporting a vulnerability

Until the repository maintainer configures a private vulnerability-reporting contact, **do not publish working exploits or private credentials in a public issue**. Contact the repository owner through an agreed private channel. Maintainers should enable GitHub private vulnerability reporting before making the project public.

## Scope

The test suite runs with mock workers. Passing tests do not certify live provider integrations, transport identity, approval integrity, operating-system security boundaries or disaster recovery.
