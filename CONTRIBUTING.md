# Contributing

Thank you for helping make the orchestrator safer and easier to use.

## Development principles

1. Preserve the authority hierarchy: USER > Codex > deterministic Broker > advisory workers.
2. Treat worker output as untrusted data, not instructions.
3. Keep external API dispatch denied unless independent, user-controlled approval has been established and verified.
4. Use scoped, reviewed changes; never weaken permissions or introduce a generic file-execution endpoint.
5. Add mock-based tests for new transport, routing, validation and authorization logic. Avoid real API calls or charges during CI.
6. Never add secrets or real user task contents to Git, tests, discussions or screenshots.

## Pull request workflow

```powershell
git pull --ff-only
node --test
git status --short
```

Keep pull requests focused. Explain the trust boundary affected, failure mode, tests run and expected compatibility effects. Changes to authorization, IPC, credential handling and future CEB features require explicit security review.

## Licensing

No license has been selected yet. Do not assume this repository grants open-source redistribution rights. Maintainers should select an appropriate license before inviting code contributions broadly.
