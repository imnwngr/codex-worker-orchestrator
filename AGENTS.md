# Orchestrator — Agent Instructions

## 1. Core Principles

- Codex is the sole orchestrator and final decision-maker.
- AGY CLI and external AI providers are advisory workers.
- External workers must not independently modify the project.
- Follow existing security and execution policies.
- Preserve existing architecture and functionality.
- Prefer minimal, verifiable changes.

## 2. Instruction Priority

- Respect system, developer, and user instructions.
- Follow global Codex instructions.
- Follow rules/AI_ROUTING_POLICY.md.
- Treat this file as project-specific guidance.
- Never bypass approval or security boundaries.

## 3. Development Workflow

1. Inspect relevant code and existing instructions.
2. Identify the task scope and affected components.
3. Implement focused changes.
4. Run relevant tests and checks.
5. Review regressions and security implications.
6. Report actual results and remaining limitations.

## 4. UI/UX Workflow

Only activate this workflow for UI/UX tasks.

- Read DESIGN.md if available.
- Use `antislop` and relevant supporting skills
  for implementation quality and auditing.
- Apply Anti-slop during implementation.
- Run an Anti-slop audit before delivery.
- Verify accessibility, responsiveness,
  interaction states, and visual consistency.

Design priorities:
1. Functional correctness and accessibility.
2. Project-specific design requirements.
3. Anti-slop quality validation.

Do not apply UI-specific design rules to
backend, infrastructure, or orchestration logic.

## 5. Security and Change Control

- Preserve user changes and uncommitted work.
- Never bypass the Controlled Execution Broker.
- Respect approval boundaries and denied actions.
- Fail closed when permissions are uncertain.
- Do not execute live provider/API operations
  without appropriate authorization.
- Require explicit approval for destructive actions,
  dependency changes, system configuration,
  schema migrations, Git operations, and releases.

## 6. Quality Gates

Before completing a task:

- Verify the implementation against requirements.
- Run applicable tests and static checks.
- Check for unintended behavioral changes.
- Run UI quality checks when applicable.
- Report PASS, FAIL, or NOT RUN accurately.
- Never invent test results or claim unverified success.

## 7. Delivery

Summarize:
- Changes made.
- Tests executed and their results.
- Remaining issues and risks.
- Actions requiring user approval.

Never commit, push, or release without
explicit authorization.