# Approval Agent Mock — UI/UX design record

This is a native **WPF desktop prototype**. Design guidance covers safe
redesign, interaction states and accessibility using native XAML controls,
rather than browser breakpoints or CSS syntax.

## Preflight and intended user

- **Audience:** a technical reviewer testing a synthetic approval proposal on
  Windows, not a consumer enrolling Windows Hello credentials.
- **Job:** inspect the **complete, exact task** and destination, understand the
  risk, then record **one local mock outcome**. Inspecting API diagnostics is
  secondary and informational.
- **Tone:** restrained, utilitarian review desk. No gradients, fake operating
  system chrome, status confetti, invented statistics or ornamental dashboards.
- **Stack:** WPF / .NET 8, `Segoe UI` for interface text, `Consolas` for exact
  task bytes, URL, hash and diagnostic JSON. No additional NuGet or font files.
- **Existing logic to preserve:** `ApprovalViewModel`, clock/expiry behavior,
  `ApproveMock_Click`, `Reject_Click`, Escape-to-reject, fake `.invalid`
  destination, diagnostic `Loaded` handler and scope, `StructuredReportJson`
  OneWay binding, no grants and no native credential operations.

## Hierarchy and layout

1. A pinned dark header identifies the application as a **LOCAL MOCK** with
   **NO DISPATCH**; it does not imply trusted application identity.
2. The first viewport presents the task and a visible no-real-approval warning.
3. Exact task text and SHA-256 sit in the primary reading region; provider,
   model, destination, UTC expiration and external-transmission warning are
   grouped in the secondary region.
4. Read-only WebAuthn diagnostics are contained in a collapsed disclosure.
   They still execute their existing read-only checks at window load. Opening
   the disclosure never starts a native credential ceremony.
5. A pinned bottom decision strip keeps the **status** and the two original
   mock actions available during task scrolling. Disabling a completed/expired
   action still comes from the original view model, not UI-only state.

The window retains native Windows resizing, text scaling and scroll behavior.
The task and JSON remain selectable, scrolling and strictly read-only. There
is no separate confirmation flow: one would change mock behavior rather than
just its presentation.

## Design evaluation

| Criterion | Self-score (1–5) | Evidence / remaining validation |
| --- | ---: | --- |
| Philosophy | 5 | Explicit safety hierarchy, fake-only semantics remain visible |
| Hierarchy | 5 | Task before diagnostics; persistent decision bar |
| Execution | 4 | WPF XAML parsed and static contracts checked; actual Windows visual pass pending |
| Specificity | 5 | Exact task hash, reserved destination, diagnostic caveats |
| Restraint | 5 | Semantic named brushes; no effects/icons/dependencies |
| Variety | 4 | Native review-desk layout instead of a generic hero/card landing page |

**Interaction and accessibility review:** action targets are 48 WPF units high;
hover, pressed and disabled states are provided by the shared button style;
keyboard focus is shown by a separate 2-unit outline; access keys are retained;
status changes have `AutomationProperties.LiveSetting="Polite"`; text contrast
is intentional and all warnings use text as well as color. Task and JSON boxes
are keyboard focusable for reading/copying. Screen-reader announcements, Windows
High Contrast and DPI/200% zoom behavior **still require a manual Windows pass**.
There are no async actions initiated by these buttons: the existing mock
handlers change local state synchronously, so artificial loading states would
misrepresent the behavior.

## Windows manual acceptance checklist

- Resize to 740×620, 1060×820 and a maximized window; check task readability,
  no clipped approval buttons, and vertical scrolling.
- Navigate by Tab/Shift+Tab and keyboard access keys; ensure focus remains
  visible and Escape still rejects while pending.
- Confirm the mock warning and no-dispatch label remain prominent.
- Open the diagnostics disclosure and confirm JSON scrolls and remains
  read-only; confirm the view model is scoped to that section.
- Check high-contrast settings, 125%/200% display scaling and screen-reader
  output before considering the redesign accessible beyond static checks.
- Approve and reject in separate launches and verify in-memory-only outcomes,
  terminal disabled buttons and no network/credential operations.

**Security posture:** this is a visual redesign only. WPF Mock is not an
approval grant or a Windows Hello authority, and production dispatch remains
DEFAULT-DENY.
