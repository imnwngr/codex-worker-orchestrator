"use strict";
const preview = new OfflineBrowserPreview.Preview();
const status = document.getElementById("status"), details = document.getElementById("details");
const buttons = [...document.querySelectorAll("button[data-outcome]")];
let importGeneration = 0;
function refresh() { for (const button of buttons) button.disabled = preview.state !== "Pending"; }
const requestInput = document.getElementById("request");
requestInput.addEventListener("cancel", () => { ++importGeneration; });
requestInput.addEventListener("change", async event => {
  const generation = ++importGeneration;
  const file = event.target.files[0];
  if (!file) return;
  try {
    if (file.size > 262144) throw Error("oversized");
    const bytes = await file.arrayBuffer();
    if (generation !== importGeneration) return;
    const request = preview.load(new TextDecoder("utf-8", { fatal: true }).decode(bytes), Date.now());
    details.textContent = JSON.stringify(request, null, 2);
    status.textContent = "Pending synthetic review. All identity and digest claims remain untrusted.";
    buttons[0].focus();
  } catch { if (generation !== importGeneration) return; status.textContent = "Invalid, oversized or expired request; any active valid review retained."; }
  refresh();
});
for (const button of buttons) button.addEventListener("click", () => {
  ++importGeneration;
  try {
    const response = preview.respond(button.dataset.outcome, Date.now());
    const url = URL.createObjectURL(new Blob([response], { type: "application/json" }));
    const link = document.createElement("a"); link.href = url; link.download = "synthetic.response.json"; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    status.textContent = "Synthetic response exported. Return it to the active WPF session. Production remains DEFAULT_DENY.";
  } catch { status.textContent = "Response denied: expired or terminal review."; }
  refresh(); document.getElementById("request").focus();
});
setInterval(() => {
  if (preview.tick(Date.now()) === "Expired") status.textContent = "Expired or clock rollback detected. No response may be exported.";
  refresh();
}, 1000);
