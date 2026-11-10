"use strict";
const { command } = require("./protocol");
class HeartbeatMonitor {
  constructor(bridge, taskId, { intervalMs = 2000, onState = () => {} } = {}) {
    if (!Number.isInteger(intervalMs) || intervalMs < 250 || intervalMs > 10000) throw new Error("HEARTBEAT_INTERVAL_INVALID");
    Object.assign(this, { bridge, taskId, intervalMs, onState }); this.stopped = true;
  }
  start() {
    if (!this.stopped) return;
    this.stopped = false;
    const tick = async () => {
      if (this.stopped) return;
      if (!this.bridge.pending) {
        try {
          const result = await this.bridge.execute(command("heartbeat", this.taskId));
          this.onState({ state: result.status === "OBSERVED" ? "CONNECTED" : "DENIED", at: Date.now() });
        } catch { this.onState({ state: "DISCONNECTED", at: Date.now() }); this.stop(); return; }
      }
      if (!this.stopped) this.timer = setTimeout(tick, this.intervalMs);
    };
    this.timer = setTimeout(tick, this.intervalMs);
  }
  stop() { this.stopped = true; clearTimeout(this.timer); }
}
module.exports = { HeartbeatMonitor };
