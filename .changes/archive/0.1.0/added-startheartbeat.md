---
kind: added
summary: startHeartbeat emits a periodic `log heartbeat` line so monitoring can detect a silent log source
---

`startHeartbeat(logger, { intervalMs? })` logs one line immediately and then every interval (default 5m), with `heartbeat_interval_s`. Invalid intervals throw `LogConfigError` code `INVALID_HEARTBEAT_INTERVAL`.
