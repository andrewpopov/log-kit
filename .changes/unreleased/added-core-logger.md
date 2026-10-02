---
kind: added
summary: Core logger (createLogger) on pino with JSON line schema v1, word levels and reserved envelope keys
---

One JSON object per line to synchronous stdout (or an opt-in `LOG_FILE` path) with `v`, `time`, `level`, `app` and `msg`, plus optional `proc`, `req_id`, `err` and `http`. Caller fields that collide with a reserved envelope key are kept under `ctx`. The line schema ships as `@andrewpopov/log-kit/schema/log-line.json`. Requires Node `^22 || ^24 || >=26`.
