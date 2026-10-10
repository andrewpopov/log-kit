# Changelog

## Unreleased

## 0.1.0

- Errors are logged through a bounded allowlist, so axios-style config, headers and response bodies never reach a line
  `err` now carries only `type`, `message`, `stack`, `code`, `status`, a structured `cause` (depth 5) and AggregateError `errors` (10 at most), with message and stack truncated. Everything else on the error is dropped, whether it is a real Error, a pre-serialised look-alike or an Error nested under another key. `log.error(err, msg)` and `log.error(err)` are supported next to `log.error({ err }, msg)`. The `err` definition in `schema/log-line.json` is now closed (`additionalProperties: false`).
- Core logger (createLogger) on pino with JSON line schema v1, word levels and reserved envelope keys
  One JSON object per line to synchronous stdout (or an opt-in `LOG_FILE` path) with `v`, `time`, `level`, `app` and `msg`, plus optional `proc`, `req_id`, `err` and `http`. Caller fields that collide with a reserved envelope key are kept under `ctx`. The line schema ships as `@andrewpopov/log-kit/schema/log-line.json`. Requires Node `^22 || ^24 || >=26`.
- HTTP request logger for Express (httpLogger) as the ./express subpath
  `import { httpLogger } from '@andrewpopov/log-kit/express'` logs one line per request with `req_id` and an `http` object (`method`, `route`, `status`, `duration_ms`, `outcome`). The route is a template or `__unmatched__`, never the URL. Level follows status, a closed-before-finish request is logged once as `aborted`, and `ignore` skips healthy health checks only. Queries, headers, bodies, IP and user agent are never logged. `express` is an optional peer dependency; the core entry does not load it.
- startHeartbeat emits a periodic `log heartbeat` line so monitoring can detect a silent log source
  `startHeartbeat(logger, { intervalMs? })` logs one line immediately and then every interval (default 5m), with `heartbeat_interval_s`. Invalid intervals throw `LogConfigError` code `INVALID_HEARTBEAT_INTERVAL`.
- Secrets, credentials and URL tokens are redacted on every logging path, and request or response bodies are never logged by default
  The message, merge objects, child bindings and error text now pass through one bounded sanitiser. Credential keys (matched case-insensitively, after percent-decoding) become `[REDACTED]`, token usage counters such as `inputTokens` stay, and strings lose Bearer and Basic credentials, JWTs, URL userinfo, URL queries and fragments, and well-known key prefixes. Values under `body`, `payload`, `data` and `rawBody` are `[omitted]` unless `redact.allowPaths` lists a dotted path; `redact.keys` adds key names. The walk is bounded (depth 8, 200 keys, 100 items, 16 KB per string), never calls `toJSON`, shows a class instance such as an `http.IncomingMessage` by name only, and renders cycles, throwing getters and binary data as markers. Log-kit does not format `%s` operands: the level methods never accepted them, and any a JS caller passes are dropped.
