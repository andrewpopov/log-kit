---
kind: added
summary: Errors are logged through a bounded allowlist, so axios-style config, headers and response bodies never reach a line
---

`err` now carries only `type`, `message`, `stack`, `code`, `status`, a structured `cause` (depth 5) and AggregateError `errors` (10 at most), with message and stack truncated. Everything else on the error is dropped, whether it is a real Error, a pre-serialised look-alike or an Error nested under another key. `log.error(err, msg)` and `log.error(err)` are supported next to `log.error({ err }, msg)`. The `err` definition in `schema/log-line.json` is now closed (`additionalProperties: false`).
