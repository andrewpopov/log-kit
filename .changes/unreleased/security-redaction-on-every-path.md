---
kind: security
summary: Secrets, credentials and URL tokens are redacted on every logging path, and request or response bodies are never logged by default
---

The message, merge objects, child bindings and error text now pass through one bounded sanitiser. Credential keys (matched case-insensitively, after percent-decoding) become `[REDACTED]`, token usage counters such as `inputTokens` stay, and strings lose Bearer and Basic credentials, JWTs, URL userinfo, URL queries and fragments, and well-known key prefixes. Values under `body`, `payload`, `data` and `rawBody` are `[omitted]` unless `redact.allowPaths` lists a dotted path; `redact.keys` adds key names. The walk is bounded (depth 8, 200 keys, 100 items, 16 KB per string), never calls `toJSON`, shows a class instance such as an `http.IncomingMessage` by name only, and renders cycles, throwing getters and binary data as markers. Log-kit does not format `%s` operands: the level methods never accepted them, and any a JS caller passes are dropped.
