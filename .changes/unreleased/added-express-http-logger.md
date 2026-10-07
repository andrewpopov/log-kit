---
kind: added
summary: HTTP request logger for Express (httpLogger) as the ./express subpath
---

`import { httpLogger } from '@andrewpopov/log-kit/express'` logs one line per request with `req_id` and an `http` object (`method`, `route`, `status`, `duration_ms`, `outcome`). The route is a template or `__unmatched__`, never the URL. Level follows status, a closed-before-finish request is logged once as `aborted`, and `ignore` skips healthy health checks only. Queries, headers, bodies, IP and user agent are never logged. `express` is an optional peer dependency; the core entry does not load it.
