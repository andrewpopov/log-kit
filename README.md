# log-kit

One fleet logger for Node services: a single JSON line schema, redaction on by default, HTTP request logging, stdout only. See PKG-203.

This README covers the core logger. Redaction, error normalisation and the HTTP adapters land in later slices.

## Usage

```ts
import { createLogger } from '@andrewpopov/log-kit';

const log = createLogger({ app: 'savoro', proc: 'web' });
log.info({ recipe_id: 42 }, 'recipe saved');
log.child({ req_id: 'r-1' }).warn('slow upstream');
```

`createLogger({ app, level?, proc?, destination? })`:

- `app`: service name, required, emitted on every line.
- `level`: `trace | debug | info | warn | error | fatal`. Defaults to `LOG_LEVEL` when set, otherwise `info`. An empty `LOG_LEVEL` counts as unset. Any other value throws `LogConfigError` with code `INVALID_LOG_LEVEL`.
- `proc`: process role, optional, emitted on every line.
- `destination`: omit for synchronous stdout. `{ file: '/path/app.log' }` is the opt-in `LOG_FILE` path for hosts without pm2 (synchronous, append). Those are the only two destinations; there are no worker transports.

Each level method takes `(msg)` or `(fields, msg)`. `child(bindings)` returns a logger that adds `bindings` to every line.

## Line schema v1

```json
{"level":"info","time":"2026-10-02T21:54:50.926Z","v":1,"app":"savoro","proc":"web","recipe_id":42,"msg":"recipe saved"}
```

- `v` is `1`; `time` is ISO 8601 UTC; `level` is always the word, never a number; `app` and `msg` are always present.
- Optional envelope fields: `proc`, `req_id`, `err` (`{type, message, stack}`) and `http`. Everything else is free-form.
- No `pid` or `hostname`: the log shipper adds the host.
- Key order is not part of the contract.

The schema is `@andrewpopov/log-kit/schema/log-line.json` (JSON Schema draft 2020-12).

## Reserved envelope keys

`v`, `time`, `level`, `app`, `proc` and `msg` belong to the logger. A caller cannot set them through a merge object or `child()` bindings.

**Rule: a colliding key is moved under `ctx.<key>`.** It never overwrites the envelope and is never dropped.

```ts
log.info({ app: 'other', user: 'u1' }, 'hello');
// {"level":"info",...,"v":1,"app":"savoro","user":"u1","ctx":{"app":"other"},"msg":"hello"}
```

If you pass your own `ctx` object, relocated keys join it without replacing an entry of yours (a clash gets a trailing `_`). A `ctx` that is not an object is kept as `ctx.value`.

## Verify

`npm install && npm run verify`.
