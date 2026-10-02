# log-kit

One fleet logger for Node services: a single JSON line schema, redaction on by default, HTTP request logging, stdout only. See PKG-203.

This README covers the core logger and error normalisation. Redaction and the HTTP adapters land in later slices.

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

Each level method takes `(msg)`, `(fields, msg)` or `(err, msg?)`. `child(bindings)` returns a logger that adds `bindings` to every line.

## Line schema v1

```json
{"level":"info","time":"2026-10-02T21:54:50.926Z","v":1,"app":"savoro","proc":"web","recipe_id":42,"msg":"recipe saved"}
```

- `v` is `1`; `time` is ISO 8601 UTC; `level` is always the word, never a number; `app` and `msg` are always present.
- Optional envelope fields: `proc`, `req_id`, `err` (see Errors) and `http`. Everything else is free-form.
- No `pid` or `hostname`: the log shipper adds the host.
- Key order is not part of the contract.

The schema is `@andrewpopov/log-kit/schema/log-line.json` (JSON Schema draft 2020-12).

## Errors

Every error is rewritten into a fixed shape before it is written. The shape is an allowlist: only the keys below are ever copied, so an axios error's `config.headers.Authorization`, `request`, `response`, `headers`, `body`, `data` and every other own or enumerable property never reach a line. A caller's `toJSON` is never called.

Supported call forms (all produce the same `err`):

```ts
log.error({ err }, 'upload failed'); // err key in the fields
log.error(err, 'upload failed');     // a bare Error; msg is optional
log.error(err);                      // msg defaults to the error's message
log.error({ error: err }, 'upload failed'); // an Error under any other key, or nested in plain objects and arrays
log.child({ err });                  // child bindings are normalised too
```

A value under the `err` key that is not an Error (a string, a number, a plain object) becomes `{ type: typeof value, message }` and never exposes the object's fields. A pre-serialised error (an object with a string `message`, such as axios's `toJSON()` output or an error that went through JSON) is read through the same allowlist. Only an `Error` instance is rewritten under other keys; a plain object there is ordinary data.

| Key | Content |
| --- | --- |
| `type` | Constructor name, else `name`, else `type`; at most 100 characters. |
| `message` | At most 2,000 characters. |
| `stack` | At most 50 frames and 8,000 characters. |
| `code` | A string or number; anything else is dropped. |
| `status` | A number, read from `status` or `statusCode`. |
| `cause` | The cause, in the same shape, to a total depth of 5 errors. |
| `errors`, `errors_truncated` | AggregateError entries (at most 10) and how many more were dropped. |

Cut text ends in `…[truncated]` and stays within its limit. Where a value cannot be shown, the field holds a marker string instead: `[circular]` for a cause chain that points back at itself, `[truncated]` past the depth limit, `[unreadable]` for a getter that throws.

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
