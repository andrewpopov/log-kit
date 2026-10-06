# log-kit

One fleet logger for Node services: a single JSON line schema, redaction on by default, HTTP request logging, stdout only. See PKG-203.

This README covers the core logger, error normalisation and redaction. The HTTP adapters land in a later slice.

## Usage

```ts
import { createLogger } from '@andrewpopov/log-kit';

const log = createLogger({ app: 'savoro', proc: 'web' });
log.info({ recipe_id: 42 }, 'recipe saved');
log.child({ req_id: 'r-1' }).warn('slow upstream');
```

`createLogger({ app, level?, proc?, destination?, redact? })`:

- `app`: service name, required, emitted on every line.
- `level`: `trace | debug | info | warn | error | fatal`. Defaults to `LOG_LEVEL` when set, otherwise `info`. An empty `LOG_LEVEL` counts as unset. Any other value throws `LogConfigError` with code `INVALID_LOG_LEVEL`.
- `proc`: process role, optional, emitted on every line.
- `destination`: omit for synchronous stdout. `{ file: '/path/app.log' }` is the opt-in `LOG_FILE` path for hosts without pm2 (synchronous, append). Those are the only two destinations; there are no worker transports.
- `redact`: additions to the built-in redaction, see Redaction. It can only add rules.

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

## Redaction

Every value a caller supplies (the message, merge objects, `child()` bindings, error text) is rebuilt through one sanitiser before pino sees it. Output is a fresh tree of plain data: a caller's `toJSON` and getters are never trusted, and anything the sanitiser does not recognise is walked as plain data, never passed through.

**Keys.** A key is normalised, then compared. Normalising folds and percent-decodes together, repeating until neither changes it (each `%XX` is decoded on its own, so one bad escape does not shield the rest; folding can create an escape, as in a full-width `％７０assword`, or a zero-width space inside `%70`). Folding is compatibility decomposition, so `ｐａｓｓｗｏｒｄ`, `paſſword` and `authorİzation` read as ASCII, and it drops combining marks, every default-ignorable character (zero-width, soft hyphen, Hangul filler) and the braille blank. The result is lower-cased and has `-`, `_`, `.`, `:` and whitespace removed. A key whose escapes are not valid UTF-8, or that is still changing after 8 decodes, is treated as a credential. A match replaces the value, whatever it holds, with `[REDACTED]`.

- Exact names: `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`, `apikey`, `x-auth-token`, `password`, `passwd`, `pass`, `pwd`, `auth`, `secret`, `client_secret`, `private_key`, `credentials`. Any key that ends in `auth` (`oauth`, `x-auth`, `smtp_auth`) matches too. `auth` is exact plus suffix, not a substring, so `author`, `authored` and `authenticated: true` stay visible.
- Substrings: `secret`, `password`, `passwd`, `apikey`, `signature`, `session`, `bearer`, `authorization`, `cookie`, `credential`, `privatekey`, `signingkey`, `encryptionkey`, `masterkey`, `authheader`, `authkey`, `authcode`, `authvalue`, and `token` with one exception.
- `pass` and `pwd` as a word of their own inside a name, found at camelCase and punctuation boundaries: `smtpPass`, `DB_PWD`, `user_pass`. `password` has its own entry and `passed`, `bypass` and `compass` are not words `pass`.
- **The `token` rule.** Delete every `tokens` and `tokencount`/`tokencounts` from the normalised key; if `token` is still in it, the key is a credential. So `token`, `accessToken`, `refresh_token`, `x-auth-token`, `csrfToken` and `tokenValue` are redacted, while `tokens`, `inputTokens`, `outputTokens`, `cacheReadTokens`, `cache_creation_input_tokens`, `max_tokens` and `token_count` are usage counters and stay. A counter key keeps its value only when that value is a number, bigint, boolean or null; a string, array or object under it is `[REDACTED]`, because `tokens: ['abc']` is a secret list, not a counter. A plural credential key such as `accessTokens` is therefore treated as a counter: put it in `redact.keys`.
- Object keys are redacted as strings too, so a secret used as a key name does not survive.

**Strings.** Applied to the message, every string value, object keys, and error `message`, `stack`, `type` and `code`:

- `Bearer <x>` always, except when the next word alone is plain English (`bearer token expired`; `Bearer token-abc` is still a credential). Every `Basic <x>` whose base64 value is 8 or more characters, with or without a `:` inside it, and a shorter one when it decodes to something with a `:`; `Basic authentication failed` reads as written.
- Credential names and their values: `password`, `passwd`, `secret`, `oauth`, `token`, `api_key`, `private_key`, `signing_key`, `encryption_key`, `master_key`, `signature`, `session`, `credential(s)`, `authorization` and `cookie`, followed by up to 32 more name characters (`AWS_SECRET_ACCESS_KEY=`, `sessionId=`, `X-Session-Id:`, `passwordConfirm=`, `tokenString=`) and `=` or `:`. `pass`, `pwd` and `auth` count as words of their own (`SMTP_PASS=`, `DB_PWD=`, `smtpPass:`, `X-Auth:`). A quoted value is matched escape-aware (`"ab\"cd"` is one value); anything else runs to the end of the line, so `password: correct horse battery` and a value opening `{` or `[` go whole. `token` is skipped only for a complete usage counter, `tokens` or `token_count` followed by a non-letter (`max_tokens=5`, `inputTokens: 12`); a plural credential name such as `accessTokens=` is therefore left readable in free text, as it is for keys. Prose such as `token: expired` is redacted too, the cost of catching `token: abc`.
- JWTs (`eyJ...` with three parts).
- URL userinfo: `https://user:pass@host` becomes `https://[REDACTED]@host`.
- URL query and fragment: the whole `?...` and `#...` after `scheme://host/path` is dropped and replaced by `?[REDACTED]`; the path stays. A scheme-less path such as `/cb?code=abc` loses its query the same way when it opens with `name=`.
- Key prefixes: `sk-` (at least 8 characters after it), `sk-ant-`, `sk_live_`/`sk_test_`/`rk_live_`/`rk_test_`, `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, `github_pat_`, `glpat-`, `xoxb-`/`xoxp-`/`xoxa-`/`xoxr-`/`xoxs-`, `AKIA`/`ASIA` access key ids, Google `AIza`, `npm_` and `hf_` (8 or more alphanumerics, so `npm_lifecycle_event` stays), `whsec_`, `tskey-`, `ya29.` and `GOCSPX-`. A prefix inside a longer word (`task-ant-worker`) is not matched.
- PEM `-----BEGIN ... PRIVATE KEY-----` blocks; one cut before its end is redacted to the end of the text.
- Webhook URLs whose secret is in the path: `discord.com`/`discordapp.com` `/api/webhooks/<id>/<token>`, `hooks.slack.com/services/...` and `api.telegram.org/bot<id>:<token>`. The host stays; the secret segment becomes `[REDACTED]`.

Every pattern is linear-time; a test sanitises 1 MB of each adversarial shape in under 100 ms. Redaction is idempotent.

**Structure.** Only plain data is walked: an object whose prototype is not `Object.prototype` or null (a class instance such as `http.IncomingMessage`, a Promise, `Headers`) is shown as `[ClassName]` and none of its fields are read. A class instance passed as the whole fields object is logged as `{ "fields": "[ClassName]" }`, and as child bindings as `{ "bindings": "[ClassName]" }`. Request logging belongs to the HTTP adapter, not to a raw `req`. The walk is bounded: depth 8 (a value deeper than that is `[truncated]`, a string included), 200 keys per object, 100 items per array, Map or Set, counting every item visited. Past a bound the value is `[truncated]`; an object that lost keys gains one `"[truncated]": <dropped count>` key. A string value is cut at 16 KB and ends in `…[truncated]`; redaction reads at most twice that much, cut back to the last whitespace, quote or bracket (or, with none within 4,096 characters, to the edge of that window) so a URL or credential is never left half cut. A cycle is `[circular]`, a getter that throws is `[unreadable]`, a Buffer, typed array or ArrayBuffer is `[binary N bytes]`. A Map is an array of `[key, value]` pairs (a string key, boxed or not, applies the same key rules) and a Set is an array. In any array, the element right after one that reads as a credential name is redacted, whatever the array's length or mix of types, which covers `[['x-api-key', 'S']]` pairs and flat `['Cookie', 'v', ...]` raw header lists. That over-redacts a word list such as `['password', 'email']` (the `email` goes); there is no telling a header list from a word list by shape, and that is the safe direction. Dates become ISO strings, a `URL` its sanitised `href`. Functions and symbols are dropped. An Error anywhere inside, a Map or Set included, becomes its allowlisted form and is walked with the same key rules. An error pre-serialised under another key, such as `{ error: axiosErr.toJSON() }`, is plain data, so `config.headers.Authorization` is redacted by key and `config.data` omitted as a body.

**Interpolation.** Not supported. The level methods take `(msg)`, `(fields, msg)` or `(err, msg?)`, and an extra argument is a type error. If a JS caller passes one anyway it is dropped, never formatted, so `log.info('login for %s', secret)` logs `login for %s` and a `%s` in `msg` stays literal. The final `msg`, including one pino derives from an error, is sanitised.

**Bodies.** Never logged by default: the value under `body`, `payload`, `data` or `rawBody` (matched like any key, so `Body` and `raw_body` count) is `[omitted]`, wherever it sits. To log part of one, list dotted paths in `createLogger({ redact: { allowPaths: [...] } })`:

```ts
createLogger({ app: 'orders', redact: { allowPaths: ['data.order.id'] } });
log.info({ data: { order: { id: 5, note: 'x' }, other: 1 } }, 'saved');
// "data":{"order":{"id":5,"note":"[omitted]"},"other":"[omitted]"}
```

- A path is the chain of object keys from the top of the logged fields (or of the `child()` bindings) down to the value, joined with `.`. Arrays add no segment: `data.items.id` allows `id` in every element of `data.items`.
- A listed path is logged in full, still redacted by the key and string rules. Inside a body, a value that is not listed, and is not on the way to a listed one, is `[omitted]`; a bare array item, and anything that is not plain data on the way (a class instance, boxed string, Date, Error, Map or Set), is `[omitted]` too.
- An allowed path never exposes a credential key: key rules run first. A key containing a `.` cannot be told from nesting.

**Extending.** `redact.keys` adds names. They get the same normalisation as the built-ins and match the whole key, not a substring (`keys: ['ssn']` hides `SSN` and `s_sn`, not `ssnLast4`). Nothing removes a built-in rule. Invalid options throw `LogConfigError` (`INVALID_ARGUMENT`).

**Not here.** Left to the app: email addresses and other personal data, long opaque tokens with no known prefix, `1//` Google refresh tokens, a bare `key`, `jwt` or `otp` key name (too common to guess), keys spelled with look-alike letters from another script (Cyrillic `а` for `a`; compatibility forms and invisible characters are handled, confusables are not), a `pass=` or `auth=` inside free text (only the keys are matched), and suppressing a whole call by its content (such as a login frame). Free text is pattern-based: pass credentials as fields under a credential key, not inside a sentence.

## Reserved envelope keys

`v`, `time`, `level`, `app`, `proc` and `msg` belong to the logger. A caller cannot set them through a merge object or `child()` bindings.

**Rule: a colliding key is moved under `ctx.<key>`.** It never overwrites the envelope and is never dropped.

```ts
log.info({ app: 'other', user: 'u1' }, 'hello');
// {"level":"info",...,"v":1,"app":"savoro","user":"u1","ctx":{"app":"other"},"msg":"hello"}
```

If you pass your own `ctx` object, relocated keys join it without replacing an entry of yours (a clash gets a trailing `_`). A `ctx` that is not an object is kept as `ctx.value`.

## Heartbeat

`startHeartbeat(logger, { intervalMs? })` emits `log heartbeat` once immediately and then every `intervalMs` (default 300000, a finite integer of at least 1000; anything else throws `LogConfigError` with code `INVALID_HEARTBEAT_INTERVAL`). Each line carries `heartbeat_interval_s`. It returns `{ stop() }`; `stop()` is idempotent. The timer is unref'd, so it never keeps a process alive, and a throwing logger is swallowed rather than crashing the process.

It exists so monitoring can tell a quiet source from a dead one: the zirkbot `logship-heartbeat-missing` alert fires when a source that heartbeated in the last 24h stops for 15m, keyed on `_msg:="log heartbeat"`. That msg is a contract. Do not change it.

```ts
const heartbeat = startHeartbeat(log);
// on shutdown
heartbeat.stop();
```

## Verify

`npm install && npm run verify`.
