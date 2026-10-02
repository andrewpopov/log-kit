# log-kit project guidelines

`@andrewpopov/log-kit`: one fleet logger for Node services on `pino`: a single
JSON line schema, word levels, redaction on by default, HTTP request logging,
synchronous stdout. Status: in progress (PKG-203). Fleet-wide package rules live
in `packages-meta`; this package's source and packed exports are authoritative.

## Layout

- `src/` — framework-free core (entry `.`). `./express` and `./fastify` adapters
  arrive in later slices; the core must never import either framework.
- `schema/log-line.json` — JSON Schema (2020-12) for the emitted line; exported
  as `./schema/log-line.json` and shipped in the tarball.
- CommonJS output, like `metrics-kit`, so CJS and ESM consumers both work.
- `dist/` is tracked: consumers install from a git tag.

## Design decisions

- **Schema v1 is the contract.** `{v, time, level, app}` plus `msg`, optional
  `proc`, `req_id`, `err`, `http`, then free-form fields. `level` is always the
  word, never pino's number. No `pid`/`hostname` (the log shipper adds host).
- **Reserved envelope keys** `v, time, level, app, proc, msg` can never be set by
  a caller. A collision is relocated to `ctx.<key>`, never dropped, never
  overwriting the envelope (`src/reserved.ts`).
- **Synchronous stdout, no worker transports.** `pino.destination({ fd: 1, sync: true })`.
  `{ file }` is the only other destination (the opt-in `LOG_FILE` path).
- **Two seams, one function each:** `sanitize` / `sanitizeString` (`src/sanitize.ts`,
  identity until PKG-203 S3 redaction) and `serializeError` (`src/serialize-error.ts`,
  the bounded allowlist error normaliser). Every caller value reaches output through
  them; do not add a second path around them. Pino's default `err` serializer is
  replaced with an identity on purpose: `normaliseFields` has already produced the
  allowlisted `err`, and pino's own would re-serialise it.
- **Typed config errors** (`LogConfigError.code`), like `MetricsConfigError`.

## Rules

- Every export is a compatibility commitment; add a `.changes/unreleased/`
  fragment for any user-visible change (see `RELEASING.md`).
- Do not hand-edit `CHANGELOG.md`; release-kit compiles it.
- Tests capture output through `createLoggerWithStream` (`src/logger.ts`, not
  exported from the package), never by patching `process.stdout`.

## Verify

`npm install && npm run verify` (typecheck, tests, build, dist freshness, pack
smoke, audits). `verify:dist-fresh` needs `src/` and `dist/` committed first.
The committed `.githooks/pre-push` runs the same chain.
