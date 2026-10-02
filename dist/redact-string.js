"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.REDACTED = void 0;
exports.sanitizeString = sanitizeString;
exports.REDACTED = '[REDACTED]';
/**
 * Every pattern here is linear-time on adversarial input. The rules that keep it so:
 * - a match starts at a fixed literal (`://`, a keyword, a key prefix) or is anchored by a
 *   `(?<![\w-])` boundary, so a failed attempt never restarts inside the run it just scanned;
 * - no quantified group is nested inside another quantifier;
 * - whitespace inside a rule is `[ \t]`, never `\s`, so a value cannot run onto the next line.
 * The 1 MB adversarial test in `sanitize.test.ts` is what holds these to it.
 */
/** Characters that end a URL embedded in prose or JSON: whitespace, quotes, angle brackets, backtick, backslash. */
const URL_END = String.raw `\s"<>\x60\\`;
/** `://user:pass@host`. Greedy, so a password containing `@` is consumed up to the last one before the path. */
const USERINFO = new RegExp(String.raw `:\/\/[^${URL_END}/?#]+@`, 'g');
/**
 * The first `?` or `#` after `://host/path`, and everything after it. The lookbehind scans back only to the previous
 * `?`, `#` or URL end, so a run of them costs nothing extra.
 */
const URL_TAIL = new RegExp(String.raw `(?<=:\/\/[^${URL_END}?#]*)[?#][^${URL_END}]*`, 'g');
/** A query or fragment with no scheme (`/cb?code=abc`, `/cb#access_token=abc`): only when it opens with `name=`. */
const RELATIVE_QUERY = new RegExp(String.raw `[?#](?=[\w%.~+\-\[\]]*=)[^${URL_END}]*`, 'g');
/** Header lines that carry a credential. The value runs to the end of the line, or to the closing quote when quoted. */
const CREDENTIAL_HEADER = /\b((?:proxy-)?authorization|(?:set-)?cookie)(["']?[ \t]*[=:][ \t]*)(?:\[REDACTED\]|"[^"\n]*"|[^\r\n"]+)/gi;
/**
 * `password=hunter2`, `{"apiKey":"hunter2"}`, `x-auth-token: abc`. `token` is not followed by `s`, so `tokens=5` stays.
 * An existing `[REDACTED]` is matched first so a second pass changes nothing, and `}` ends an unquoted value.
 */
const KEY_VALUE = /((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|signature|session|credentials?)["']?[ \t]*[=:][ \t]*)(?:\[REDACTED\]|"[^"]*"|'[^']*'|[^\s,;&"'}]+)/gi;
/**
 * `Bearer <x>` always, except when the next word is plain English (`bearer token expired`). `Basic <x>` only when the
 * credential has a digit or base64 punctuation in it, so `Basic authentication failed` stays readable; an
 * `Authorization: Basic ...` header is caught whole by CREDENTIAL_HEADER anyway.
 */
const BEARER = /\b(Bearer)[ \t]+(?!(?:token|tokens|auth|authentication|authorization|scheme|header|credential|credentials|realm)\b)[\w.~+/=%-]+/gi;
const BASIC = /\b(Basic)[ \t]+(?=[A-Za-z0-9+/]*[\d+/=])[\w.~+/=%-]+/gi;
const JWT = /(?<![\w-])eyJ[\w-]+\.[\w-]+\.[\w-]*/g;
/**
 * Well-known credential prefixes. Bounded by `(?<![\w-])`, so `task-ant-worker` (which contains `sk-ant-`) is left
 * alone. `sk-` needs eight characters after it so `sk-8` in prose survives.
 */
const KEY_PREFIXES = new RegExp('(?<![\\w-])(?:' +
    [
        String.raw `sk-ant-[\w-]+`,
        String.raw `sk-[\w-]{8,}`,
        String.raw `(?:sk|rk)_(?:live|test)_\w+`,
        String.raw `gh[pousr]_\w+`,
        String.raw `github_pat_\w+`,
        String.raw `xox[abprs]-[\w-]+`,
        '(?:AKIA|ASIA)[0-9A-Z]{16}',
        String.raw `tskey-[\w-]+`,
        String.raw `ya29\.[\w-]+`,
        String.raw `GOCSPX-[\w-]+`,
    ].join('|') +
    ')', 'g');
/**
 * Redaction for one string: the final message, string values anywhere in a line, object keys, error messages and
 * stacks. Idempotent, so a value that passes through twice (an already-serialised `err`) reads the same.
 */
function sanitizeString(value) {
    return value
        .replace(USERINFO, `://${exports.REDACTED}@`)
        .replace(URL_TAIL, `?${exports.REDACTED}`)
        .replace(RELATIVE_QUERY, `?${exports.REDACTED}`)
        .replace(CREDENTIAL_HEADER, `$1$2${exports.REDACTED}`)
        .replace(KEY_VALUE, `$1${exports.REDACTED}`)
        .replace(BEARER, `$1 ${exports.REDACTED}`)
        .replace(BASIC, `$1 ${exports.REDACTED}`)
        .replace(JWT, exports.REDACTED)
        .replace(KEY_PREFIXES, exports.REDACTED);
}
