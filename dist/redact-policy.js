"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_REDACT_POLICY = exports.normaliseKey = void 0;
exports.classifyKey = classifyKey;
exports.resolveRedactPolicy = resolveRedactPolicy;
const errors_1 = require("./errors");
/** Names whose value is always a credential, once normalised. */
const EXACT_KEYS = [
    'authorization',
    'proxy-authorization',
    'cookie',
    'set-cookie',
    'x-api-key',
    'api-key',
    'apikey',
    'x-auth-token',
    'password',
    'passwd',
    'pass',
    'pwd',
    'auth',
    'secret',
    'client_secret',
    'private_key',
    'credentials',
];
/**
 * Normalised keys containing one of these are credentials. `token` is handled apart (see `classifyKey`). Beyond the
 * required list, `passwd`, `authorization`, `cookie` and `privatekey` also match as substrings, because the object
 * under `cookies` or `authorizationHeader` is exactly as sensitive as the one under `cookie`. `credential` (so
 * `userCredential`), the `*key` names that are keys to something (`signing`, `encryption`, `master`) and `auth` followed
 * by `header`, `key`, `code` or `value` are included for the same reason. A `pass` or `pwd` that is a word of its own
 * inside a name (`smtpPass`, `DB_PWD`) is a credential too, but that needs the word boundaries `classifyKey` reads.
 *
 * `auth` is not a substring: it would redact `author`, `authored` and `authenticated: true`. Instead `auth` is an exact
 * name (Nodemailer's `{ auth: { user, pass } }`) and any key that ends in `auth` (`oauth`, `x-auth`, `smtp_auth`) matches.
 */
const SECRET_SUBSTRINGS = [
    'secret',
    'password',
    'passwd',
    'apikey',
    'signature',
    'session',
    'bearer',
    'authorization',
    'cookie',
    'privatekey',
    'signingkey',
    'encryptionkey',
    'masterkey',
    'credential',
    'authheader',
    'authkey',
    'authcode',
    'authvalue',
];
/** Keys whose value is a request or response body: omitted unless an allowed path says otherwise. */
const BODY_KEYS = new Set(['body', 'payload', 'data', 'rawbody']);
/**
 * The usage counters that contain the word `token` without being credentials: any `*tokens` key (`inputTokens`,
 * `max_tokens`, `cache_read_input_tokens`) and `token_count`. They are removed before looking for a credential token.
 */
const TOKEN_COUNTER = /tokens|tokencounts?/g;
/** How many layers of percent-encoding a key is unwrapped. A key that is still changing after this is not a plain name. */
const MAX_DECODE_LAYERS = 8;
/**
 * One layer of percent-decoding. Each ASCII `%XX` is decoded on its own, so one bad escape cannot shield the rest.
 * `failed` is set when an escape for a non-ASCII byte is not valid UTF-8 and has to stay encoded.
 */
function decodeLayer(text) {
    let failed = false;
    const decoded = text.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
        try {
            return decodeURIComponent(run);
        }
        catch {
            return run.replace(/%([0-9a-fA-F]{2})/g, (escape, hex) => {
                const code = parseInt(hex, 16);
                if (code < 0x80)
                    return String.fromCharCode(code);
                failed = true;
                return escape;
            });
        }
    });
    return { text: decoded, failed };
}
/**
 * Compatibility decomposition (NFKD), so `ｐａｓｓｗｏｒｄ`, `paſſword`, `İ` and the full-width `％７０` read as ASCII, then
 * the characters that show nothing are dropped: combining marks, every default-ignorable code point (zero-width, soft
 * hyphen, Hangul fillers) and the braille blank.
 */
const foldKey = (text) => text.normalize('NFKD').replace(/[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}\u2800]/gu, '');
/** Where a camelCase or punctuation boundary falls: `smtpPass`, `DB_PWD`, `HTTPServer`. */
const WORD_BOUNDARY = /[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/;
/**
 * Folds and percent-decodes together until neither changes the key, because each can create input for the other
 * (`%\u200b70` folds to `%70`, which decodes to `p`). A key still changing after 8 decodes is not a plain name. The
 * result is lower-cased and has `-`, `_`, `.`, `:` and whitespace removed.
 */
function readKey(key) {
    let current = key;
    let undecodable = false;
    let settled = false;
    for (let pass = 0; pass <= MAX_DECODE_LAYERS && !settled; pass++) {
        const next = decodeLayer(foldKey(current));
        undecodable || (undecodable = next.failed);
        settled = next.text === current;
        current = next.text;
    }
    const folded = foldKey(current);
    return {
        name: folded.toLowerCase().replace(/\u0131/g, 'i').replace(/[-_.:\s]/g, ''),
        words: folded.split(WORD_BOUNDARY).filter(Boolean).map((word) => word.toLowerCase()),
        undecodable: undecodable || !settled,
    };
}
const normaliseKey = (key) => readKey(key).name;
exports.normaliseKey = normaliseKey;
const NORMALISED_EXACT_KEYS = new Set(EXACT_KEYS.map(exports.normaliseKey));
function classifyKey(rawKey, policy) {
    const { name: key, words, undecodable } = readKey(rawKey);
    if (undecodable || words.includes('pass') || words.includes('pwd'))
        return 'secret';
    if (NORMALISED_EXACT_KEYS.has(key) || policy.extraKeys.has(key) || key.endsWith('auth'))
        return 'secret';
    if (SECRET_SUBSTRINGS.some((fragment) => key.includes(fragment)))
        return 'secret';
    const withoutCounters = key.replace(TOKEN_COUNTER, '');
    if (withoutCounters.includes('token'))
        return 'secret';
    if (BODY_KEYS.has(key))
        return 'body';
    return withoutCounters === key ? 'plain' : 'counter';
}
exports.DEFAULT_REDACT_POLICY = {
    extraKeys: new Set(),
    allowPaths: new Set(),
    allowPrefixes: new Set(),
};
function requireStringList(field, value) {
    if (value === undefined)
        return [];
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string' || entry.length === 0)) {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', `${field} must be an array of non-empty strings`);
    }
    return value;
}
function properPrefixes(path) {
    const segments = path.split('.');
    return segments.slice(0, -1).map((_, index) => segments.slice(0, index + 1).join('.'));
}
/** Validates `createLogger({ redact })` and merges it over the built-in policy. Options can only add to it. */
function resolveRedactPolicy(options) {
    if (options === undefined)
        return exports.DEFAULT_REDACT_POLICY;
    const keys = requireStringList('redact.keys', options.keys).map(exports.normaliseKey);
    if (keys.some((key) => key.length === 0)) {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', 'redact.keys entries must contain a character besides -, _ and whitespace');
    }
    const allowPaths = requireStringList('redact.allowPaths', options.allowPaths);
    if (allowPaths.some((path) => path.split('.').some((segment) => segment.length === 0))) {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', 'redact.allowPaths entries must be dotted paths with no empty segment');
    }
    return {
        extraKeys: new Set(keys),
        allowPaths: new Set(allowPaths),
        allowPrefixes: new Set(allowPaths.flatMap(properPrefixes)),
    };
}
