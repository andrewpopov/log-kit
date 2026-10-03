export const REDACTED = '[REDACTED]';

/**
 * Every pattern here is linear-time on adversarial input. The rules that keep it so:
 * - a match starts at a fixed literal (`://`, a keyword, a key prefix) or is anchored by a
 *   `(?<![\w-])` boundary, so a failed attempt never restarts inside the run it just scanned;
 * - no quantified group is nested inside another quantifier, and a name tail is bounded;
 * - whitespace between a name and its value is `[ \t]`, never `\s`, so it cannot jump to the next line.
 * The 1 MB adversarial test in `redact-string.test.ts` is what holds these to it.
 */

/** Characters that end a URL embedded in prose or JSON: whitespace, quotes, angle brackets, backtick, backslash. */
const URL_END = String.raw`\s"<>\x60\\`;

/** `://user:pass@host`. Greedy, so a password containing `@` is consumed up to the last one before the path. */
const USERINFO = new RegExp(String.raw`:\/\/[^${URL_END}/?#]+@`, 'g');

/**
 * The first `?` or `#` after `://host/path`, and everything after it. The lookbehind scans back only to the previous
 * `?`, `#` or URL end, so a run of them costs nothing extra.
 */
const URL_TAIL = new RegExp(String.raw`(?<=:\/\/[^${URL_END}?#]*)[?#][^${URL_END}]*`, 'g');

/** A query or fragment with no scheme (`/cb?code=abc`, `/cb#access_token=abc`): only when it opens with `name=`. */
const RELATIVE_QUERY = new RegExp(String.raw`[?#](?=[\w%.~+\-\[\]]*=)[^${URL_END}]*`, 'g');

/** A quoted string (escape-aware, so `"a\\"b"` is one value), otherwise everything to the end of the line. */
const VALUE = String.raw`("(?:[^"\\]|\\[\s\S])*"|'(?:[^'\\]|\\[\s\S])*'|[^\r\n]+)`;

/** What follows a credential name: more name characters (up to 32), an optional quote, then `=` or `:`. */
const NAME_END = String.raw`[\w.-]{0,32}["']?[ \t]*[=:][ \t]*`;

/**
 * A credential name and the value after it: `password=hunter2`, `{"apiKey":"x"}`, `AWS_SECRET_ACCESS_KEY=x`,
 * `X-Session-Id: x`, `Authorization: Bearer x`, `Cookie: a=1; b=2`, `tokenString=x`. The keyword may be followed by up
 * to 32 more name characters, so a longer name that contains it is caught. `token` is skipped only when it is the whole
 * of a usage counter, `tokens` or `token_count`, followed by something that is not a letter (`max_tokens=5`,
 * `inputTokens: 12`); `tokenString`, `tokenSigningKey` and `tokensecret` are credentials.
 *
 * The value is a quoted string or everything to the end of the line: `password: correct horse battery` is one secret,
 * and so is a value opening `{` or `[`.
 */
const NAME_VALUE = new RegExp(
  String.raw`((?:password|passwd|secret|oauth|token(?!s(?![a-z])|[-_.]?counts?(?![a-z]))|api[_-]?key|private[_-]?key|signing[_-]?key|encryption[_-]?key|master[_-]?key|signature|session|credentials?|authorization|cookie)${NAME_END})${VALUE}`,
  'gi',
);

/**
 * `pass`, `pwd` and `auth` as a word of their own inside a name: `SMTP_PASS=x`, `DB_PWD=x`, `smtpPass=x`, `X-Auth: x`.
 * Case matters here (a camelCase boundary is a lower-case letter then `Pass`), so there is no `i` flag. `password` and
 * `author` have letters after the word and are not matched.
 */
const WORD_NAME_VALUE = new RegExp(
  String.raw`((?:(?<![A-Za-z])(?:[Pp]ass|PASS|[Pp]wd|PWD|[Aa]uth|AUTH)|(?<=[a-z0-9])(?:Pass|Pwd|Auth))(?![a-z])${NAME_END})${VALUE}`,
  'g',
);

/** Words that follow `Bearer` or `Basic` in ordinary prose. A credential is never just one of these on its own. */
const PROSE_WORDS = 'token|tokens|auth|authentication|authorization|scheme|header|credential|credentials|realm';

/** `Bearer <x>` always, except for a prose word alone: `bearer token expired`, but `Bearer token-abc` is a credential. */
const BEARER = new RegExp(String.raw`\b(Bearer)[ \t]+(?!(?:${PROSE_WORDS})(?!\S))[\w.~+/=%-]+`, 'gi');

/**
 * `Basic <x>`: every base64 value of 8 or more characters (a `user:password`, but also an API key with no colon);
 * a shorter one when it decodes to something with a `:` in it. A prose word alone (`Basic authentication failed`) stays.
 */
const BASIC = new RegExp(String.raw`\b(Basic)[ \t]+(?!(?:${PROSE_WORDS}|configuration|config|usage|setup)(?!\S))([A-Za-z0-9+/_-]+={0,2})`, 'gi');

/** Past this many decodes in one string the rest are redacted unread, which bounds the cost of a string made of them. */
const MAX_BASIC_DECODES = 64;
const MIN_BASIC_LENGTH = 8;

function isBasicCredential(value: string, decodes: number): boolean {
  return (
    value.length >= MIN_BASIC_LENGTH || decodes > MAX_BASIC_DECODES || Buffer.from(value, 'base64').toString('latin1').includes(':')
  );
}

const JWT = /(?<![\w-])eyJ[\w-]+\.[\w-]+\.[\w-]*/g;

/**
 * A private key block. An unterminated one (a log line cut mid-key) is redacted to the end of the text, which keeps
 * the pattern linear: a start with no end swallows the rest, so no later start rescans it.
 */
const PEM = /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|[\s\S]*)/g;

/** A secret carried in the URL path of a webhook: the host and the id are kept, the secret segment is not. */
const WEBHOOK_PATHS = [
  /(discord(?:app)?\.com\/api\/(?:v\d+\/)?webhooks\/\d+\/)[\w-]+/gi,
  /(hooks\.slack\.com\/(?:services|workflows|triggers)\/)[\w/-]+/gi,
  /(api\.telegram\.org\/(?:file\/)?bot)\d+:[\w-]+/gi,
];

/**
 * Well-known credential prefixes. Bounded by `(?<![\w-])`, so `task-ant-worker` (which contains `sk-ant-`) is left
 * alone. `sk-` needs eight characters after it so `sk-8` in prose survives, and `npm_` and `hf_` need eight
 * alphanumerics so an environment variable name like `npm_lifecycle_event` does (the run must also end at a non-word character).
 */
const KEY_PREFIXES = new RegExp(
  '(?<![\\w-])(?:' +
    [
      String.raw`sk-ant-[\w-]+`,
      String.raw`sk-[\w-]{8,}`,
      String.raw`(?:sk|rk)_(?:live|test)_\w+`,
      String.raw`gh[pousr]_\w+`,
      String.raw`github_pat_\w+`,
      String.raw`glpat-[\w-]+`,
      String.raw`xox[abprs]-[\w-]+`,
      '(?:AKIA|ASIA)[0-9A-Z]{16}',
      String.raw`AIza[\w-]{16,}`,
      String.raw`npm_[A-Za-z0-9]{8,}(?!\w)`,
      String.raw`hf_[A-Za-z0-9]{8,}(?!\w)`,
      String.raw`whsec_\w+`,
      String.raw`tskey-[\w-]+`,
      String.raw`ya29\.[\w-]+`,
      String.raw`GOCSPX-[\w-]+`,
    ].join('|') +
    ')',
  'g',
);

/** A quoted value keeps its quotes, so a redacted JSON fragment is still well formed and a second pass changes nothing. */
const redactedValue = (value: string): string => {
  const quote = value[0];
  return (quote === '"' || quote === "'") && value.length > 1 ? `${quote}${REDACTED}${quote}` : REDACTED;
};

const redactNameValue = (_match: string, name: string, secret: string): string => `${name}${redactedValue(secret)}`;

/**
 * Redaction for one string: the final message, string values anywhere in a line, object keys, error messages and
 * stacks. Idempotent, so a value that passes through twice reads the same.
 */
export function sanitizeString(value: string): string {
  let basicCredentials = 0;
  let text = value
    .replace(USERINFO, `://${REDACTED}@`)
    .replace(URL_TAIL, `?${REDACTED}`)
    .replace(RELATIVE_QUERY, `?${REDACTED}`)
    .replace(NAME_VALUE, redactNameValue)
    .replace(WORD_NAME_VALUE, redactNameValue)
    .replace(BEARER, `$1 ${REDACTED}`)
    .replace(BASIC, (match, scheme: string, credential: string) =>
      isBasicCredential(credential, ++basicCredentials) ? `${scheme} ${REDACTED}` : match,
    )
    .replace(JWT, REDACTED)
    .replace(PEM, REDACTED);
  for (const webhook of WEBHOOK_PATHS) text = text.replace(webhook, `$1${REDACTED}`);
  return text.replace(KEY_PREFIXES, REDACTED);
}
