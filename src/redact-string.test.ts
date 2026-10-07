import { describe, expect, it } from 'vitest';
import { sanitizeString } from './redact-string';

describe('sanitizeString redacts', () => {
  it.each([
    ['a Bearer header', 'sent Bearer abc123.def-456 upstream', 'sent Bearer [REDACTED] upstream'],
    ['a lower-case bearer header', 'authz bearer abc123', 'authz bearer [REDACTED]'],
    ['a Basic credential', 'sent Basic dXNlcjpwdw== upstream', 'sent Basic [REDACTED] upstream'],
    ['a whole Authorization line', 'Authorization: Basic abc\nnext line', 'Authorization: [REDACTED]\nnext line'],
    ['a Cookie line', 'Cookie: sid=abc; theme=dark', 'Cookie: [REDACTED]'],
    ['a Set-Cookie line', 'set-cookie: sid=abc; HttpOnly', 'set-cookie: [REDACTED]'],
    ['a quoted header in JSON text', '{"authorization":"Bearer abc","x":1}', '{"authorization":"[REDACTED]","x":1}'],
    ['key=value secrets, to the end of the line', 'connect failed password=hunter2 host=db', 'connect failed password=[REDACTED]'],
    ['a JSON-quoted secret', '{"apiKey":"hunter2"}', '{"apiKey":"[REDACTED]"}'],
    ['a token pair', 'refresh failed access_token=abc123', 'refresh failed access_token=[REDACTED]'],
    ['an x-api-key header', 'x-api-key: abc123', 'x-api-key: [REDACTED]'],
    ['URL userinfo', 'connect https://user:pass@db.internal:5432/app', 'connect https://[REDACTED]@db.internal:5432/app'],
    ['URL userinfo whose password holds an @', 'https://u:p@ss@host.com/x', 'https://[REDACTED]@host.com/x'],
    ['a redis URL with an empty user', 'redis://:hunter2@127.0.0.1:6379/0', 'redis://[REDACTED]@127.0.0.1:6379/0'],
    ['a URL query and fragment', 'GET https://api.example.com/v1/cb?code=abc&state=x#frag ok', 'GET https://api.example.com/v1/cb?[REDACTED] ok'],
    ['a URL fragment alone', 'see https://example.com/a#access_token=abc', 'see https://example.com/a?[REDACTED]'],
    ['a URL query inside JSON text', '{"url":"https://x.com/p?t=abc","n":1}', '{"url":"https://x.com/p?[REDACTED]","n":1}'],
    ['a relative path query', 'GET /cb?code=abc&state=x 200', 'GET /cb?[REDACTED] 200'],
    ['a JWT', 'jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl end', 'jwt [REDACTED] end'],
    ['an OpenAI style key', 'key sk-abcdefghijklmnopqrstuvwx used', 'key [REDACTED] used'],
    ['an Anthropic key', 'key sk-ant-api03-abcDEF_123-xyz used', 'key [REDACTED] used'],
    ['a Stripe key', 'key sk_live_abcDEF123456 used', 'key [REDACTED] used'],
    ['a GitHub token', 'ghp_abcDEF123456 gho_abcDEF123456 github_pat_11ABC_def456', '[REDACTED] [REDACTED] [REDACTED]'],
    ['a Slack token', 'xoxb-123-456-abcDEF xoxp-1-2 xoxa-1-2', '[REDACTED] [REDACTED] [REDACTED]'],
    ['an AWS access key id', 'id AKIAIOSFODNN7EXAMPLE used', 'id [REDACTED] used'],
    ['a Tailscale key', 'tskey-auth-kABC123CNTRL-abcdef123456', '[REDACTED]'],
    ['a Google OAuth token', 'ya29.a0AfH6SMBx-abc and GOCSPX-abc_123', '[REDACTED] and [REDACTED]'],
    ['an escaped quote inside a JSON password', 'body {"password":"ab\\"CANARYQ1"}', 'body {"password":"[REDACTED]"}'],
    ['an escaped quote inside a plain quoted value', 'password="abc\\"CANARYQ2" next', 'password="[REDACTED]" next'],
    ['a single-quoted value with an escaped quote', "token='a\\'CANARYQ3' next", "token='[REDACTED]' next"],
    ['an environment-style name', 'env AWS_SECRET_ACCESS_KEY=CANARYAWS region=x', 'env AWS_SECRET_ACCESS_KEY=[REDACTED]'],
    ['secret_key', 'secret_key=CANARYSK', 'secret_key=[REDACTED]'],
    ['sessionId', 'sessionId=CANARYSID', 'sessionId=[REDACTED]'],
    ['a session header', 'X-Session-Id: CANARYHDR', 'X-Session-Id: [REDACTED]'],
    ['passwordConfirm', 'passwordConfirm=CANARYPC', 'passwordConfirm=[REDACTED]'],
    ['a multi-word value to the end of the line', 'password: correct horse CANARYBATTERY\nnext', 'password: [REDACTED]\nnext'],
    ['a value that opens a brace', '{"credentials":{"user":"u","pass":"CANARYNEST"}}', '{"credentials":[REDACTED]'],
    ['a Basic credential that holds user:password', 'sent Basic dXNlcjpwYXNz now', 'sent Basic [REDACTED] now'],
    ['a short Basic credential with no digit', 'used Basic dTpw', 'used Basic [REDACTED]'],
    ['a Bearer credential that starts with a prose word', 'Authz is Bearer token-CANARYBT', 'Authz is Bearer [REDACTED]'],
    ['SMTP_PASS', 'SMTP_PASS=CANARYSP host=x', 'SMTP_PASS=[REDACTED]'],
    ['DB_PWD', 'DB_PWD=CANARYPWD', 'DB_PWD=[REDACTED]'],
    ['smtpPass', 'smtpPass: CANARYCAMEL', 'smtpPass: [REDACTED]'],
    ['OAUTH', 'OAUTH=CANARYOA', 'OAUTH=[REDACTED]'],
    ['an Auth header', 'X-Auth: CANARYXA', 'X-Auth: [REDACTED]'],
    ['tokenString, which merely starts like tokens', 'tokenString=CANARYTS', 'tokenString=[REDACTED]'],
    ['tokenSigningKey', 'tokenSigningKey=CANARYTSK', 'tokenSigningKey=[REDACTED]'],
    ['tokenCountKey, which is not a counter', 'tokenCountKey=CANARYTCK', 'tokenCountKey=[REDACTED]'],
    ['a signing key name', 'signing_key=CANARYSIGN', 'signing_key=[REDACTED]'],
    ['a Basic API key with no colon in it', 'Authz Basic U0VDUkVUa2V5Tm9Db2xvbg== x', 'Authz Basic [REDACTED] x'],
    ['a Basic value of exactly 8 characters', 'Basic abcdefgh', 'Basic [REDACTED]'],
    ['a Google API key', 'key=AIzaCANARYxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'key=[REDACTED]'],
    ['npm, Hugging Face, GitLab and Stripe webhook secrets', 'npm_CANARYa1b2 hf_CANARYc3d4 glpat-CANARYe5 whsec_CANARYf6', '[REDACTED] [REDACTED] [REDACTED] [REDACTED]'],
    ['a PEM private key', 'bad key -----BEGIN PRIVATE KEY-----\nMIIEvCANARYPEM\n-----END PRIVATE KEY----- after', 'bad key [REDACTED] after'],
    ['a PEM block cut before its end', '-----BEGIN RSA PRIVATE KEY-----\nMIIEvCANARYCUT', '[REDACTED]'],
    ['a Discord webhook URL', 'POST https://discord.com/api/webhooks/123456/CANARYhookTok failed', 'POST https://discord.com/api/webhooks/123456/[REDACTED] failed'],
    ['a Slack webhook URL', 'POST https://hooks.slack.com/services/T000/B000/CANARYslack failed', 'POST https://hooks.slack.com/services/[REDACTED] failed'],
    ['a Telegram bot URL', 'GET https://api.telegram.org/bot123:CANARYtg/getMe', 'GET https://api.telegram.org/bot[REDACTED]/getMe'],
  ])('%s', (_name, input, expected) => {
    expect(sanitizeString(input)).toBe(expected);
  });
});

describe('sanitizeString leaves readable', () => {
  it.each([
    'refresh token expired for user 7',
    'bearer token expired',
    'Bearer authentication failed',
    'Basic authentication failed',
    'tokens=5 inputTokens=12 max_tokens=100 token_count=3',
    'task-ant-worker and task-abcdefghijklmnopqrstuvwxyz and sk-8 configuration',
    'GET https://api.example.com/v1/items/42 200',
    'GET /v1/items/42 200 in 12ms',
    'really? yes',
    'mail person@example.com about it',
    'ghp is a prefix and AKIA too',
    'order 1234 shipped to Springfield',
    'npm_config_cache=/tmp npm_package_version=1.2.3 npm_lifecycle_event',
    'Basic authentication and Basic configuration failed',
    'author=bob authenticated=true',
    'POST https://discord.com/api/webhooks failed',
    'bypass=1 passed=3 compass=2 passage=4 tokens_used=5 inputTokens: 12 max_tokens: 100 token_count=7',
    'Basic abcdefg',
  ])('%s', (text) => {
    expect(sanitizeString(text)).toBe(text);
  });
});

describe('sanitizeString is idempotent', () => {
  it('reads the same after a second pass, so an already-sanitised value can pass through again', () => {
    const corpus = [
      'Authorization: Bearer abc.def\nCookie: a=1',
      'https://user:pass@host.com/p?q=1#f and /cb?code=abc',
      'password=hunter2 {"apiKey":"x"} Basic dXNlcjpwdw==',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln sk-ant-abcdefgh ghp_abc tskey-auth-abc',
    ];
    for (const text of corpus) {
      const once = sanitizeString(text);
      expect(sanitizeString(once)).toBe(once);
    }
  });
});

describe('sanitizeString runs in linear time', () => {
  /**
   * The guard compares the time for n and 8n characters, measured in the same process, so it holds on a runner several
   * times slower than a laptop. Linear input costs about 8x; a quadratic pattern costs about 64x.
   */
  const SIZES = [2_048, 16_384, 131_072, 1_048_576];
  const MAX_GROWTH = 24;
  /** Below this a time is mostly fixed overhead, so the pair moves up to a larger n. */
  const MEASURABLE_MS = 2;

  /** Best of three, so one GC pause or scheduler hiccup does not count. */
  const fastestRun = (text: string): number => {
    let fastest = Infinity;
    for (let run = 0; run < 3; run++) {
      const started = performance.now();
      sanitizeString(text);
      fastest = Math.min(fastest, performance.now() - started);
    }
    return fastest;
  };

  /**
   * How much slower 8n is than n, for the first n slow enough to measure (or the largest pair). A quadratic pattern is
   * measurable at a small n and fails there (about 20 s on skybox when the JWT anchor was removed), never reaching
   * 1 MB, where it would run for hours.
   */
  const growth = (unit: string): number => {
    const timeAt = (size: number) => fastestRun(unit.repeat(Math.ceil(size / unit.length)).slice(0, size));
    timeAt(SIZES[0]); // warm-up: compile every pattern before anything is timed
    let previous = timeAt(SIZES[0]);
    for (const size of SIZES.slice(1)) {
      const current = timeAt(size);
      if (previous >= MEASURABLE_MS || size === SIZES[SIZES.length - 1]) return current / previous;
      previous = current;
    }
    throw new Error('unreachable: SIZES has more than one entry');
  };

  const shapes: readonly string[] = [
    'a',
    'eyJ',
    'eyJ-',
    'eyJa.',
    '://',
    ':// ',
    '?',
    '?a',
    '#',
    '=',
    'token',
    'token=',
    'token="',
    'password',
    'cookie=',
    'Authorization:',
    'Bearer ',
    'Basic ',
    'Basic a',
    'sk-',
    'ghp_',
    'AKIA',
    ' ',
    '%',
    '@',
    'a@',
    'https://a:',
    'https://a@',
    '"',
    '[',
    'https://a/?',
    'a=b&',
    'Cookie: ',
    'eyJa.b.c.',
    'Basic a1 ',
    'sk-ant-',
    'x://y@z?',
    'password="',
    "password='",
    'password="\\"',
    'secret_',
    'SESSION_ID_',
    '-----BEGIN PRIVATE KEY-----',
    '-----BEGIN ',
    'discord.com/api/webhooks/1/',
    'hooks.slack.com/services/',
    'api.telegram.org/bot1:',
    'Basic YQ==',
    'password=x\n',
    'npm_',
    'AIza',
    'SMTP_PASS',
    'smtpPass',
    'pass=',
    'tokenS',
    'OAUTH',
    'Basic abcdefgh',
  ];

  it.each(shapes)('%j repeated: 8x the input costs under 24x the time', (unit) => {
    expect(growth(unit)).toBeLessThan(MAX_GROWTH);
  });
});
