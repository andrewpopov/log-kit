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
    ['a quoted header in JSON text', '{"authorization":"Bearer abc","x":1}', '{"authorization":[REDACTED],"x":1}'],
    ['key=value secrets', 'connect failed password=hunter2 host=db', 'connect failed password=[REDACTED] host=db'],
    ['a JSON-quoted secret', '{"apiKey":"hunter2"}', '{"apiKey":[REDACTED]}'],
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
  const SIZE = 1_000_000;
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
  ];

  it.each(shapes)('1 MB of %j sanitises in under 100 ms', (unit) => {
    const text = unit.repeat(Math.ceil(SIZE / unit.length)).slice(0, SIZE);
    const started = performance.now();
    sanitizeString(text);
    expect(performance.now() - started).toBeLessThan(100);
  });
});
