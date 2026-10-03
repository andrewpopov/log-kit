import { readFileSync } from 'node:fs';
import { IncomingMessage } from 'node:http';
import { Socket } from 'node:net';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import { describe, expect, it } from 'vitest';
import { LogConfigError } from './index';
import type { CreateLoggerOptions, Logger } from './index';
import { createLoggerWithStream } from './logger';
import { classifyKey, DEFAULT_REDACT_POLICY } from './redact-policy';
import { sanitize } from './sanitize';
import { captureStream } from './test-support';
import type { CapturedLines } from './test-support';

const validateLine = new Ajv2020({ strict: true }).compile(
  JSON.parse(readFileSync(join(__dirname, '..', 'schema', 'log-line.json'), 'utf8')),
);

interface Run {
  readonly out: CapturedLines;
  readonly log: Logger;
}

/** A logger over an in-memory stream. Every line it emits is checked against the line schema as it is read back. */
function start(options: Partial<CreateLoggerOptions> = {}): Run {
  const out = captureStream();
  return { out, log: createLoggerWithStream({ app: 'demo', level: 'trace', ...options }, out) };
}

function lines(run: Run): Record<string, unknown>[] {
  for (const line of run.out.lines) expect(validateLine(line), JSON.stringify(validateLine.errors)).toBe(true);
  return run.out.lines;
}

/** Asserts that none of `secrets` appears anywhere in the raw bytes written, in any encoding the logger could pick. */
function expectNoneEmitted(run: Run, secrets: readonly string[]): void {
  lines(run);
  for (const secret of secrets) {
    expect(run.out.raw, `leaked ${secret}`).not.toContain(secret);
    expect(run.out.raw, `leaked ${secret} (JSON-escaped)`).not.toContain(JSON.stringify(secret).slice(1, -1));
  }
}

const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUllKV1QifQ.c2lnbmF0dXJlQ0FOQVJZSldU';

describe('canary: no secret reaches the raw bytes, through every entry point', () => {
  it('msg, as a single string and as the message beside a merge object', () => {
    const run = start();
    run.log.info('auth failed Bearer CANARY-MSG-BEARER for https://CANARYMSGUSER:CANARYMSGPASS@host.example/x?token=CANARY-MSG-QUERY');
    run.log.info({ ok: 1 }, 'retry with Bearer CANARY-MSG2-BEARER and key sk-CANARYMSG2KEYabcdef');
    expectNoneEmitted(run, [
      'CANARY-MSG-BEARER',
      'CANARYMSGUSER',
      'CANARYMSGPASS',
      'CANARY-MSG-QUERY',
      'CANARY-MSG2-BEARER',
      'CANARYMSG2KEYabcdef',
    ]);
    expect(lines(run)[0].msg).toContain('Bearer [REDACTED]');
  });

  it('a merge object: top level, nested, in arrays, under mixed-case and percent-encoded keys', () => {
    const run = start();
    run.log.info(
      {
        password: 'CANARY-TOP-PASSWORD',
        nested: { deeper: { client_secret: 'CANARY-NESTED-SECRET' } },
        list: [{ apiKey: 'CANARY-ARRAY-APIKEY' }, [{ Token: 'CANARY-ARRAY2-TOKEN' }]],
        AuThOrIzAtIoN: 'CANARY-MIXED-AUTH',
        '%41uthorization': 'CANARY-ENCODED-AUTH',
        'x%2DAPI%2Dkey': 'CANARY-ENCODED-XAPIKEY',
        '%2574oken': 'CANARY-DOUBLE-ENCODED-TOKEN',
        'X_Api_Key': 'CANARY-UNDERSCORE-XAPIKEY',
        headers: { 'Set-Cookie': 'sid=CANARY-SETCOOKIE', Cookie: 'sid=CANARY-COOKIE' },
        'bad%zzescape%74oken': 'CANARY-PARTIAL-ESCAPE',
      },
      'merge',
    );
    expectNoneEmitted(run, [
      'CANARY-TOP-PASSWORD',
      'CANARY-NESTED-SECRET',
      'CANARY-ARRAY-APIKEY',
      'CANARY-ARRAY2-TOKEN',
      'CANARY-MIXED-AUTH',
      'CANARY-ENCODED-AUTH',
      'CANARY-ENCODED-XAPIKEY',
      'CANARY-DOUBLE-ENCODED-TOKEN',
      'CANARY-UNDERSCORE-XAPIKEY',
      'CANARY-SETCOOKIE',
      'CANARY-COOKIE',
      'CANARY-PARTIAL-ESCAPE',
    ]);
    expect(lines(run)[0]).toMatchObject({ password: '[REDACTED]', nested: { deeper: { client_secret: '[REDACTED]' } } });
  });

  it('child bindings, and a child of a child', () => {
    const run = start();
    const child = run.log.child({ token: 'CANARY-CHILD-TOKEN', req: { headers: { Authorization: 'CANARY-CHILD-AUTH' } } });
    child.info('one');
    const grandchild = child.child({ client_secret: 'CANARY-GRANDCHILD-SECRET', note: `see Bearer CANARY-GRANDCHILD-BEARER` });
    grandchild.info('two');
    grandchild.child({ list: [{ password: 'CANARY-GREAT-PASSWORD' }] }).info({ own: 1 }, 'three');
    expectNoneEmitted(run, [
      'CANARY-CHILD-TOKEN',
      'CANARY-CHILD-AUTH',
      'CANARY-GRANDCHILD-SECRET',
      'CANARY-GRANDCHILD-BEARER',
      'CANARY-GREAT-PASSWORD',
    ]);
    expect(lines(run)).toHaveLength(3);
  });

  it("an Error's message and stack, a cause chain and an AggregateError", () => {
    const run = start();
    const cause = new Error('inner Bearer CANARY-CAUSE-BEARER');
    const failure = new Error('connect https://CANARYERRUSER:CANARYERRPASS@db.example/app?password=CANARY-ERR-QUERY failed', { cause });
    run.log.error({ err: failure }, 'upload failed');
    run.log.error(failure);
    run.log.error(new AggregateError([new Error('agg key sk-CANARYAGGKEYabcdef')], 'many'), 'agg');
    expectNoneEmitted(run, ['CANARYERRUSER', 'CANARYERRPASS', 'CANARY-ERR-QUERY', 'CANARY-CAUSE-BEARER', 'CANARYAGGKEYabcdef']);
    expect(String(lines(run)[1].msg)).toContain('[REDACTED]');
  });

  it('an error under a non-err key, as the pre-serialised shape axios toJSON produces', () => {
    const run = start();
    const axiosShape = {
      message: 'Request failed with status code 401',
      name: 'AxiosError',
      stack: 'AxiosError: failed Bearer CANARY-AXIOS-STACK\n    at settle (node_modules/axios/lib/core/settle.js:19:12)',
      config: {
        url: 'https://api.example.com/v1/me?access_token=CANARY-AXIOS-URLQUERY',
        headers: { Accept: 'application/json', Authorization: 'Bearer CANARY-AXIOS-AUTH', 'X-Api-Key': 'CANARY-AXIOS-APIKEY' },
        data: '{"password":"CANARY-AXIOS-BODY"}',
        auth: { username: 'u', password: 'CANARY-AXIOS-BASICPASS' },
      },
      response: { status: 401, data: { error: 'denied', session: 'CANARY-AXIOS-RESPONSE' } },
    };
    run.log.error({ error: axiosShape }, 'call failed');
    expectNoneEmitted(run, [
      'CANARY-AXIOS-STACK',
      'CANARY-AXIOS-URLQUERY',
      'CANARY-AXIOS-AUTH',
      'CANARY-AXIOS-APIKEY',
      'CANARY-AXIOS-BODY',
      'CANARY-AXIOS-BASICPASS',
      'CANARY-AXIOS-RESPONSE',
    ]);
    const { config } = lines(run)[0].error as { config: { headers: Record<string, unknown>; data: unknown } };
    expect(config.headers).toEqual({ Accept: 'application/json', Authorization: '[REDACTED]', 'X-Api-Key': '[REDACTED]' });
    expect(config.data).toBe('[omitted]');
  });

  it('a URL with userinfo or a query inside a string value, and as an object key', () => {
    const run = start();
    run.log.info(
      {
        target: 'https://CANARYURLUSER:CANARYURLPASS@host.example/path/to?sig=CANARY-URL-SIG&x=1#CANARY-URL-FRAGMENT',
        'https://k.example/?token=CANARY-KEY-IN-NAME': 1,
        url: new URL('https://host.example/a?apikey=CANARY-URL-OBJECT'),
        relative: 'GET /oauth/cb?code=CANARY-RELATIVE-CODE&state=s 302',
      },
      'urls',
    );
    expectNoneEmitted(run, [
      'CANARYURLUSER',
      'CANARYURLPASS',
      'CANARY-URL-SIG',
      'CANARY-URL-FRAGMENT',
      'CANARY-KEY-IN-NAME',
      'CANARY-URL-OBJECT',
      'CANARY-RELATIVE-CODE',
    ]);
    expect(lines(run)[0]).toMatchObject({
      target: 'https://[REDACTED]@host.example/path/to?[REDACTED]',
      url: 'https://host.example/a?[REDACTED]',
    });
  });

  it('a Map value, a Set, and an Error or URL inside one', () => {
    const run = start();
    run.log.info(
      {
        cache: new Map<unknown, unknown>([
          ['password', 'CANARY-MAP-PASSWORD'],
          ['note', 'Bearer CANARY-MAP-BEARER'],
          [{ token: 'CANARY-MAP-OBJECTKEY' }, 'plain'],
          ['failure', new Error('boom sk-CANARYMAPERRabcdef')],
        ]),
        seen: new Set(['Bearer CANARY-SET-BEARER', { secret: 'CANARY-SET-SECRET' }]),
      },
      'maps',
    );
    expectNoneEmitted(run, [
      'CANARY-MAP-PASSWORD',
      'CANARY-MAP-BEARER',
      'CANARY-MAP-OBJECTKEY',
      'CANARYMAPERRabcdef',
      'CANARY-SET-BEARER',
      'CANARY-SET-SECRET',
    ]);
    expect((lines(run)[0].cache as unknown[])[0]).toEqual(['password', '[REDACTED]']);
  });

  it('a Bearer header and a JWT inside free text, in a value and in the message', () => {
    const run = start();
    run.log.info({ detail: `upstream said: Authorization: Bearer CANARY-FREE-BEARER, also saw ${JWT}.` }, `token ${JWT} rejected`);
    run.log.warn(`header was "Bearer CANARY-FREE2-BEARER"`);
    expectNoneEmitted(run, ['CANARY-FREE-BEARER', 'CANARY-FREE2-BEARER', JWT, JWT.split('.')[1]]);
  });

  it('a class instance is shown by name only, a boxed string and a Date are rendered, toJSON is never called', () => {
    class Holder {
      readonly secret = 'CANARY-CLASS-SECRET';
      readonly visible = 'shown';
      toJSON(): unknown {
        throw new Error('toJSON must not be called');
      }
    }
    const run = start();
    run.log.info(
      {
        holder: new Holder(),
        boxed: new String('Bearer CANARY-BOXED'),
        when: new Date('2026-10-02T00:00:00.000Z'),
        bad: new Date(Number.NaN),
        plain: { toJSON: () => ({ secret: 'CANARY-OWN-TOJSON' }), keep: 1 },
      },
      'objects',
    );
    expectNoneEmitted(run, ['CANARY-CLASS-SECRET', 'shown', 'CANARY-BOXED', 'CANARY-OWN-TOJSON']);
    expect(lines(run)[0]).toMatchObject({
      holder: '[Holder]',
      boxed: 'Bearer [REDACTED]',
      when: '2026-10-02T00:00:00.000Z',
      bad: null,
      plain: { keep: 1 },
    });
  });

  it('binary data is never rendered', () => {
    const run = start();
    run.log.info({ buf: Buffer.from('CANARY-BUFFER-TEXT'), u8: new Uint8Array(4), ab: new ArrayBuffer(8), dv: new DataView(new ArrayBuffer(2)) }, 'bin');
    expectNoneEmitted(run, ['CANARY-BUFFER-TEXT', 'Q0FOQVJZ']);
    expect(lines(run)[0]).toMatchObject({
      buf: '[binary 18 bytes]',
      u8: '[binary 4 bytes]',
      ab: '[binary 8 bytes]',
      dv: '[binary 2 bytes]',
    });
  });

  it('a body key beside everything else: omitted, not just redacted', () => {
    const run = start();
    run.log.info({ body: { note: 'CANARY-BODY-FREE-TEXT' }, rawBody: 'CANARY-RAW-BODY', payload: ['CANARY-PAYLOAD'], data: 'CANARY-DATA' }, 'bodies');
    expectNoneEmitted(run, ['CANARY-BODY-FREE-TEXT', 'CANARY-RAW-BODY', 'CANARY-PAYLOAD', 'CANARY-DATA']);
    expect(lines(run)[0]).toMatchObject({ body: '[omitted]', rawBody: '[omitted]', payload: '[omitted]', data: '[omitted]' });
  });

  it('keeps a hostile __proto__ key as data and never writes through to the prototype', () => {
    const run = start();
    run.log.info(JSON.parse('{"__proto__":{"polluted":"CANARY-PROTO","password":"CANARY-PROTO-PASSWORD"}}') as Record<string, unknown>, 'proto');
    expectNoneEmitted(run, ['CANARY-PROTO-PASSWORD']);
    expect(Object.getOwnPropertyDescriptor(lines(run)[0], '__proto__')?.value).toEqual({ polluted: 'CANARY-PROTO', password: '[REDACTED]' });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('must stay visible', () => {
  it('keeps token usage counters, a URL path, ordinary text and the reserved envelope', () => {
    const run = start({ proc: 'worker' });
    run.log.info(
      {
        inputTokens: 12,
        outputTokens: 34,
        cacheReadTokens: 56,
        cache_creation_input_tokens: 78,
        max_tokens: 99,
        total_tokens: 3,
        token_count: 7,
        tokens: 5,
        usage: { inputTokens: 1, outputTokens: 2 },
        path: 'https://api.example.com/v1/items/42',
        note: 'refresh token expired for user 7; tokens=5 inputTokens=12',
        level: 'forged',
      },
      'token refresh finished',
    );
    const [line] = lines(run);
    expect(line).toMatchObject({
      v: 1,
      level: 'info',
      app: 'demo',
      proc: 'worker',
      msg: 'token refresh finished',
      inputTokens: 12,
      outputTokens: 34,
      cacheReadTokens: 56,
      cache_creation_input_tokens: 78,
      max_tokens: 99,
      total_tokens: 3,
      token_count: 7,
      tokens: 5,
      usage: { inputTokens: 1, outputTokens: 2 },
      path: 'https://api.example.com/v1/items/42',
      note: 'refresh token expired for user 7; tokens=5 inputTokens=12',
      ctx: { level: 'forged' },
    });
  });

  it('classifies the token rule exactly', () => {
    const cls = (key: string) => classifyKey(key, DEFAULT_REDACT_POLICY);
    for (const key of ['token', 'Token', 'accessToken', 'refresh_token', 'x-auth-token', 'id_token', 'tokenValue', 'csrfToken', 'token_hash']) {
      expect(cls(key), key).toBe('secret');
    }
    for (const key of ['tokens', 'inputTokens', 'outputTokens', 'cacheReadTokens', 'max_tokens', 'cache_creation_input_tokens', 'token_count', 'tokenCount', 'token-counts']) {
      expect(cls(key), key).toBe('counter');
    }
    for (const key of ['count', 'name', 'user']) expect(cls(key), key).toBe('plain');
  });

  it('redacts a counter-named key when it holds something other than a number', () => {
    const run = start();
    run.log.info({ tokens: 'CANARY-STRING-TOKENS', inputTokens: ['CANARY-ARRAY-TOKENS'], outputTokens: { a: 'CANARY-OBJ-TOKENS' }, cacheReadTokens: 4 }, 'x');
    expectNoneEmitted(run, ['CANARY-STRING-TOKENS', 'CANARY-ARRAY-TOKENS', 'CANARY-OBJ-TOKENS']);
    expect(lines(run)[0]).toMatchObject({ tokens: '[REDACTED]', inputTokens: '[REDACTED]', outputTokens: '[REDACTED]', cacheReadTokens: 4 });
  });

  it('leaves Dates, numbers, booleans, null, bigint and plain arrays as they are', () => {
    const run = start();
    run.log.info({ n: 1.5, b: false, nil: null, big: 10n, list: [1, 'a', null, true], empty: {} }, 'plain');
    expect(lines(run)[0]).toMatchObject({ n: 1.5, b: false, nil: null, big: 10, list: [1, 'a', null, true], empty: {} });
  });
});

describe('bounds', () => {
  it('truncates past depth 8', () => {
    const run = start();
    let deep: Record<string, unknown> = { leaf: 'bottom' };
    for (let i = 0; i < 12; i++) deep = { a: deep };
    run.log.info({ deep }, 'deep');
    // `deep` is depth 1; its 8th nested object is the last one kept.
    let cursor: unknown = lines(run)[0].deep;
    let kept = 0;
    while (typeof cursor === 'object' && cursor !== null) {
      kept++;
      cursor = (cursor as Record<string, unknown>).a;
    }
    expect(kept).toBe(8);
    expect(cursor).toBe('[truncated]');
  });

  it('keeps 200 keys per object and says how many it dropped', () => {
    const run = start();
    const wide = Object.fromEntries(Array.from({ length: 250 }, (_, i) => [`k${i}`, i]));
    run.log.info({ wide }, 'wide');
    const out = lines(run)[0].wide as Record<string, unknown>;
    expect(Object.keys(out)).toHaveLength(201);
    expect(out.k199).toBe(199);
    expect(out).not.toHaveProperty('k200');
    expect(out['[truncated]']).toBe(50);
  });

  it('keeps 100 array items, then [truncated], for arrays, Maps and Sets', () => {
    const run = start();
    const hundredFifty = Array.from({ length: 150 }, (_, i) => i);
    run.log.info(
      {
        arr: hundredFifty,
        set: new Set(hundredFifty),
        map: new Map(hundredFifty.map((i) => [`k${i}`, i] as const)),
        exact: Array.from({ length: 100 }, (_, i) => i),
      },
      'long',
    );
    const out = lines(run)[0] as Record<string, unknown[]>;
    expect(out.arr).toHaveLength(101);
    expect(out.arr.at(-1)).toBe('[truncated]');
    expect(out.arr[99]).toBe(99);
    expect(out.set).toHaveLength(101);
    expect(out.set.at(-1)).toBe('[truncated]');
    expect(out.map).toHaveLength(101);
    expect(out.map.at(-1)).toBe('[truncated]');
    expect(out.exact).toHaveLength(100);
  });

  it('turns a cycle into [circular], through objects, arrays and Maps', () => {
    const run = start();
    const loop: Record<string, unknown> = { name: 'loop' };
    loop.self = loop;
    const list: unknown[] = [];
    list.push(list);
    const map = new Map<string, unknown>();
    map.set('me', map);
    run.log.info({ loop, list, map }, 'cycles');
    expect(lines(run)[0]).toMatchObject({ loop: { name: 'loop', self: '[circular]' }, list: ['[circular]'], map: [['me', '[circular]']] });
  });

  it('does not call a throwing getter twice and renders it [unreadable]', () => {
    const run = start();
    let reads = 0;
    const instance = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(instance, 'boom', {
      enumerable: true,
      get() {
        reads++;
        throw new Error('getter exploded CANARY-GETTER');
      },
    });
    const plain = {
      get boom(): string {
        throw new Error('plain getter exploded CANARY-GETTER');
      },
      ok: 1,
    };
    run.log.info({ instance, plain, list: new Proxy([1], { get() { throw new Error('trap CANARY-GETTER'); } }) }, 'getters');
    expectNoneEmitted(run, ['CANARY-GETTER']);
    expect(reads).toBe(1);
    expect(lines(run)[0]).toMatchObject({ instance: { boom: '[unreadable]' }, plain: { boom: '[unreadable]', ok: 1 } });
  });

  it('drops functions and symbols from objects and arrays', () => {
    const run = start();
    run.log.info({ f: () => 'x', s: Symbol('s'), keep: 1, list: [() => 1, Symbol('t'), 2] }, 'drops');
    const [line] = lines(run);
    expect(line).not.toHaveProperty('f');
    expect(line).not.toHaveProperty('s');
    expect(line).toMatchObject({ keep: 1, list: [2] });
  });

  it('survives an object whose key listing throws', () => {
    const run = start();
    const hostile = new Proxy({}, { ownKeys() { throw new Error('no keys CANARY-OWNKEYS'); } });
    run.log.info({ hostile }, 'hostile');
    expectNoneEmitted(run, ['CANARY-OWNKEYS']);
    expect(lines(run)[0].hostile).toBe('[unreadable]');
  });

  it('sanitize returns a fresh tree and never the caller object', () => {
    const input = { a: { b: 1 }, list: [1] };
    const output = sanitize(input);
    expect(output).toEqual(input);
    expect(output).not.toBe(input);
    expect(output.a).not.toBe(input.a);
    expect(output.list).not.toBe(input.list);
  });
});

describe('interpolation', () => {
  it('has no operand parameter in the types, so a %s in msg stays literal', () => {
    const run = start();
    // @ts-expect-error extra arguments are not part of the API
    run.log.info('login for %s', 'CANARY-OPERAND');
    run.log.info({ a: 1 }, 'progress 100%s %d %o %j');
    run.log.info('literal %s %d %o %j');
    expectNoneEmitted(run, ['CANARY-OPERAND']);
    expect(lines(run).map((line) => line.msg)).toEqual(['login for %s', 'progress 100%s %d %o %j', 'literal %s %d %o %j']);
  });

  it('drops operands a JS caller passes anyway, for every call shape', () => {
    const run = start();
    const loose = (fn: unknown): ((...args: unknown[]) => void) => fn as (...args: unknown[]) => void;
    loose(run.log.info)('x %s', 'CANARY-OP1');
    loose(run.log.info)({ a: 1 }, 'x %s %o', 'CANARY-OP2', { token: 'CANARY-OP3' });
    loose(run.log.error)(new Error('e'), 'x %j', { password: 'CANARY-OP4' });
    expectNoneEmitted(run, ['CANARY-OP1', 'CANARY-OP2', 'CANARY-OP3', 'CANARY-OP4']);
  });

  it('sanitises the final msg, including one pino derives from the error', () => {
    const run = start();
    run.log.error(new Error('derived Bearer CANARY-DERIVED-MSG'));
    expectNoneEmitted(run, ['CANARY-DERIVED-MSG']);
    expect(String(lines(run)[0].msg)).toBe('derived Bearer [REDACTED]');
  });
});

describe('createLogger({ redact }) can only extend the policy', () => {
  it('redacts an extra key, case-insensitively, beside the built-ins', () => {
    const run = start({ redact: { keys: ['ssn', 'card-number'] } });
    run.log.info({ SSN: 'CANARY-SSN', card_number: 'CANARY-CARD', user: { cardNumber: 'CANARY-CARD2' }, password: 'CANARY-STILL-PASSWORD', authorization: 'CANARY-STILL-AUTH' }, 'x');
    expectNoneEmitted(run, ['CANARY-SSN', 'CANARY-CARD', 'CANARY-CARD2', 'CANARY-STILL-PASSWORD', 'CANARY-STILL-AUTH']);
  });

  it('matches an extra key whole, not as a substring', () => {
    const run = start({ redact: { keys: ['ssn'] } });
    run.log.info({ ssnLast4: '1234', classname: 'kept' }, 'x');
    expect(lines(run)[0]).toMatchObject({ ssnLast4: '1234', classname: 'kept' });
  });

  it('applies to child bindings of a logger built with it', () => {
    const run = start({ redact: { keys: ['ssn'] } });
    run.log.child({ ssn: 'CANARY-CHILD-SSN' }).info('x');
    expectNoneEmitted(run, ['CANARY-CHILD-SSN']);
  });

  it('cannot be used to un-redact: no option removes a built-in, and an allowed path cannot expose a credential key', () => {
    const run = start({ redact: { keys: [], allowPaths: ['data.password', 'data.nested.token', 'password'] } });
    run.log.info({ data: { password: 'CANARY-ALLOWED-PASSWORD', nested: { token: 'CANARY-ALLOWED-TOKEN' } }, password: 'CANARY-ROOT-ALLOWED' }, 'x');
    expectNoneEmitted(run, ['CANARY-ALLOWED-PASSWORD', 'CANARY-ALLOWED-TOKEN', 'CANARY-ROOT-ALLOWED']);
  });

  it.each([
    ['keys', { keys: 'ssn' }],
    ['keys', { keys: [''] }],
    ['keys', { keys: [1] }],
    ['keys', { keys: ['-_ '] }],
    ['allowPaths', { allowPaths: [''] }],
    ['allowPaths', { allowPaths: ['a..b'] }],
    ['allowPaths', { allowPaths: ['.a'] }],
    ['allowPaths', { allowPaths: [['a']] }],
  ] as const)('rejects a malformed redact.%s', (_name, redact) => {
    expect(() => createLoggerWithStream({ app: 'demo', redact: redact as never }, captureStream())).toThrow(LogConfigError);
  });
});

describe('bodies', () => {
  it.each(['body', 'Body', 'payload', 'PAYLOAD', 'data', 'rawBody', 'raw_body', 'raw-body'])('omits the value under %s by default', (key) => {
    const run = start();
    run.log.info({ [key]: { order: { id: 7 } } }, 'x');
    expect(lines(run)[0][key]).toBe('[omitted]');
  });

  it('omits a body nested anywhere, and one inside an array', () => {
    const run = start();
    run.log.info({ req: { body: { id: 1 } }, items: [{ data: 'x', id: 2 }] }, 'x');
    expect(lines(run)[0]).toMatchObject({ req: { body: '[omitted]' }, items: [{ data: '[omitted]', id: 2 }] });
  });

  it('allows exactly the listed dotted paths, from the root of the logged fields', () => {
    const run = start({ redact: { allowPaths: ['data.order.id', 'req.body.kind'] } });
    run.log.info(
      {
        data: { order: { id: 5, note: 'CANARY-BODY-NOTE', items: ['CANARY-BODY-ITEM'] }, other: 'CANARY-BODY-OTHER' },
        req: { body: { kind: 'create', extra: 'CANARY-BODY-EXTRA' } },
        payload: { order: { id: 9 } },
      },
      'x',
    );
    expectNoneEmitted(run, ['CANARY-BODY-NOTE', 'CANARY-BODY-ITEM', 'CANARY-BODY-OTHER', 'CANARY-BODY-EXTRA']);
    expect(lines(run)[0]).toEqual(
      expect.objectContaining({
        data: { order: { id: 5, note: '[omitted]', items: '[omitted]' }, other: '[omitted]' },
        req: { body: { kind: 'create', extra: '[omitted]' } },
        payload: '[omitted]',
      }),
    );
  });

  it('treats arrays as transparent in a path, and omits bare items inside a body', () => {
    const run = start({ redact: { allowPaths: ['data.items.id'] } });
    run.log.info({ data: { items: [{ id: 1, name: 'CANARY-ITEM-NAME' }, 'CANARY-ITEM-BARE'] } }, 'x');
    expectNoneEmitted(run, ['CANARY-ITEM-NAME', 'CANARY-ITEM-BARE']);
    expect(lines(run)[0].data).toEqual({ items: [{ id: 1, name: '[omitted]' }, '[omitted]'] });
  });

  it('lets an allowed path expose a whole subtree, still redacted by key and string policy', () => {
    const run = start({ redact: { allowPaths: ['data'] } });
    run.log.info({ data: { id: 1, password: 'CANARY-SUBTREE-PASSWORD', link: 'https://h.example/p?token=CANARY-SUBTREE-QUERY', body: 'CANARY-SUBTREE-INNERBODY' } }, 'x');
    expectNoneEmitted(run, ['CANARY-SUBTREE-PASSWORD', 'CANARY-SUBTREE-QUERY']);
    expect(lines(run)[0].data).toMatchObject({ id: 1, password: '[REDACTED]', link: 'https://h.example/p?[REDACTED]' });
  });

  it('does not let an allowed path through a class instance in a body', () => {
    class Opaque {
      readonly id = 'CANARY-INSTANCE-ID';
    }
    const run = start({ redact: { allowPaths: ['data.opaque.id'] } });
    run.log.info({ data: { opaque: new Opaque() } }, 'x');
    expectNoneEmitted(run, ['CANARY-INSTANCE-ID']);
  });

  it('applies to child bindings, with the path rooted at the bindings object', () => {
    const run = start({ redact: { allowPaths: ['data.id'] } });
    run.log.child({ data: { id: 3, name: 'CANARY-BINDING-NAME' } }).info('x');
    expectNoneEmitted(run, ['CANARY-BINDING-NAME']);
    expect(lines(run)[0].data).toEqual({ id: 3, name: '[omitted]' });
  });
});

describe('the line schema', () => {
  it('accepts every line the logger emits with redaction active, markers included', () => {
    const run = start({ redact: { allowPaths: ['data.id'] } });
    const loop: Record<string, unknown> = {};
    loop.self = loop;
    run.log.info({ password: 'x', body: 'y', data: { id: 1, v: 2 }, loop, big: Array.from({ length: 300 }, (_, i) => i) }, 'a');
    run.log.error({ err: new Error('Bearer abc') }, 'b');
    run.log.child({ token: 'z' }).warn('c');
    expect(lines(run)).toHaveLength(3);
  });
});

describe('review findings: class instances and header lists', () => {
  it('shows an http.IncomingMessage by name and never its raw headers', () => {
    const req = new IncomingMessage(new Socket());
    req.rawHeaders = ['Host', 'h.example', 'X-Api-Key', 'CANARY-REQ-KEY', 'Cookie', 'sid=CANARY-REQ-SID', 'Authorization', 'Basic dXNlcjpwYXNz'];
    req.headers = { 'x-api-key': 'CANARY-REQ-KEY', authorization: 'Basic dXNlcjpwYXNz' };
    req.url = '/cb?code=CANARY-REQ-CODE';
    const run = start();
    run.log.info({ req }, 'incoming');
    run.log.child({ req }).info('child');
    expectNoneEmitted(run, ['CANARY-REQ-KEY', 'CANARY-REQ-SID', 'dXNlcjpwYXNz', 'CANARY-REQ-CODE', 'h.example']);
    expect(lines(run)[0].req).toBe('[IncomingMessage]');
  });

  it('shows any class instance, Promise or Headers-like object by name only', () => {
    class Session {
      readonly id = 'CANARY-INSTANCE-ID';
    }
    const run = start();
    run.log.info({ owner: new Session(), p: Promise.resolve('CANARY-PROMISE'), list: [new Session()], map: new Map([['k', new Session()]]) }, 'instances');
    expectNoneEmitted(run, ['CANARY-INSTANCE-ID', 'CANARY-PROMISE']);
    expect(lines(run)[0]).toMatchObject({ owner: '[Session]', p: '[Promise]', list: ['[Session]'], map: [['k', '[Session]']] });
  });

  it('keeps walking plain objects, null-prototype objects and arrays', () => {
    const run = start();
    const bare = Object.assign(Object.create(null) as Record<string, unknown>, { a: 1 });
    run.log.info({ bare, nested: { list: [{ ok: true }] } }, 'plain');
    expect(lines(run)[0]).toMatchObject({ bare: { a: 1 }, nested: { list: [{ ok: true }] } });
  });

  it('redacts the value after a credential name in header pair arrays, flat raw header lists and Maps', () => {
    const run = start();
    run.log.info(
      {
        pairs: [['x-api-key', 'CANARY-PAIR-KEY'], ['Accept', 'json'], ['Set-Cookie', 'sid=CANARY-PAIR-COOKIE']],
        rawHeaders: ['Host', 'h.example', 'X-Api-Key', 'CANARY-FLAT-KEY', 'Cookie', 'sid=CANARY-FLAT-SID', 'Authorization', 'Basic CANARY-FLAT-AUTH', 'Accept', 'json'],
        headers: new Map([['proxy-authorization', 'CANARY-MAP-PROXY']]),
      },
      'headers',
    );
    expectNoneEmitted(run, ['CANARY-PAIR-KEY', 'CANARY-PAIR-COOKIE', 'CANARY-FLAT-KEY', 'CANARY-FLAT-SID', 'CANARY-FLAT-AUTH', 'CANARY-MAP-PROXY']);
    const [line] = lines(run);
    expect(line.pairs).toEqual([['x-api-key', '[REDACTED]'], ['Accept', 'json'], ['Set-Cookie', '[REDACTED]']]);
    expect(line.rawHeaders).toEqual(['Host', 'h.example', 'X-Api-Key', '[REDACTED]', 'Cookie', '[REDACTED]', 'Authorization', '[REDACTED]', 'Accept', 'json']);
  });

  it('leaves ordinary string arrays and pairs alone', () => {
    const run = start();
    run.log.info({ words: ['alpha', 'beta', 'gamma'], pairs: [['a', 'b'], ['c', 'd']], flat: ['a', 'b', 'c', 'd'] }, 'plain lists');
    expect(lines(run)[0]).toMatchObject({ words: ['alpha', 'beta', 'gamma'], pairs: [['a', 'b'], ['c', 'd']], flat: ['a', 'b', 'c', 'd'] });
  });
});

describe('review findings: strings through the logger', () => {
  it('escaped quotes, environment-style names, multi-word values and webhook paths never reach the bytes', () => {
    const run = start();
    run.log.info('body {"password":"ab\\"CANARY-ESC1"} and password="x\\"CANARY-ESC2"');
    run.log.error(new Error('bad {"password":"ab\\"CANARY-ESC3"}'), 'failed');
    run.log.info({ detail: JSON.stringify({ password: 'x"CANARY-ESC4' }) }, 'stringified');
    run.log.child({ note: 'password="a\\"CANARY-ESC5"' }).info('child');
    run.log.info({ error: { message: 'password="a\\"CANARY-ESC6"', stack: 'at x password="b\\"CANARY-ESC7"' } }, 'shape');
    run.log.info('env AWS_SECRET_ACCESS_KEY=CANARY-AWS secret_key=CANARY-SK sessionId=CANARY-SID passwordConfirm=CANARY-PC');
    run.log.info('X-Session-Id: CANARY-HDR\npassword: correct horse CANARY-BATTERY');
    run.log.info({ hook: 'POST https://discord.com/api/webhooks/123456/CANARY-DISCORD', slack: 'https://hooks.slack.com/services/T000/B000/CANARY-SLACK', tg: 'https://api.telegram.org/bot123:CANARY-TG/getMe' }, 'hooks');
    expectNoneEmitted(run, [
      ...Array.from({ length: 7 }, (_, i) => `CANARY-ESC${i + 1}`),
      'CANARY-AWS',
      'CANARY-SK',
      'CANARY-SID',
      'CANARY-PC',
      'CANARY-HDR',
      'CANARY-BATTERY',
      'CANARY-DISCORD',
      'CANARY-SLACK',
      'CANARY-TG',
    ]);
  });

  it('Basic and Bearer credentials of any shape, new key prefixes and PEM blocks', () => {
    const run = start();
    run.log.info(
      'a Basic dXNlcjpwYXNz b Basic dTpw c Bearer token-CANARY-BT d AIzaCANARY-GKEYxxxxxxxxxxxxxxxxxxxx e npm_CANARYNPM1 f hf_CANARYHF123 g glpat-CANARY-GL h whsec_CANARY-WH',
    );
    run.log.info({ pem: '-----BEGIN PRIVATE KEY-----\nCANARY-PEM\n-----END PRIVATE KEY-----', cut: '-----BEGIN RSA PRIVATE KEY-----\nCANARY-PEMCUT' }, 'pem');
    expectNoneEmitted(run, ['dXNlcjpwYXNz', 'dTpw', 'CANARY-BT', 'CANARY-GKEY', 'CANARYNPM1', 'CANARYHF123', 'CANARY-GL', 'CANARY-WH', 'CANARY-PEM']);
  });

  it('keeps counters and prose readable after the wider name rule', () => {
    const run = start();
    run.log.info('tokens=5 inputTokens=12 max_tokens=100 token_count=3 author=bob Basic authentication ok');
    expect(lines(run)[0].msg).toBe('tokens=5 inputTokens=12 max_tokens=100 token_count=3 author=bob Basic authentication ok');
  });
});

describe('review findings: keys', () => {
  it.each([
    ['dotless I', 'authorİzation'],
    ['long s', 'paſſword'],
    ['zero-width space', 'pass​word'],
    ['zero-width joiner', 'access‍token'],
    ['soft hyphen', 'pass­word'],
    ['fullwidth', 'ｐａｓｓｗｏｒｄ'],
    ['Kelvin sign', 'apiKey'],
    ['dot separated', 'api.key'],
    ['colon separated', 'x:api:key'],
    ['padded with spaces', ' Authorization '],
    ['four layers of percent-encoding', '%25252541uthorization'],
    ['one bad escape beside valid ones', '%FF%70%61%73%73%77%6F%72%64'],
    ['an escape that is not valid UTF-8', 'name%FF'],
    ['pass', 'pass'],
    ['pwd', 'PWD'],
    ['auth', 'auth'],
    ['oauth', 'oauth'],
    ['x-auth', 'X-Auth'],
  ])('redacts the value under %s', (_name, key) => {
    const run = start();
    run.log.info({ [key]: 'CANARY-KEY-VALUE' }, 'x');
    expectNoneEmitted(run, ['CANARY-KEY-VALUE']);
  });

  it.each(['author', 'authored', 'authenticated', 'authority', 'compass', 'passage'])(
    'does not redact %s',
    (key) => {
      const run = start();
      run.log.info({ [key]: 'visible-value' }, 'x');
      expect(lines(run)[0][key]).toBe('visible-value');
    },
  );

  it('redacts Nodemailer-style auth, and an allowed body path cannot expose these keys', () => {
    const run = start({ redact: { allowPaths: ['data'] } });
    run.log.info({ auth: { user: 'u', pass: 'CANARY-NM' }, data: { pwd: 'CANARY-PWD', 'pa​ss': 'ok', 'pass​word': 'CANARY-ZW' } }, 'x');
    expectNoneEmitted(run, ['CANARY-NM', 'CANARY-PWD', 'CANARY-ZW']);
  });
});

describe('review findings: bodies, Maps and Errors', () => {
  it('omits a non-plain value inside an allowed body path: boxed string, Error in a Set, Date, Map', () => {
    const run = start({ redact: { allowPaths: ['data.items.id'] } });
    run.log.info(
      {
        data: { items: [new String('CANARY-BOXED-ITEM'), new Set([new Error('CANARY-SET-ERR')]), new Date(0), new Map([['k', 'CANARY-MAP-IN-BODY']]), { id: 1 }] },
      },
      'x',
    );
    expectNoneEmitted(run, ['CANARY-BOXED-ITEM', 'CANARY-SET-ERR', 'CANARY-MAP-IN-BODY', '1970-01-01']);
    expect((lines(run)[0].data as { items: unknown[] }).items).toEqual(['[omitted]', '[omitted]', '[omitted]', '[omitted]', { id: 1 }]);
  });

  it('applies redact.keys to an Error found inside a Map or Set, as it does to a direct one', () => {
    const failure = Object.assign(new Error('CANARY-ERR-MESSAGE'), { code: 'CANARY-ERR-CODE' });
    failure.name = 'CANARY-ERR-NAME';
    failure.stack = 'CANARY-ERR-STACK';
    const run = start({ redact: { keys: ['message', 'stack', 'type', 'code'] } });
    run.log.info({ map: new Map([['e', failure]]), set: new Set([failure]), direct: { e: failure } }, 'x');
    expectNoneEmitted(run, ['CANARY-ERR-MESSAGE', 'CANARY-ERR-CODE', 'CANARY-ERR-NAME', 'CANARY-ERR-STACK']);
  });

  it('classifies a boxed Map key like the string it holds', () => {
    const run = start();
    run.log.info({ map: new Map<unknown, unknown>([[new String('password'), 'CANARY-BOXED-KEY'], [new String('body'), 'CANARY-BOXED-BODY']]) }, 'x');
    expectNoneEmitted(run, ['CANARY-BOXED-KEY', 'CANARY-BOXED-BODY']);
    expect(lines(run)[0].map).toEqual([['password', '[REDACTED]'], ['body', '[omitted]']]);
  });
});

describe('review findings: bounds', () => {
  it('cuts a 50 MB string value, ending in the truncation marker, and does not scan all of it', () => {
    const run = start();
    const started = performance.now();
    run.log.info({ big: 'x'.repeat(50 * 1024 * 1024), withSecret: `${'y'.repeat(40_000)} Bearer CANARY-BIG-TAIL` }, 'z'.repeat(1024 * 1024));
    expect(performance.now() - started).toBeLessThan(1000);
    expect(run.out.raw.length).toBeLessThan(80_000);
    expectNoneEmitted(run, ['CANARY-BIG-TAIL']);
    const [line] = lines(run);
    expect(String(line.big).endsWith('…[truncated]')).toBe(true);
    expect(String(line.big).length).toBeLessThanOrEqual(16 * 1024);
    expect(String(line.msg).length).toBeLessThanOrEqual(16 * 1024);
  });

  it('does not cut a short secret in half at the cut', () => {
    const run = start();
    // Redaction shrinks the long query to a marker, so the characters just before the 32 KB read limit reach the output.
    const prefix = `https://h.example/?${'a'.repeat(32_761 - 19 - 1)} `;
    expect(prefix.length).toBe(32_761);
    run.log.info({ v: `${prefix}sk-CANARYCUTKEY1234567890` }, 'x');
    expectNoneEmitted(run, ['sk-C', 'CANARYCUTKEY']);
  });

  it('never traverses an omitted body: no getter on it runs', () => {
    let reads = 0;
    const items = Array.from({ length: 1000 }, () => ({
      get v(): number {
        reads++;
        return 1;
      },
    }));
    const run = start();
    run.log.info({ body: items }, 'x');
    expect(reads).toBe(0);
    expect(lines(run)[0].body).toBe('[omitted]');
  });

  it('counts dropped items as visited: 300 functions then a value ends in [truncated]', () => {
    const run = start();
    const functions = Array.from({ length: 300 }, (_, i) => () => i);
    run.log.info({ set: new Set<unknown>([...functions, 'CANARY-AFTER-FUNCTIONS']), list: [...functions, 'CANARY-AFTER-LIST'] }, 'x');
    expectNoneEmitted(run, ['CANARY-AFTER-FUNCTIONS', 'CANARY-AFTER-LIST']);
    expect(lines(run)[0]).toMatchObject({ set: ['[truncated]'], list: ['[truncated]'] });
  });

  it('truncates a primitive at depth 9 too', () => {
    const run = start();
    let deep: unknown = 'CANARY-DEEP-LEAF';
    for (let i = 0; i < 9; i++) deep = { a: deep };
    run.log.info(deep as Record<string, unknown>, 'x');
    expectNoneEmitted(run, ['CANARY-DEEP-LEAF']);
  });

  it('bounds a sparse 50-million-item array and a million-key object without walking them', () => {
    const run = start();
    const sparse: unknown[] = [];
    sparse.length = 50_000_000;
    const wide: Record<string, number> = {};
    for (let i = 0; i < 300_000; i++) wide[`k${i}`] = i;
    const started = performance.now();
    run.log.info({ sparse, wide }, 'x');
    expect(performance.now() - started).toBeLessThan(1500);
    const [line] = lines(run);
    expect((line.sparse as unknown[]).length).toBeLessThanOrEqual(101);
    expect(Object.keys(line.wide as object)).toHaveLength(201);
  });
});

describe('review findings: reserved keys', () => {
  it('keeps a __proto__ key from JSON.parse as data when it relocates a reserved key', () => {
    const run = start();
    run.log.info(JSON.parse('{"msg":"m","__proto__":{"ctx":{"injected":"CANARY-PROTO-CTX"}}}') as Record<string, unknown>, 'real');
    const [line] = lines(run);
    expect(line.ctx).toEqual({ msg: 'm' });
    expect(Object.getOwnPropertyDescriptor(line, '__proto__')?.value).toEqual({ ctx: { injected: 'CANARY-PROTO-CTX' } });
    expect(({} as Record<string, unknown>).ctx).toBeUndefined();
  });
});

describe('re-review findings', () => {
  class Session {
    readonly id = 'CANARY-SESSID';
    readonly inner = { token: 'CANARY-INNER' };
  }
  const asFields = (value: object): Record<string, unknown> => value as unknown as Record<string, unknown>;

  it('shows a class instance given as the whole fields object, or as child bindings, by name only', () => {
    const run = start();
    run.log.info(asFields(new Session()), 'top level');
    run.log.child(asFields(new Session())).info('child');
    run.log.error(asFields(Object.assign(new Error('x'), { config: { headers: { Authorization: 'CANARY-ERR-AUTH' } } })), 'err as fields');
    expectNoneEmitted(run, ['CANARY-SESSID', 'CANARY-INNER', 'CANARY-ERR-AUTH']);
    const [first, second] = lines(run);
    expect(first.fields).toBe('[Session]');
    expect(second.bindings).toBe('[Session]');
  });

  it('keeps the S2 call forms: a bare Error, and a plain fields object', () => {
    const run = start();
    run.log.error(new Error('boom CANARY-BARE Bearer abcdef'));
    run.log.info({ a: 1 }, 'plain');
    expectNoneEmitted(run, ['abcdef']);
    expect(lines(run)[1]).toMatchObject({ a: 1, msg: 'plain' });
  });

  it('never emits a URL password when the read-limit cut falls inside the URL', () => {
    const secret = `CANARY${'A'.repeat(70)}`;
    const tail = `https://u:${secret}@host`;
    // The long query shrinks to a marker, which pulls the password inside the output window; the cut falls before `@host`.
    const message = `${'https://h/?'.padEnd(4000 - tail.indexOf('@') - 1, 'x')} ${tail}`;
    const failure = new Error(message);
    failure.stack = '';
    const run = start();
    run.log.error(failure);
    run.log.info({ v: `${'https://h/?'}${'q'.repeat(17_000)} ${'z '.repeat((32_768 - 17_012 - tail.indexOf('@') - 2) / 2)}${tail}` }, 'field');
    expectNoneEmitted(run, [secret.slice(0, 20), 'https://u:']);
  });

  it('never emits half a JWT when the cut falls inside it', () => {
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${'eyJzdWIiOiJ1c2VyIn0'.repeat(10)}.SIGCANARY`;
    const run = start();
    run.log.info({ v: `https://h/p?${'q'.repeat(17_000)} ${'y'.repeat(32 * 1024 - 17_013 - 21 - 100 - 1)} ${jwt}${'x '.repeat(4000)}` }, 'x');
    expectNoneEmitted(run, ['SIGCANARY', 'eyJhbGciOiJIUzI1NiJ9.eyJ']);
  });

  it.each(['credential', 'userCredential', 'authHeader', 'authKey', 'authCode', 'authValue', 'smtpPass', 'dbPwd', 'DB_PWD', 'user_pass', 'encryptionKey', 'signingKey', 'masterKey'])(
    'redacts the value under the credential name %s',
    (key) => {
      const run = start();
      run.log.info({ [key]: 'CANARY-NAME-VALUE' }, 'x');
      expectNoneEmitted(run, ['CANARY-NAME-VALUE']);
    },
  );

  it.each(['author', 'authored', 'passed', 'bypass', 'compass', 'passage', 'inputTokens', 'max_tokens'])('still shows %s', (key) => {
    const run = start();
    run.log.info({ [key]: 7 }, 'x');
    expect(lines(run)[0][key]).toBe(7);
  });

  it('redacts credential names and values in free text: pass, pwd, oauth and token names that start like tokens', () => {
    const run = start();
    run.log.info('SMTP_PASS=CANARY-S1 DB_PWD=CANARY-S2\nOAUTH=CANARY-S3\ntokenString=CANARY-S4\ntokenSigningKey=CANARY-S5\nsmtpPass=CANARY-S6');
    expectNoneEmitted(run, ['CANARY-S1', 'CANARY-S2', 'CANARY-S3', 'CANARY-S4', 'CANARY-S5', 'CANARY-S6']);
  });

  it.each([
    ['odd length', ['X-Api-Key', 'CANARY-ODD', 'Host']],
    ['a dangling name', ['Host', 'x', 'Cookie']],
    ['misaligned', ['Host', 'X-Api-Key', 'CANARY-MIS', 'x']],
    ['mixed types', ['X-Api-Key', 'CANARY-MIX', 1, 2]],
    ['a three-item pair', [['x-api-key', 'CANARY-TUPLE', 'x']]],
  ])('redacts the value after a credential name in a list: %s', (_name, list) => {
    const run = start();
    run.log.info({ h: list, s: new Set([['x-api-key', 'CANARY-SET']]) }, 'x');
    expectNoneEmitted(run, ['CANARY-ODD', 'CANARY-MIS', 'CANARY-MIX', 'CANARY-TUPLE', 'CANARY-SET']);
  });

  it('documents the over-redaction: a word after a credential name in an ordinary list is redacted too', () => {
    const run = start();
    run.log.info({ missing: ['password', 'email'], fine: ['alpha', 'beta'] }, 'x');
    expect(lines(run)[0]).toMatchObject({ missing: ['password', '[REDACTED]'], fine: ['alpha', 'beta'] });
  });

  it.each([
    ['a full-width percent sign', '％７０assword'],
    ['an invisible character inside an escape', '%​70assword'],
    ['a Hangul filler', 'passㅤword'],
    ['a braille blank', 'pass⠀word'],
    ['a combining grapheme joiner', 'pa​ss͏word'],
    ['an escape that only appears after folding, nested', '％２５７０assword'],
  ])('redacts a key spelled with %s', (_name, key) => {
    const run = start();
    run.log.info({ [key]: 'CANARY-FOLD' }, 'x');
    expectNoneEmitted(run, ['CANARY-FOLD']);
  });

  it('redacts every Basic value of 8 or more characters, with or without a colon, and survives 64 decoys', () => {
    const run = start();
    const noColon = Buffer.from('CANARY-KEY-NO-COLON').toString('base64');
    const withColon = Buffer.from('user:CANARY-PW').toString('base64');
    run.log.info(`Authz Basic ${noColon} and ${'Basic aaaa '.repeat(64)}Basic ${withColon}`);
    expectNoneEmitted(run, [noColon, withColon]);
  });
});
