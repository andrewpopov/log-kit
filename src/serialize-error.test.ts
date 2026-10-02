import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import { describe, expect, it } from 'vitest';
import { createLoggerWithStream } from './logger';
import { TRUNCATION_MARKER, serializeError } from './serialize-error';
import { captureStream } from './test-support';

const CANARY = 'canary-s3cr3t-7f3a9c';
const ALLOWED_KEYS = ['type', 'message', 'stack', 'code', 'status', 'cause', 'errors', 'errors_truncated'];

const schema = JSON.parse(readFileSync(join(__dirname, '..', 'schema', 'log-line.json'), 'utf8'));
const validate = new Ajv2020({ strict: true }).compile(schema);

type Loose = Error & Record<string, unknown>;

class AxiosError extends Error {}

/** An axios error as it exists at runtime: the secret sits in config, request and response, including the cycles. */
function axiosShaped(message = 'Request failed with status code 401'): Loose {
  const err = new AxiosError(message) as Loose;
  err.name = 'AxiosError';
  err.code = 'ERR_BAD_REQUEST';
  err.status = 401;
  const config = { headers: { Authorization: `Bearer ${CANARY}` }, data: `grant=${CANARY}` };
  const response: Record<string, unknown> = {
    status: 401,
    data: { token: CANARY },
    headers: { 'set-cookie': `sid=${CANARY}` },
    config,
  };
  const request = { _header: `GET /me HTTP/1.1\r\nAuthorization: Bearer ${CANARY}\r\n`, res: response };
  response.request = request;
  err.config = config;
  err.request = request;
  err.response = response;
  err.toJSON = () => ({ secret: CANARY });
  return err;
}

/** What `axiosError.toJSON()` or a JSON round trip hands you: a plain object, no Error in sight. */
function preSerialised(): Record<string, unknown> {
  const err = axiosShaped();
  return {
    message: err.message,
    name: 'AxiosError',
    stack: err.stack,
    code: err.code,
    status: err.status,
    config: err.config,
    request: err.request,
    response: err.response,
  };
}

/** The acyclic part of the error, after JSON: roughly what lands in a queue or a database row. */
function jsonRoundTrip(): unknown {
  const err = axiosShaped();
  const { config, response } = err as unknown as { config: unknown; response: { status: number; data: unknown; headers: unknown } };
  const { status, data, headers } = response;
  return JSON.parse(JSON.stringify({ message: err.message, name: err.name, stack: err.stack, code: err.code, config, response: { status, data, headers } }));
}

function withCause(cause: unknown, message = 'outer'): Error {
  return Object.assign(new Error(message), { cause });
}

function aggregate(errors: unknown[], message = 'many failed'): Error {
  return new AggregateError(errors, message);
}

function chain(length: number): Error {
  let current = new Error(`level ${length}`);
  for (let i = length - 1; i >= 1; i--) current = withCause(current, `level ${i}`);
  return current;
}

function causeDepth(node: unknown): number {
  let depth = 0;
  for (let cur = node as { cause?: unknown } | string | undefined; typeof cur === 'object'; cur = cur.cause as never) depth++;
  return depth;
}

/** Calls `log.error` with arguments of any shape, including ones the types would refuse. */
function logged(...args: unknown[]) {
  const out = captureStream();
  (createLoggerWithStream({ app: 'demo' }, out).error as (...a: unknown[]) => void)(...args);
  return out;
}

describe('serializeError allowlist', () => {
  it('keeps type, message, stack, code and status of a real error', () => {
    const out = serializeError(Object.assign(new RangeError('bad'), { code: 'E_RANGE', statusCode: 422 }));
    expect(out).toEqual({
      type: 'RangeError',
      message: 'bad',
      stack: expect.stringContaining('bad'),
      code: 'E_RANGE',
      status: 422,
    });
  });

  it.each([
    ['a real Error with axios props assigned', () => axiosShaped()],
    ['a pre-serialised plain object', () => preSerialised()],
    ['a JSON round trip of the error', jsonRoundTrip],
    ['an error nested in a cause', () => withCause(axiosShaped())],
    ['an error nested in a cause of a plain object', () => withCause(preSerialised())],
    ['an error inside an AggregateError', () => aggregate([axiosShaped(), preSerialised()])],
  ])('never emits the canary for %s', (_label, make) => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).error({ err: make() }, 'failed');
    expect(out.raw).not.toContain(CANARY);
    expect(out.raw).not.toMatch(/Authorization|set-cookie|_header|"config"|"response"|"request"/);
    const err = out.lines[0].err as Record<string, unknown>;
    expect(Object.keys(err).filter((key) => !ALLOWED_KEYS.includes(key))).toEqual([]);
  });

  it('drops every non-allowlisted own and enumerable property by construction', () => {
    const err = Object.assign(new Error('x'), {
      config: 1,
      request: 2,
      response: 3,
      headers: 4,
      body: 5,
      data: 6,
      extra: 7,
      statusText: 'no',
    });
    Object.defineProperty(err, 'hidden', { value: CANARY, enumerable: false });
    expect(Object.keys(serializeError(err))).toEqual(['type', 'message', 'stack']);
    expect(Object.keys(serializeError({ message: 'x', headers: {}, body: 1, ...{ data: 2 } }))).toEqual(['type', 'message']);
  });

  it('never calls a user toJSON, on the error or anywhere in the tree', () => {
    let calls = 0;
    const toJSON = () => {
      calls++;
      return { secret: CANARY };
    };
    const inner = Object.assign(new Error('inner'), { toJSON });
    const out = serializeError(Object.assign(new Error('outer'), { toJSON, cause: inner, errors: [{ message: 'p', toJSON }] }));
    expect(calls).toBe(0);
    expect(JSON.stringify(out)).not.toContain(CANARY);
  });

  it('uses the constructor name, then name, then type', () => {
    expect(serializeError(new TypeError('x')).type).toBe('TypeError');
    expect(serializeError({ message: 'x', name: 'AxiosError' }).type).toBe('AxiosError');
    expect(serializeError({ message: 'x', type: 'TypeError' }).type).toBe('TypeError');
    expect(serializeError({ message: 'x' }).type).toBe('Error');
    expect(serializeError(Object.assign(new Error('x'), { name: 'AbortError' })).type).toBe('AbortError');
    expect(serializeError(new (class extends Error {})('x')).type).toBe('Error');
  });

  it('bounds an overlong type', () => {
    const type = serializeError({ message: 'x', name: 'N'.repeat(500) }).type;
    expect(type).toHaveLength(100);
    expect(type.endsWith(TRUNCATION_MARKER)).toBe(true);
  });
});

describe('message and stack bounds', () => {
  it('truncates an overlong message with the marker, within the 2,000 character bound', () => {
    const { message } = serializeError(new Error('m'.repeat(5000)));
    expect(message).toHaveLength(2000);
    expect(message.endsWith(TRUNCATION_MARKER)).toBe(true);
  });

  it('leaves a message at exactly the bound untouched, so serialising twice is stable', () => {
    const at = 'm'.repeat(2000);
    expect(serializeError(new Error(at)).message).toBe(at);
    const once = serializeError(new Error('m'.repeat(5000)));
    expect(serializeError(once)).toEqual({ ...once, type: 'Error' });
  });

  it('truncates a stack over 8,000 characters', () => {
    const err = new Error('s');
    err.stack = `Error: s\n${'    at wide (file.js:1:1)'.padEnd(200, ' ')}\n`.repeat(100);
    const { stack } = serializeError(err);
    expect(stack).toBeDefined();
    expect(stack).toHaveLength(8000);
    expect(stack?.endsWith(TRUNCATION_MARKER)).toBe(true);
  });

  it('keeps 50 stack frames then marks the cut', () => {
    const err = new Error('deep');
    err.stack = ['Error: deep', ...Array.from({ length: 80 }, (_, i) => `    at f${i} (file.js:${i}:1)`)].join('\n');
    const lines = (serializeError(err).stack ?? '').split('\n');
    expect(lines.filter((line) => line.startsWith('    at '))).toHaveLength(50);
    expect(lines[0]).toBe('Error: deep');
    expect(lines.at(-1)).toBe(TRUNCATION_MARKER);
    expect(lines).not.toContain('    at f50 (file.js:50:1)');
  });

  it('leaves a short stack alone', () => {
    const err = new Error('short');
    err.stack = 'Error: short\n    at a (x.js:1:1)';
    expect(serializeError(err).stack).toBe(err.stack);
  });
});

describe('code and status', () => {
  it.each([
    ['an object', { a: 1 }],
    ['a boolean', true],
    ['null', null],
    ['an array', ['E']],
    ['NaN', Number.NaN],
    ['a function', () => 'E'],
  ])('drops a code that is %s', (_label, code) => {
    expect(serializeError(Object.assign(new Error('x'), { code }))).not.toHaveProperty('code');
  });

  it('keeps a string or numeric code', () => {
    expect(serializeError(Object.assign(new Error('x'), { code: 'ECONNRESET' })).code).toBe('ECONNRESET');
    expect(serializeError(Object.assign(new Error('x'), { code: 42 })).code).toBe(42);
  });

  it('writes status or statusCode to status, numbers only', () => {
    expect(serializeError(Object.assign(new Error('x'), { status: 404 })).status).toBe(404);
    expect(serializeError(Object.assign(new Error('x'), { statusCode: 503 })).status).toBe(503);
    expect(serializeError(Object.assign(new Error('x'), { status: '404' }))).not.toHaveProperty('status');
    expect(serializeError(Object.assign(new Error('x'), { status: 404, statusCode: 503 })).status).toBe(404);
    expect(serializeError(Object.assign(new Error('x'), { response: { status: 500 } }))).not.toHaveProperty('status');
  });
});

describe('cause', () => {
  it('keeps a cause chain structurally to depth 5, then marks it truncated', () => {
    const out = serializeError(chain(9));
    expect(causeDepth(out)).toBe(5);
    let last: Record<string, unknown> = out as never;
    for (let i = 1; i < 5; i++) last = last.cause as Record<string, unknown>;
    expect(last.message).toBe('level 5');
    expect(last.cause).toBe('[truncated]');
  });

  it('keeps a chain of exactly 5 whole, with no truncation marker', () => {
    expect(JSON.stringify(serializeError(chain(5)))).not.toContain('[truncated]');
  });

  it('keeps a non-Error cause as a structured value, not folded into the message', () => {
    expect(serializeError(withCause('plain string cause')).cause).toEqual({ type: 'string', message: 'plain string cause' });
    expect(serializeError(withCause({ password: CANARY }))).toMatchObject({
      message: 'outer',
      cause: { type: 'object', message: '[object Object]' },
    });
  });

  it('ignores a null or undefined cause', () => {
    expect(serializeError(withCause(null))).not.toHaveProperty('cause');
    expect(serializeError(withCause(undefined))).not.toHaveProperty('cause');
  });
});

describe('cycles', () => {
  it('stops a self-cause with [circular]', () => {
    const err = new Error('self');
    Object.assign(err, { cause: err });
    expect(serializeError(err).cause).toBe('[circular]');
  });

  it('stops a two-error cycle', () => {
    const a = new Error('a');
    const b = withCause(a, 'b');
    Object.assign(a, { cause: b });
    expect(serializeError(a)).toMatchObject({ message: 'a', cause: { message: 'b', cause: '[circular]' } });
  });

  it('stops an AggregateError containing itself', () => {
    const agg = aggregate([], 'loop');
    (agg as unknown as { errors: unknown[] }).errors.push(agg, new Error('ok'));
    expect(serializeError(agg).errors).toEqual([
      '[circular]',
      expect.objectContaining({ message: 'ok' }),
    ]);
  });

  it('does not call the same error twice in different branches a cycle', () => {
    const shared = new Error('shared');
    const out = serializeError(aggregate([shared, shared]));
    expect(out.errors).toEqual([expect.objectContaining({ message: 'shared' }), expect.objectContaining({ message: 'shared' })]);
  });
});

describe('unreadable properties', () => {
  const throwing = (target: object, key: string) =>
    Object.defineProperty(target, key, {
      get() {
        throw new Error(`getter ${key} exploded with ${CANARY}`);
      },
      enumerable: true,
    });

  it.each(['message', 'stack', 'cause', 'code'])('yields [unreadable] for a throwing %s getter', (key) => {
    const err = new Error('fine');
    throwing(err, key);
    const out = serializeError(err);
    expect(JSON.stringify(out)).not.toContain(CANARY);
    expect((out as unknown as Record<string, unknown>)[key]).toBe('[unreadable]');
  });

  it('survives a throwing name, constructor, status and errors getter', () => {
    const err = Object.assign(new Error('fine'), { name: undefined });
    for (const key of ['name', 'constructor', 'status', 'statusCode', 'errors']) throwing(err, key);
    const out = serializeError(err);
    expect(out.message).toBe('fine');
    expect(out.type).toBe('[unreadable]');
    expect(out.errors).toEqual(['[unreadable]']);
    expect(out).not.toHaveProperty('status');
  });

  it('survives a Proxy whose every trap throws', () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error('trap');
        },
        getPrototypeOf() {
          throw new Error('trap');
        },
      },
    );
    expect(() => serializeError(hostile)).not.toThrow();
    expect(() => serializeError(withCause(hostile))).not.toThrow();
  });
});

describe('AggregateError', () => {
  it('keeps each inner error in the allowlisted shape', () => {
    const out = serializeError(aggregate([new TypeError('t'), 'plain', axiosShaped()]));
    expect(out.type).toBe('AggregateError');
    expect(out.errors).toEqual([
      expect.objectContaining({ type: 'TypeError', message: 't' }),
      { type: 'string', message: 'plain' },
      expect.objectContaining({ type: 'AxiosError', code: 'ERR_BAD_REQUEST', status: 401 }),
    ]);
    expect(out).not.toHaveProperty('errors_truncated');
  });

  it('keeps at most 10 and counts the rest in errors_truncated', () => {
    const out = serializeError(aggregate(Array.from({ length: 25 }, (_, i) => new Error(`e${i}`))));
    expect(out.errors).toHaveLength(10);
    expect(out.errors_truncated).toBe(15);
  });

  it('omits errors for an empty list and a non-array', () => {
    expect(serializeError(aggregate([]))).not.toHaveProperty('errors');
    expect(serializeError(Object.assign(new Error('x'), { errors: 'nope' }))).not.toHaveProperty('errors');
  });

  it('counts inner errors toward the total depth limit', () => {
    const deep = chain(9);
    const out = serializeError(aggregate([deep]));
    const [first] = out.errors as readonly { cause?: unknown }[];
    expect(causeDepth(first)).toBe(4);
  });
});

describe('values that are not errors', () => {
  it.each([
    ['a string', 'boom', { type: 'string', message: 'boom' }],
    ['a number', 42, { type: 'number', message: '42' }],
    ['null', null, { type: 'object', message: 'null' }],
    ['undefined', undefined, { type: 'undefined', message: 'undefined' }],
    ['a bigint', 10n, { type: 'bigint', message: '10' }],
    ['a plain object without message', { password: CANARY, a: 1 }, { type: 'object', message: '[object Object]' }],
    ['an array', [CANARY], { type: 'object', message: '[object Array]' }],
    ['an object whose message is not a string', { message: { nested: CANARY } }, { type: 'object', message: '[object Object]' }],
  ])('turns %s into {type, message} and never its fields', (_label, value, expected) => {
    const out = serializeError(value);
    expect(out).toEqual(expected);
    expect(JSON.stringify(out)).not.toContain(CANARY);
  });

  it('does not run a caller toString or print a function body', () => {
    const sneaky = {
      toString() {
        return CANARY;
      },
    };
    expect(serializeError(sneaky).message).toBe('[object Object]');
    expect(serializeError(() => CANARY).message).toBe('[object Function]');
  });

  it('bounds the message of an overlong string', () => {
    const { message } = serializeError('z'.repeat(9000));
    expect(message).toHaveLength(2000);
    expect(message.endsWith(TRUNCATION_MARKER)).toBe(true);
  });
});

describe('through the logger', () => {
  it('log.error({ err }, msg)', () => {
    const out = logged({ err: axiosShaped() }, 'failed');
    expect(out.raw).not.toContain(CANARY);
    expect(out.lines[0]).toMatchObject({ msg: 'failed', err: { type: 'AxiosError', code: 'ERR_BAD_REQUEST', status: 401 } });
  });

  it('log.error(err, msg)', () => {
    const out = logged(axiosShaped(), 'failed');
    expect(out.raw).not.toContain(CANARY);
    expect(out.lines[0]).toMatchObject({ msg: 'failed', err: { type: 'AxiosError' } });
  });

  it('log.error(err) takes its msg from the bounded message', () => {
    const out = logged(new Error('e'.repeat(5000)));
    const [line] = out.lines;
    expect(String(line.msg)).toHaveLength(2000);
    expect(String(line.msg).endsWith(TRUNCATION_MARKER)).toBe(true);
    expect(out.raw.length).toBeLessThan(20000);
  });

  it('log.error({ err }) without a msg also uses the bounded message, not the raw one', () => {
    const out = logged({ err: new Error('e'.repeat(5000)) });
    expect(String(out.lines[0].msg)).toHaveLength(2000);
  });

  it('an Error with its own enumerable reserved-looking keys is still an error, not a merge object', () => {
    const out = logged(Object.assign(new Error('real'), { msg: 'spoof', level: 'fatal', app: 'evil' }), 'failed');
    expect(out.lines[0]).toMatchObject({ level: 'error', app: 'demo', msg: 'failed', err: { message: 'real' } });
    expect(out.lines[0]).not.toHaveProperty('ctx');
  });

  it.each([
    ['another key', (e: Error) => ({ error: e })],
    ['a nested plain object', (e: Error) => ({ ctx: { upstream: { failure: e } } })],
    ['an array', (e: Error) => ({ failures: [e] })],
    ['a cause under another key', (e: Error) => ({ error: withCause(e) })],
    ['an AggregateError under another key', (e: Error) => ({ error: aggregate([e]) })],
  ])('normalises an Error passed under %s', (_label, wrapIn) => {
    const out = logged(wrapIn(axiosShaped()), 'failed');
    expect(out.raw).not.toContain(CANARY);
    expect(out.raw).not.toMatch(/Authorization|set-cookie|_header/);
    expect(out.raw).toContain('AxiosError');
  });

  it('normalises an Error in child bindings', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).child({ err: axiosShaped(), other: axiosShaped() }).info('hi');
    expect(out.raw).not.toContain(CANARY);
    expect(out.lines[0].err).toMatchObject({ type: 'AxiosError' });
  });

  it('ends a cycle among plain objects and keeps the line valid', () => {
    const loop: Record<string, unknown> = { name: 'loop' };
    loop.self = loop;
    const out = logged({ loop, err: new Error('x') }, 'cyclic');
    expect(out.lines[0].loop).toEqual({ name: 'loop', self: '[circular]' });
  });

  it('turns a non-Error err into {type, message}', () => {
    const out = logged({ err: { password: CANARY } }, 'odd');
    expect(out.raw).not.toContain(CANARY);
    expect(out.lines[0].err).toEqual({ type: 'object', message: '[object Object]' });
  });

  it('leaves non-error values alone, including keys named like secrets and Dates', () => {
    const when = new Date('2026-10-02T00:00:00.000Z');
    const out = logged({ when, n: 1, list: [1, 'a'], nested: { a: { b: null } }, skip: undefined }, 'plain');
    expect(out.lines[0]).toMatchObject({ when: when.toISOString(), n: 1, list: [1, 'a'], nested: { a: { b: null } } });
    expect(out.lines[0]).not.toHaveProperty('skip');
  });

  it('keeps a hostile __proto__ key as data', () => {
    const out = logged(JSON.parse('{"__proto__":{"polluted":true},"ok":1}'), 'proto');
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(out.lines[0].ok).toBe(1);
  });

  it('emits lines that validate against schema/log-line.json', () => {
    const nested = chain(9);
    const out = captureStream();
    const log = createLoggerWithStream({ app: 'demo' }, out);
    const cyclic = new Error('self');
    Object.assign(cyclic, { cause: cyclic });
    const broken = Object.defineProperty(new Error('b'), 'message', {
      get() {
        throw new Error('no');
      },
    });
    for (const err of [
      axiosShaped(),
      preSerialised(),
      nested,
      cyclic,
      broken,
      aggregate(Array.from({ length: 25 }, (_, i) => new Error(`e${i}`))),
      new Error('m'.repeat(5000)),
      'boom',
      42,
      null,
      { password: CANARY },
    ]) {
      log.error({ err }, 'e');
    }
    log.error(axiosShaped(), 'bare');
    log.error(new Error('no msg'));
    expect(out.lines).toHaveLength(13);
    for (const line of out.lines) expect(validate(line), JSON.stringify(validate.errors)).toBe(true);
  });
});

describe('schema err definition', () => {
  const base = { v: 1, time: '2026-10-02T00:00:00.000Z', level: 'error', app: 'demo', msg: 'x' };

  it('rejects an err with any key outside the allowlist, at any depth', () => {
    expect(validate({ ...base, err: { type: 'E', message: 'm' } })).toBe(true);
    expect(validate({ ...base, err: { type: 'E', message: 'm', config: {} } })).toBe(false);
    expect(validate({ ...base, err: { type: 'E', message: 'm', cause: { type: 'E', message: 'm', response: {} } } })).toBe(false);
    expect(validate({ ...base, err: { type: 'E', message: 'm', errors: [{ type: 'E', message: 'm', data: 1 }] } })).toBe(false);
  });

  it('rejects a code that is not a string or number and a non-numeric status', () => {
    expect(validate({ ...base, err: { type: 'E', message: 'm', code: {} } })).toBe(false);
    expect(validate({ ...base, err: { type: 'E', message: 'm', status: '500' } })).toBe(false);
    expect(validate({ ...base, err: { type: 'E', message: 'm', code: 'X', status: 500 } })).toBe(true);
  });
});
