import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { LogConfigError, LOG_LEVELS, createLogger } from './index';
import { createLoggerWithStream } from './logger';
import { captureStream } from './test-support';

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

afterEach(() => {
  delete process.env.LOG_LEVEL;
});

describe('envelope', () => {
  it('emits schema v1 with ISO UTC time, word level, app and msg, and no pid/hostname', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).info('hello');
    expect(out.lines).toHaveLength(1);
    const [line] = out.lines;
    expect(line).toMatchObject({ v: 1, level: 'info', app: 'demo', msg: 'hello' });
    expect(line.time).toMatch(ISO_UTC);
    expect(line).not.toHaveProperty('pid');
    expect(line).not.toHaveProperty('hostname');
    expect(line).not.toHaveProperty('proc');
  });

  it('emits proc when given', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo', proc: 'worker' }, out).info('hello');
    expect(out.lines[0]).toMatchObject({ app: 'demo', proc: 'worker' });
  });

  it.each(LOG_LEVELS)('emits the word %s, never a number', (level) => {
    const out = captureStream();
    const logger = createLoggerWithStream({ app: 'demo', level: 'trace' }, out);
    logger[level](`at ${level}`);
    expect(out.lines).toEqual([expect.objectContaining({ level, msg: `at ${level}` })]);
  });

  it('suppresses lines below the configured level', () => {
    const out = captureStream();
    const logger = createLoggerWithStream({ app: 'demo', level: 'warn' }, out);
    logger.info('hidden');
    logger.warn('shown');
    expect(out.lines.map((l) => l.msg)).toEqual(['shown']);
  });

  it('merges free-form fields next to the envelope', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).info({ job: 'sync', count: 3 }, 'done');
    expect(out.lines[0]).toMatchObject({ app: 'demo', job: 'sync', count: 3, msg: 'done' });
  });

  it('serializes err through the allowlisted {type, message, stack} shape', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).error({ err: new TypeError('boom') }, 'failed');
    expect(out.lines[0].err).toEqual({
      type: 'TypeError',
      message: 'boom',
      stack: expect.stringContaining('boom'),
    });
  });
});

describe('error call forms', () => {
  it('types and runs all three: log.error(err), log.error(err, msg) and log.error({ err }, msg)', () => {
    const out = captureStream();
    const log = createLoggerWithStream({ app: 'demo' }, out);
    log.error(new Error('bare'));
    log.error(new Error('with msg'), 'explicit');
    log.error({ err: new Error('keyed') }, 'in fields');
    expect(out.lines.map((line) => [line.msg, (line.err as { message: string }).message])).toEqual([
      ['bare', 'bare'],
      ['explicit', 'with msg'],
      ['in fields', 'keyed'],
    ]);
  });
});

describe('child', () => {
  it('adds bindings to every line it emits, leaving the parent untouched', () => {
    const out = captureStream();
    const parent = createLoggerWithStream({ app: 'demo' }, out);
    const child = parent.child({ req_id: 'r-1', route: '/x' });
    child.info('from child');
    parent.info('from parent');
    expect(out.lines[0]).toMatchObject({ req_id: 'r-1', route: '/x', msg: 'from child' });
    expect(out.lines[1]).not.toHaveProperty('req_id');
  });

  it('nests: grandchild keeps both layers of bindings', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).child({ a: 1 }).child({ b: 2 }).info('x');
    expect(out.lines[0]).toMatchObject({ a: 1, b: 2 });
  });
});

describe('reserved envelope keys', () => {
  const hostile = { v: 99, time: 'never', level: 'fatal', app: 'evil', proc: 'evil', msg: 'evil' };

  it('child bindings cannot override the envelope and are kept under ctx', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo', proc: 'web' }, out).child(hostile).info('real');
    const [line] = out.lines;
    expect(line).toMatchObject({ v: 1, level: 'info', app: 'demo', proc: 'web', msg: 'real' });
    expect(line.time).toMatch(ISO_UTC);
    expect(line.ctx).toEqual(hostile);
  });

  it('merge objects cannot override the envelope and are kept under ctx', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo', proc: 'web' }, out).info(hostile, 'real');
    const [line] = out.lines;
    expect(line).toMatchObject({ v: 1, level: 'info', app: 'demo', proc: 'web', msg: 'real' });
    expect(line.time).toMatch(ISO_UTC);
    expect(line.ctx).toEqual(hostile);
  });

  it('emits exactly one of each envelope key even for a hostile merge object', () => {
    const out = captureStream();
    const raw: string[] = [];
    createLoggerWithStream({ app: 'demo' }, { write: (chunk: string) => raw.push(chunk) }).info(hostile, 'real');
    const outsideCtx = raw.join('').replace(/"ctx":\{[^}]*\}/, '');
    for (const key of ['v', 'time', 'level', 'app', 'msg']) {
      expect(outsideCtx.match(new RegExp(`"${key}":`, 'g')), key).toHaveLength(1);
    }
    expect(out.lines).toHaveLength(0);
  });

  it('keeps a caller-supplied ctx and does not lose relocated keys', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).info({ ctx: { app: 'mine', x: 1 }, app: 'theirs' }, 'm');
    expect(out.lines[0].ctx).toEqual({ app: 'mine', x: 1, app_: 'theirs' });
  });

  it('keeps a non-object ctx as ctx.value', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).info({ ctx: 'plain', msg: 'sneaky' }, 'm');
    expect(out.lines[0]).toMatchObject({ app: 'demo', msg: 'm', ctx: { value: 'plain', msg: 'sneaky' } });
  });

  it('leaves non-colliding fields alone, with no ctx added', () => {
    const out = captureStream();
    createLoggerWithStream({ app: 'demo' }, out).info({ ok: true }, 'm');
    expect(out.lines[0]).not.toHaveProperty('ctx');
  });
});

describe('configuration', () => {
  it('rejects an invalid LOG_LEVEL with a typed error', () => {
    process.env.LOG_LEVEL = 'verbose';
    expect(() => createLogger({ app: 'demo' })).toThrowError(LogConfigError);
    expect(() => createLogger({ app: 'demo' })).toThrowError(expect.objectContaining({ code: 'INVALID_LOG_LEVEL' }));
  });

  it('uses a valid LOG_LEVEL', () => {
    process.env.LOG_LEVEL = 'error';
    const out = captureStream();
    const logger = createLoggerWithStream({ app: 'demo' }, out);
    logger.warn('hidden');
    logger.error('shown');
    expect(out.lines.map((l) => l.msg)).toEqual(['shown']);
  });

  it('defaults to info when LOG_LEVEL is unset or empty', () => {
    for (const value of [undefined, '']) {
      if (value === undefined) delete process.env.LOG_LEVEL;
      else process.env.LOG_LEVEL = value;
      const out = captureStream();
      const logger = createLoggerWithStream({ app: 'demo' }, out);
      logger.debug('hidden');
      logger.info('shown');
      expect(out.lines.map((l) => l.msg)).toEqual(['shown']);
    }
  });

  it('an explicit level wins over LOG_LEVEL, and an invalid one is rejected', () => {
    process.env.LOG_LEVEL = 'verbose';
    expect(() => createLogger({ app: 'demo', level: 'loud' as never })).toThrowError(
      expect.objectContaining({ code: 'INVALID_LOG_LEVEL' }),
    );
    const out = captureStream();
    expect(() => createLoggerWithStream({ app: 'demo', level: 'debug' }, out)).not.toThrow();
  });

  it('rejects an empty app', () => {
    expect(() => createLogger({ app: '' })).toThrowError(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
  });

  it('rejects a malformed destination', () => {
    expect(() => createLogger({ app: 'demo', destination: { file: '' } })).toThrowError(
      expect.objectContaining({ code: 'INVALID_ARGUMENT' }),
    );
  });
});

describe('file destination', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it('writes lines to the file synchronously', () => {
    const dir = mkdtempSync(join(tmpdir(), 'log-kit-test-'));
    dirs.push(dir);
    const file = join(dir, 'app.log');
    const logger = createLogger({ app: 'demo', proc: 'web', destination: { file } });
    logger.info({ n: 1 }, 'first');
    logger.warn('second');
    const lines = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(lines).toEqual([
      expect.objectContaining({ v: 1, level: 'info', app: 'demo', proc: 'web', n: 1, msg: 'first' }),
      expect.objectContaining({ level: 'warn', msg: 'second' }),
    ]);
  });
});
