import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv2020 from 'ajv/dist/2020';
import { describe, expect, it } from 'vitest';
import { createLoggerWithStream } from './logger';
import { captureStream } from './test-support';

const schema = JSON.parse(readFileSync(join(__dirname, '..', 'schema', 'log-line.json'), 'utf8'));
const validate = new Ajv2020({ strict: true }).compile(schema);

describe('schema/log-line.json', () => {
  it('accepts every line the logger emits, across levels, children, errors and collisions', () => {
    const out = captureStream();
    const logger = createLoggerWithStream({ app: 'demo', proc: 'web', level: 'trace' }, out);
    logger.trace('t');
    logger.debug({ a: 1 }, 'd');
    logger.info('i');
    logger.warn({ nested: { deep: [1, 2] } }, 'w');
    logger.error({ err: new Error('boom') }, 'e');
    logger.fatal('f');
    logger.child({ req_id: 'r-1', http: { method: 'GET', status: 200 } }).info('c');
    logger.info({ level: 'x', msg: 'y', ctx: 'z' }, 'collision');
    expect(out.lines).toHaveLength(8);
    for (const line of out.lines) {
      expect(validate(line), JSON.stringify(validate.errors)).toBe(true);
    }
  });

  it('rejects a numeric level, a wrong version and a missing app', () => {
    const base = { v: 1, time: '2026-10-02T00:00:00.000Z', level: 'info', app: 'demo', msg: 'x' };
    expect(validate(base)).toBe(true);
    expect(validate({ ...base, level: 30 })).toBe(false);
    expect(validate({ ...base, v: 2 })).toBe(false);
    expect(validate({ ...base, app: undefined })).toBe(false);
    expect(validate({ ...base, time: '2026-10-02 00:00:00' })).toBe(false);
  });
});
