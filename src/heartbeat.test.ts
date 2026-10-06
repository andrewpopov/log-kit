import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LogConfigError, startHeartbeat } from './index';
import { createLoggerWithStream } from './logger';
import { captureStream } from './test-support';

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

function setup() {
  const out = captureStream();
  return { out, logger: createLoggerWithStream({ app: 'demo' }, out) };
}

describe('startHeartbeat', () => {
  it('emits one line immediately with the contract shape', () => {
    const { out, logger } = setup();
    const hb = startHeartbeat(logger);
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0]).toMatchObject({
      v: 1,
      app: 'demo',
      level: 'info',
      msg: 'log heartbeat',
      heartbeat_interval_s: 300,
    });
    hb.stop();
  });

  it('emits again every interval', () => {
    const { out, logger } = setup();
    const hb = startHeartbeat(logger, { intervalMs: 5000 });
    expect(out.lines).toHaveLength(1);
    vi.advanceTimersByTime(4999);
    expect(out.lines).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(out.lines).toHaveLength(2);
    vi.advanceTimersByTime(10_000);
    expect(out.lines).toHaveLength(4);
    expect(out.lines[3]).toMatchObject({ msg: 'log heartbeat', heartbeat_interval_s: 5 });
    hb.stop();
  });

  it('stop halts the beat and is idempotent', () => {
    const { out, logger } = setup();
    const hb = startHeartbeat(logger, { intervalMs: 1000 });
    hb.stop();
    hb.stop();
    vi.advanceTimersByTime(10_000);
    expect(out.lines).toHaveLength(1);
  });

  it('unrefs its timer so it never keeps the process alive', () => {
    const unref = vi.fn();
    const realSetInterval = globalThis.setInterval;
    vi.spyOn(globalThis, 'setInterval').mockImplementation(((...args: Parameters<typeof setInterval>) => {
      const timer = realSetInterval(...args);
      timer.unref = (() => {
        unref();
        return timer;
      }) as typeof timer.unref;
      return timer;
    }) as typeof setInterval);
    const { logger } = setup();
    startHeartbeat(logger).stop();
    expect(unref).toHaveBeenCalledTimes(1);
  });

  it.each([0, 999, 1.5, NaN, Infinity])('rejects intervalMs %s', (intervalMs) => {
    const { logger } = setup();
    expect(() => startHeartbeat(logger, { intervalMs })).toThrow(
      expect.objectContaining({ name: 'LogConfigError', code: 'INVALID_HEARTBEAT_INTERVAL' }),
    );
    expect(() => startHeartbeat(logger, { intervalMs })).toThrow(LogConfigError);
  });

  it('survives a throwing logger, on the first line and on later ticks', () => {
    const { logger } = setup();
    let calls = 0;
    vi.spyOn(logger, 'info').mockImplementation(() => {
      calls += 1;
      throw new Error('destination closed');
    });
    let hb: ReturnType<typeof startHeartbeat> | undefined;
    expect(() => {
      hb = startHeartbeat(logger, { intervalMs: 1000 });
      vi.advanceTimersByTime(3000);
    }).not.toThrow();
    expect(calls).toBe(4);
    hb?.stop();
  });
});
