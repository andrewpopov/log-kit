import { LogConfigError } from './errors';
import type { Logger } from './types';

const DEFAULT_INTERVAL_MS = 300_000;
const MIN_INTERVAL_MS = 1000;

export interface HeartbeatOptions {
  /** Milliseconds between lines. Defaults to 300000; a finite integer of at least 1000. */
  readonly intervalMs?: number;
}

export interface Heartbeat {
  /** Clears the timer. Safe to call more than once. */
  stop(): void;
}

/**
 * Emits `log heartbeat` once now and then every interval, so monitoring can alert when a source that was
 * shipping lines goes silent. The msg is a cross-repo contract: alerts key on it, do not change it.
 */
export function startHeartbeat(logger: Logger, options: HeartbeatOptions = {}): Heartbeat {
  const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
  if (!Number.isInteger(intervalMs) || intervalMs < MIN_INTERVAL_MS) {
    throw new LogConfigError(
      'INVALID_HEARTBEAT_INTERVAL',
      `intervalMs must be a finite integer of at least ${MIN_INTERVAL_MS}`,
    );
  }

  const beat = (): void => {
    try {
      logger.info({ heartbeat_interval_s: intervalMs / 1000 }, 'log heartbeat');
    } catch {
      // A broken destination must not crash the process or end the beat; logging the failure would loop.
    }
  };

  beat();
  const timer = setInterval(beat, intervalMs);
  timer.unref();

  return { stop: () => clearInterval(timer) };
}
