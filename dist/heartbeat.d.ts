import type { Logger } from './types';
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
export declare function startHeartbeat(logger: Logger, options?: HeartbeatOptions): Heartbeat;
