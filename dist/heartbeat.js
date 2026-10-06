"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.startHeartbeat = startHeartbeat;
const errors_1 = require("./errors");
const DEFAULT_INTERVAL_MS = 300000;
const MIN_INTERVAL_MS = 1000;
/**
 * Emits `log heartbeat` once now and then every interval, so monitoring can alert when a source that was
 * shipping lines goes silent. The msg is a cross-repo contract: alerts key on it, do not change it.
 */
function startHeartbeat(logger, options = {}) {
    const intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS;
    if (!Number.isInteger(intervalMs) || intervalMs < MIN_INTERVAL_MS) {
        throw new errors_1.LogConfigError('INVALID_HEARTBEAT_INTERVAL', `intervalMs must be a finite integer of at least ${MIN_INTERVAL_MS}`);
    }
    const beat = () => {
        try {
            logger.info({ heartbeat_interval_s: intervalMs / 1000 }, 'log heartbeat');
        }
        catch {
            // A broken destination must not crash the process or end the beat; logging the failure would loop.
        }
    };
    beat();
    const timer = setInterval(beat, intervalMs);
    timer.unref();
    return { stop: () => clearInterval(timer) };
}
