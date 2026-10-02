import type { LogFields } from './types';
/** Envelope keys owned by the logger. Callers can never set these. */
export declare const RESERVED_KEYS: ReadonlySet<string>;
/**
 * Moves reserved keys out of caller fields into `ctx.<key>` so they can neither
 * overwrite the envelope nor vanish. A caller's own `ctx` stays intact: relocated
 * keys join it without replacing an entry, and a non-object `ctx` is kept as `ctx.value`.
 */
export declare function relocateReserved(fields: LogFields): LogFields;
