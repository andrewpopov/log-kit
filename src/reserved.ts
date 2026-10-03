import type { LogFields } from './types';

/** Envelope keys owned by the logger. Callers can never set these. */
export const RESERVED_KEYS: ReadonlySet<string> = new Set(['v', 'time', 'level', 'app', 'proc', 'msg']);

const isPlainObject = (value: unknown): value is LogFields =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function freeKey(taken: LogFields, key: string): string {
  let candidate = key;
  while (candidate in taken) candidate += '_';
  return candidate;
}

/**
 * Moves reserved keys out of caller fields into `ctx.<key>` so they can neither
 * overwrite the envelope nor vanish. A caller's own `ctx` stays intact: relocated
 * keys join it without replacing an entry, and a non-object `ctx` is kept as `ctx.value`.
 */
export function relocateReserved(fields: LogFields): LogFields {
  const moved = Object.keys(fields).filter((key) => RESERVED_KEYS.has(key));
  if (moved.length === 0) return fields;

  // No prototype, so a `__proto__` key from JSON.parse is an own property: it can neither reparent `kept` nor be found as `ctx`.
  const kept: LogFields = Object.create(null) as LogFields;
  for (const [key, value] of Object.entries(fields)) {
    if (!RESERVED_KEYS.has(key)) kept[key] = value;
  }

  const ctx: LogFields = isPlainObject(kept.ctx)
    ? { ...kept.ctx }
    : kept.ctx === undefined
      ? {}
      : { value: kept.ctx };
  for (const key of moved) ctx[freeKey(ctx, key)] = fields[key];

  return { ...kept, ctx };
}
