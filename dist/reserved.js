"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RESERVED_KEYS = void 0;
exports.relocateReserved = relocateReserved;
/** Envelope keys owned by the logger. Callers can never set these. */
exports.RESERVED_KEYS = new Set(['v', 'time', 'level', 'app', 'proc', 'msg']);
const isPlainObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
function freeKey(taken, key) {
    let candidate = key;
    while (candidate in taken)
        candidate += '_';
    return candidate;
}
/**
 * Moves reserved keys out of caller fields into `ctx.<key>` so they can neither
 * overwrite the envelope nor vanish. A caller's own `ctx` stays intact: relocated
 * keys join it without replacing an entry, and a non-object `ctx` is kept as `ctx.value`.
 */
function relocateReserved(fields) {
    const moved = Object.keys(fields).filter((key) => exports.RESERVED_KEYS.has(key));
    if (moved.length === 0)
        return fields;
    const kept = {};
    for (const [key, value] of Object.entries(fields)) {
        if (!exports.RESERVED_KEYS.has(key))
            kept[key] = value;
    }
    const ctx = isPlainObject(kept.ctx)
        ? { ...kept.ctx }
        : kept.ctx === undefined
            ? {}
            : { value: kept.ctx };
    for (const key of moved)
        ctx[freeKey(ctx, key)] = fields[key];
    return { ...kept, ctx };
}
