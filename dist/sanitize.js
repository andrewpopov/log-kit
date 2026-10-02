"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitizeString = void 0;
exports.sanitize = sanitize;
const node_util_1 = require("node:util");
const redact_policy_1 = require("./redact-policy");
const redact_string_1 = require("./redact-string");
Object.defineProperty(exports, "sanitizeString", { enumerable: true, get: function () { return redact_string_1.sanitizeString; } });
const serialize_error_1 = require("./serialize-error");
const OMITTED = '[omitted]';
const MAX_KEYS = 200;
const MAX_ITEMS = 100;
/** A function or symbol: dropped from an object or array rather than rendered. */
const DROP = Symbol('drop');
const isCounterValue = (value) => value === null || value === undefined || ['number', 'bigint', 'boolean'].includes(typeof value);
/**
 * What an object property becomes. The key decides first: a credential key redacts whatever it holds, so an allowed
 * path can never expose one. Inside a body, only a value whose path is allowed, or that leads to one, survives.
 */
function sanitizeProperty(key, value, walk, parent) {
    if (typeof value === 'function' || typeof value === 'symbol')
        return DROP;
    const keyClass = (0, redact_policy_1.classifyKey)(key, walk.policy);
    if (keyClass === 'secret')
        return redact_string_1.REDACTED;
    if (keyClass === 'counter' && !isCounterValue(value))
        return redact_string_1.REDACTED;
    const keys = [...parent.keys, key];
    const dotted = keys.join('.');
    const inBody = parent.inBody || keyClass === 'body';
    if (inBody && walk.policy.allowPaths.has(dotted))
        return sanitizeValue(value, walk, { depth: parent.depth + 1, keys, inBody: false });
    if (inBody && !(walk.policy.allowPrefixes.has(dotted) && (0, serialize_error_1.isObject)(value) && (0, serialize_error_1.isWalkable)(value))) {
        return value === undefined ? DROP : OMITTED;
    }
    return sanitizeValue(value, walk, { depth: parent.depth + 1, keys, inBody });
}
function sanitizeObject(source, walk, at) {
    let keys;
    try {
        keys = Object.keys(source);
    }
    catch {
        return serialize_error_1.UNREADABLE;
    }
    const entries = [];
    for (const key of keys.slice(0, MAX_KEYS)) {
        const raw = (0, serialize_error_1.read)(source, key);
        const value = raw === serialize_error_1.unreadable ? serialize_error_1.UNREADABLE : sanitizeProperty(key, raw, walk, at);
        if (value !== DROP)
            entries.push([(0, redact_string_1.sanitizeString)(key), value]);
    }
    if (keys.length > MAX_KEYS)
        entries.push([serialize_error_1.TRUNCATED, keys.length - MAX_KEYS]);
    // fromEntries defines own properties, so a hostile `__proto__` key stays data instead of reassigning the prototype.
    return Object.fromEntries(entries);
}
/** A list item or Map side. Inside a body only a container may be descended into; a bare value there is body content. */
function sanitizeElement(item, walk, at) {
    const deeper = { ...at, depth: at.depth + 1 };
    if (at.inBody && !(0, serialize_error_1.isObject)(item))
        return typeof item === 'function' || typeof item === 'symbol' ? DROP : OMITTED;
    return sanitizeValue(item, walk, deeper);
}
function sanitizeItems(items, walk, at) {
    const out = [];
    for (const item of items) {
        if (out.length >= MAX_ITEMS) {
            out.push(serialize_error_1.TRUNCATED);
            break;
        }
        const value = sanitizeElement(item, walk, at);
        if (value !== DROP)
            out.push(value);
    }
    return out;
}
function sanitizeArray(source, walk, at) {
    const length = (0, serialize_error_1.read)(source, 'length');
    const items = [];
    for (let i = 0; typeof length === 'number' && i < Math.min(length, MAX_ITEMS + 1); i++) {
        const item = (0, serialize_error_1.read)(source, i);
        items.push(item === serialize_error_1.unreadable ? serialize_error_1.UNREADABLE : item);
    }
    // Items are read once up front (a getter or hole is read exactly once), then bounded and sanitised like any list.
    return sanitizeItems(items, walk, at);
}
/** A Map entry is `[key, value]`; a string key applies the same key policy as an object property would. */
function sanitizeMap(source, walk, at) {
    const pairs = [];
    for (const [key, value] of Map.prototype.entries.call(source)) {
        if (pairs.length >= MAX_ITEMS) {
            pairs.push(serialize_error_1.TRUNCATED);
            break;
        }
        if (typeof key === 'string') {
            const entry = sanitizeProperty(key, value, walk, at);
            if (entry !== DROP)
                pairs.push([(0, redact_string_1.sanitizeString)(key), entry]);
        }
        else {
            const sanitisedKey = sanitizeElement(key, walk, at);
            const sanitisedValue = sanitizeElement(value, walk, at);
            if (sanitisedKey !== DROP && sanitisedValue !== DROP)
                pairs.push([sanitisedKey, sanitisedValue]);
        }
    }
    return pairs;
}
const byteLengthOf = (view) => {
    const length = (0, serialize_error_1.read)(view, 'byteLength');
    return typeof length === 'number' ? length : 0;
};
/** Built-ins that have a safe, fixed rendering. `undefined` means: not one of them, walk it as an object. */
function sanitizeBuiltin(value) {
    if (ArrayBuffer.isView(value) || node_util_1.types.isAnyArrayBuffer(value))
        return `[binary ${byteLengthOf(value)} bytes]`;
    if (node_util_1.types.isDate(value)) {
        const time = Date.prototype.getTime.call(value);
        return Number.isNaN(time) ? null : Date.prototype.toISOString.call(value);
    }
    if (node_util_1.types.isStringObject(value))
        return (0, redact_string_1.sanitizeString)(String.prototype.valueOf.call(value));
    if (node_util_1.types.isNumberObject(value))
        return Number.prototype.valueOf.call(value);
    if (node_util_1.types.isBooleanObject(value))
        return Boolean.prototype.valueOf.call(value);
    if (node_util_1.types.isBigIntObject(value) || node_util_1.types.isSymbolObject(value))
        return DROP;
    if (value instanceof URL) {
        const href = (0, serialize_error_1.read)(value, 'href');
        return typeof href === 'string' ? (0, redact_string_1.sanitizeString)(href) : serialize_error_1.UNREADABLE;
    }
    return undefined;
}
function sanitizeValue(value, walk, at) {
    if (typeof value === 'string')
        return (0, redact_string_1.sanitizeString)(value);
    if (typeof value === 'function' || typeof value === 'symbol')
        return DROP;
    if (!(0, serialize_error_1.isObject)(value))
        return value;
    if ((0, serialize_error_1.isError)(value))
        return (0, serialize_error_1.serializeError)(value);
    if (walk.ancestors.has(value))
        return serialize_error_1.CIRCULAR;
    walk.ancestors.add(value);
    try {
        const builtin = sanitizeBuiltin(value);
        if (builtin !== undefined)
            return builtin;
        if (at.depth > serialize_error_1.MAX_FIELD_DEPTH)
            return serialize_error_1.TRUNCATED;
        if (Array.isArray(value))
            return sanitizeArray(value, walk, at);
        if (node_util_1.types.isMap(value))
            return sanitizeMap(value, walk, at);
        if (node_util_1.types.isSet(value))
            return sanitizeItems(Set.prototype.values.call(value), walk, at);
        return sanitizeObject(value, walk, at);
    }
    catch {
        return serialize_error_1.UNREADABLE;
    }
    finally {
        walk.ancestors.delete(value);
    }
}
/**
 * The single choke point every caller-supplied value passes through before it reaches output: merge objects, child
 * bindings and the message. Always returns a freshly built tree of plain data, never the caller's own objects, so
 * nothing downstream (pino's stringifier included) can call a caller's `toJSON` or getter, or see a key this skipped.
 *
 * Strings are redacted by `sanitizeString`; keys by `classifyKey`. The walk is bounded: depth 8, 200 keys per
 * object, 100 items per array, Map or Set. Past a bound the value is `[truncated]` (an object gets one extra
 * `"[truncated]": <dropped count>` key). A cycle is `[circular]`, a throwing getter `[unreadable]`, binary data
 * `[binary N bytes]`; functions and symbols are dropped.
 */
function sanitize(value, policy = redact_policy_1.DEFAULT_REDACT_POLICY) {
    const result = sanitizeValue(value, { policy, ancestors: new Set() }, { depth: 0, keys: [], inBody: false });
    return (result === DROP ? undefined : result);
}
