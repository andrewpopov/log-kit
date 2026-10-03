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
/** A string value is cut here (after redaction, which itself reads at most twice this much), ending in `…[truncated]`. */
const MAX_STRING_VALUE = 16 * 1024;
const MAX_KEY_LENGTH = 256;
const MAX_CLASS_NAME = 100;
/** A function or symbol: dropped from an object or array rather than rendered. */
const DROP = Symbol('drop');
const isCounterValue = (value) => value === null || value === undefined || ['number', 'bigint', 'boolean'].includes(typeof value);
/** True when the key says the value must not be shown: a credential name, or a usage counter holding a non-number. */
function protectsValue(name, value, policy) {
    const keyClass = (0, redact_policy_1.classifyKey)(name, policy);
    return keyClass === 'secret' || (keyClass === 'counter' && !isCounterValue(value));
}
/**
 * What an object property becomes. The key decides first: a credential key redacts whatever it holds, so an allowed
 * path can never expose one. Inside a body, only a value whose path is allowed, or that leads to one, survives.
 */
function sanitizeProperty(key, value, walk, parent) {
    if (typeof value === 'function' || typeof value === 'symbol')
        return DROP;
    if (protectsValue(key, value, walk.policy))
        return redact_string_1.REDACTED;
    const keys = [...parent.keys, key];
    const dotted = keys.join('.');
    const inBody = parent.inBody || (0, redact_policy_1.classifyKey)(key, walk.policy) === 'body';
    const next = { depth: parent.depth + 1, keys };
    if (inBody && walk.policy.allowPaths.has(dotted))
        return sanitizeValue(value, walk, { ...next, inBody: false });
    if (inBody && !(walk.policy.allowPrefixes.has(dotted) && (0, serialize_error_1.isObject)(value) && (0, serialize_error_1.isWalkable)(value))) {
        return value === undefined ? DROP : OMITTED;
    }
    return sanitizeValue(value, walk, { ...next, inBody });
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
            entries.push([(0, serialize_error_1.boundedText)(key, MAX_KEY_LENGTH), value]);
    }
    if (keys.length > MAX_KEYS)
        entries.push([serialize_error_1.TRUNCATED, keys.length - MAX_KEYS]);
    // fromEntries defines own properties, so a hostile `__proto__` key stays data instead of reassigning the prototype.
    return Object.fromEntries(entries);
}
/** A list item or Map side. Inside a body only a plain container may be descended into; anything else there is body content. */
function sanitizeElement(item, walk, at) {
    if (at.inBody && !((0, serialize_error_1.isObject)(item) && (0, serialize_error_1.isWalkable)(item))) {
        return typeof item === 'function' || typeof item === 'symbol' ? DROP : OMITTED;
    }
    return sanitizeValue(item, walk, { ...at, depth: at.depth + 1 });
}
/** Up to `MAX_ITEMS` visited items, then `[truncated]`. Dropped items count as visited, so a long run of them cannot hide the end. */
function sanitizeItems(items, walk, at) {
    const out = [];
    let visited = 0;
    for (const item of items) {
        if (visited++ >= MAX_ITEMS) {
            out.push(serialize_error_1.TRUNCATED);
            break;
        }
        const value = sanitizeElement(item, walk, at);
        if (value !== DROP)
            out.push(value);
    }
    return out;
}
/**
 * Header lists: `[['x-api-key', 'S']]` pairs and the flat `['Cookie', 'v', ...]` of a raw header list. Each name goes
 * through the key policy and the value that follows a credential name is replaced. A flat list is only taken for one
 * when every item is a string and there is an even number of them, so ordinary arrays of values are left to the walk.
 */
function redactHeaderValues(items, policy) {
    const head = items.slice(0, MAX_ITEMS);
    if (head.length >= 2 && head.length % 2 === 0 && head.every((item) => typeof item === 'string')) {
        return items.map((item, index) => index % 2 === 1 && index < MAX_ITEMS && protectsValue(items[index - 1], item, policy) ? redact_string_1.REDACTED : item);
    }
    return items.map((item) => {
        if (!Array.isArray(item) || (0, serialize_error_1.read)(item, 'length') !== 2)
            return item;
        const [name, value] = [(0, serialize_error_1.read)(item, 0), (0, serialize_error_1.read)(item, 1)];
        return typeof name === 'string' && protectsValue(name, value, policy) ? [name, redact_string_1.REDACTED] : item;
    });
}
function sanitizeArray(source, walk, at) {
    const length = (0, serialize_error_1.read)(source, 'length');
    const items = [];
    // Read once, and no further than the bound needs.
    for (let i = 0; typeof length === 'number' && i < Math.min(length, MAX_ITEMS + 1); i++) {
        const item = (0, serialize_error_1.read)(source, i);
        items.push(item === serialize_error_1.unreadable ? serialize_error_1.UNREADABLE : item);
    }
    return sanitizeItems(redactHeaderValues(items, walk.policy), walk, at);
}
/** A Map entry is `[key, value]`; a string key (a boxed one is unboxed first) applies the same key policy as an object property. */
function sanitizeMap(source, walk, at) {
    const pairs = [];
    let visited = 0;
    for (const [rawKey, value] of Map.prototype.entries.call(source)) {
        if (visited++ >= MAX_ITEMS) {
            pairs.push(serialize_error_1.TRUNCATED);
            break;
        }
        const key = node_util_1.types.isStringObject(rawKey) ? String.prototype.valueOf.call(rawKey) : rawKey;
        if (typeof key === 'string') {
            const entry = sanitizeProperty(key, value, walk, at);
            if (entry !== DROP)
                pairs.push([(0, serialize_error_1.boundedText)(key, MAX_KEY_LENGTH), entry]);
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
/** Built-ins that have a safe, fixed rendering. `undefined` means: not one of them. */
function sanitizeBuiltin(value) {
    if (ArrayBuffer.isView(value) || node_util_1.types.isAnyArrayBuffer(value))
        return `[binary ${byteLengthOf(value)} bytes]`;
    if (node_util_1.types.isDate(value)) {
        const time = Date.prototype.getTime.call(value);
        return Number.isNaN(time) ? null : Date.prototype.toISOString.call(value);
    }
    if (node_util_1.types.isStringObject(value))
        return (0, serialize_error_1.boundedText)(String.prototype.valueOf.call(value), MAX_STRING_VALUE);
    if (node_util_1.types.isNumberObject(value))
        return Number.prototype.valueOf.call(value);
    if (node_util_1.types.isBooleanObject(value))
        return Boolean.prototype.valueOf.call(value);
    if (node_util_1.types.isBigIntObject(value) || node_util_1.types.isSymbolObject(value))
        return DROP;
    if (value instanceof URL) {
        const href = (0, serialize_error_1.read)(value, 'href');
        return typeof href === 'string' ? (0, serialize_error_1.boundedText)(href, MAX_STRING_VALUE) : serialize_error_1.UNREADABLE;
    }
    return undefined;
}
/** The constructor name, read from the prototype's own data property so no caller code runs. `[Object]` when there is none. */
function describeInstance(value) {
    try {
        const descriptor = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(value), 'constructor');
        const ctor = descriptor !== undefined && 'value' in descriptor ? descriptor.value : undefined;
        const name = typeof ctor === 'function' ? Object.getOwnPropertyDescriptor(ctor, 'name')?.value : undefined;
        return `[${typeof name === 'string' && name !== '' ? (0, serialize_error_1.boundedText)(name, MAX_CLASS_NAME) : 'Object'}]`;
    }
    catch {
        return '[Object]';
    }
}
function sanitizeValue(value, walk, at) {
    if (typeof value === 'function' || typeof value === 'symbol')
        return DROP;
    if (value === undefined)
        return value;
    if (at.depth > serialize_error_1.MAX_FIELD_DEPTH)
        return serialize_error_1.TRUNCATED;
    if (typeof value === 'string')
        return (0, serialize_error_1.boundedText)(value, MAX_STRING_VALUE);
    if (!(0, serialize_error_1.isObject)(value))
        return value;
    // An Error is replaced by its allowlisted form, which is then walked like any plain object (key policy included).
    if ((0, serialize_error_1.isError)(value))
        return sanitizeValue((0, serialize_error_1.serializeError)(value), walk, at);
    if (walk.ancestors.has(value))
        return serialize_error_1.CIRCULAR;
    walk.ancestors.add(value);
    try {
        const builtin = sanitizeBuiltin(value);
        if (builtin !== undefined)
            return builtin;
        if (Array.isArray(value))
            return sanitizeArray(value, walk, at);
        if (node_util_1.types.isMap(value))
            return sanitizeMap(value, walk, at);
        if (node_util_1.types.isSet(value))
            return sanitizeItems(Set.prototype.values.call(value), walk, at);
        // Never walk a class instance (an http.IncomingMessage carries its raw headers): only its name is shown.
        return (0, serialize_error_1.isWalkable)(value) ? sanitizeObject(value, walk, at) : describeInstance(value);
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
 * Strings are redacted by `sanitizeString` and cut at 16 KB; keys by `classifyKey`. Only plain data is walked: an
 * object whose prototype is not `Object.prototype` or null is shown as `[ClassName]`. The walk is bounded: depth 8,
 * 200 keys per object, 100 items per array, Map or Set. Past a bound the value is `[truncated]` (an object gets one
 * extra `"[truncated]": <dropped count>` key). A cycle is `[circular]`, a throwing getter `[unreadable]`, binary data
 * `[binary N bytes]`; functions and symbols are dropped. An Error anywhere inside is replaced by its allowlisted form.
 */
function sanitize(value, policy = redact_policy_1.DEFAULT_REDACT_POLICY) {
    const result = sanitizeValue(value, { policy, ancestors: new Set() }, { depth: 0, keys: [], inBody: false });
    return (result === DROP ? undefined : result);
}
