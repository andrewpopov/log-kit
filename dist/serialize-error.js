"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isWalkable = exports.isObject = exports.unreadable = exports.MAX_FIELD_DEPTH = exports.TRUNCATED = exports.CIRCULAR = exports.UNREADABLE = exports.TRUNCATION_MARKER = void 0;
exports.read = read;
exports.isError = isError;
exports.serializeError = serializeError;
exports.normaliseFields = normaliseFields;
const node_util_1 = require("node:util");
const redact_string_1 = require("./redact-string");
exports.TRUNCATION_MARKER = '…[truncated]';
exports.UNREADABLE = '[unreadable]';
exports.CIRCULAR = '[circular]';
exports.TRUNCATED = '[truncated]';
const MAX_TYPE = 100;
const MAX_CODE = 100;
const MAX_MESSAGE = 2000;
const MAX_STACK = 8000;
const MAX_STACK_FRAMES = 50;
/** Error levels kept: the error itself is depth 1, so at most four nested causes. */
const MAX_ERROR_DEPTH = 5;
const MAX_AGGREGATE_ERRORS = 10;
/** How deep `normaliseFields` looks for an Error inside a caller's fields. */
exports.MAX_FIELD_DEPTH = 8;
exports.unreadable = Symbol('unreadable');
const GENERIC_TYPE_NAMES = new Set(['', 'Object', 'Error']);
/** Property read that survives a throwing getter or Proxy trap. */
function read(source, key) {
    try {
        return source[key];
    }
    catch {
        return exports.unreadable;
    }
}
const isObject = (value) => typeof value === 'object' && value !== null;
exports.isObject = isObject;
function isError(value) {
    try {
        return value instanceof Error || node_util_1.types.isNativeError(value);
    }
    catch {
        return false; // a Proxy whose getPrototypeOf trap throws
    }
}
function truncate(text, max) {
    return text.length <= max ? text : text.slice(0, max - exports.TRUNCATION_MARKER.length) + exports.TRUNCATION_MARKER;
}
/** Message-like text: redacted first so a secret cut in half by the bound cannot survive as a prefix. */
const boundedText = (text, max) => truncate((0, redact_string_1.sanitizeString)(text), max);
function boundStack(stack) {
    const kept = [];
    let frames = 0;
    let cutFrames = false;
    for (const line of (0, redact_string_1.sanitizeString)(stack).split('\n')) {
        if (/^\s+at /.test(line) && ++frames > MAX_STACK_FRAMES) {
            cutFrames = true;
            break;
        }
        kept.push(line);
    }
    if (cutFrames)
        kept.push(exports.TRUNCATION_MARKER);
    return truncate(kept.join('\n'), MAX_STACK);
}
/** The constructor name, else `name`, else `type` (what a pre-serialised or JSON round-tripped error carries). */
function typeName(source) {
    const ctor = read(source, 'constructor');
    const ctorName = typeof ctor === 'function' ? read(ctor, 'name') : undefined;
    for (const candidate of [ctorName, read(source, 'name'), read(source, 'type')]) {
        if (candidate === exports.unreadable)
            return exports.UNREADABLE;
        // A bare Error or plain object says nothing, so a more specific `name` (an AbortError) wins over it.
        if (typeof candidate === 'string' && !GENERIC_TYPE_NAMES.has(candidate))
            return boundedText(candidate, MAX_TYPE);
    }
    return 'Error';
}
/** A real Error, or an object carrying a string `message`: axios's `toJSON()` output, an error that went through JSON. */
function isErrorLike(value) {
    return isError(value) || ((0, exports.isObject)(value) && typeof read(value, 'message') === 'string');
}
function describeNonError(value) {
    if (!(0, exports.isObject)(value) && typeof value !== 'function')
        return String(value);
    // Never String(value): that would run a caller's toString (or print a function's source).
    try {
        return Object.prototype.toString.call(value);
    }
    catch {
        return exports.UNREADABLE;
    }
}
function fromNonError(value) {
    return { type: typeof value, message: boundedText(describeNonError(value), MAX_MESSAGE) };
}
function readText(source, key, bound) {
    const value = read(source, key);
    if (value === exports.unreadable)
        return exports.UNREADABLE;
    return typeof value === 'string' ? bound(value) : undefined;
}
function readStatus(source) {
    for (const key of ['status', 'statusCode']) {
        const value = read(source, key);
        if (typeof value === 'number' && Number.isFinite(value))
            return value;
    }
    return undefined;
}
function readCode(source) {
    const value = read(source, 'code');
    if (value === exports.unreadable)
        return exports.UNREADABLE;
    if (typeof value === 'string')
        return boundedText(value, MAX_CODE);
    return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}
function node(value, depth, path) {
    if (value === exports.unreadable)
        return exports.UNREADABLE;
    if ((0, exports.isObject)(value) && path.has(value))
        return exports.CIRCULAR;
    if (depth > MAX_ERROR_DEPTH)
        return exports.TRUNCATED;
    return fromValue(value, depth, path);
}
function readErrors(source, depth, path) {
    const list = read(source, 'errors');
    if (list === exports.unreadable)
        return { errors: [exports.UNREADABLE] };
    if (!Array.isArray(list))
        return {};
    const length = read(list, 'length');
    if (typeof length !== 'number' || length <= 0)
        return {};
    const shown = Math.min(length, MAX_AGGREGATE_ERRORS);
    const errors = [];
    for (let i = 0; i < shown; i++)
        errors.push(node(read(list, i), depth + 1, path));
    return length > shown ? { errors, errors_truncated: length - shown } : { errors };
}
function fromValue(value, depth, path) {
    if (!isErrorLike(value))
        return fromNonError(value);
    path.add(value);
    try {
        const stack = readText(value, 'stack', boundStack);
        const code = readCode(value);
        const status = readStatus(value);
        const cause = read(value, 'cause');
        return {
            type: typeName(value),
            message: readText(value, 'message', (text) => boundedText(text, MAX_MESSAGE)) ?? '',
            ...(stack === undefined ? {} : { stack }),
            ...(code === undefined ? {} : { code }),
            ...(status === undefined ? {} : { status }),
            ...(cause === undefined || cause === null ? {} : { cause: node(cause, depth + 1, path) }),
            ...readErrors(value, depth, path),
        };
    }
    finally {
        path.delete(value);
    }
}
/**
 * Serializer for the `err` field: an allowlist, not a filter. Only the keys of
 * `SerializedError` are ever copied, so `config`, `request`, `response`,
 * `headers`, `body`, `data` and every other own or enumerable property are
 * dropped by construction, for real Errors and for pre-serialised look-alikes
 * alike. A caller's `toJSON` is never called.
 */
function serializeError(value) {
    return fromValue(value, 1, new Set());
}
/** An array, or an object with no prototype beyond `Object`: data, as opposed to a class instance. */
const isWalkable = (value) => {
    if (Array.isArray(value))
        return true;
    try {
        const proto = Object.getPrototypeOf(value);
        return proto === Object.prototype || proto === null;
    }
    catch {
        return false;
    }
};
exports.isWalkable = isWalkable;
function walk(value, depth, path) {
    if (isError(value))
        return serializeError(value);
    if (!(0, exports.isObject)(value) || !(0, exports.isWalkable)(value))
        return value;
    if (path.has(value))
        return exports.CIRCULAR;
    if (depth > exports.MAX_FIELD_DEPTH)
        return exports.TRUNCATED;
    path.add(value);
    try {
        if (Array.isArray(value)) {
            const length = read(value, 'length');
            const items = [];
            for (let i = 0; typeof length === 'number' && i < length; i++)
                items.push(readField(value, i, depth, path));
            return items;
        }
        return Object.fromEntries(Object.keys(value).map((key) => [key, readField(value, key, depth, path)]));
    }
    catch {
        return exports.UNREADABLE;
    }
    finally {
        path.delete(value);
    }
}
function readField(source, key, depth, path) {
    const value = read(source, key);
    return value === exports.unreadable ? exports.UNREADABLE : walk(value, depth + 1, path);
}
/**
 * Makes every Error inside caller fields safe before pino sees it: pino's
 * stringifier would otherwise emit an Error's enumerable properties (an axios
 * error's `config.headers.Authorization`). The `err` key always goes through
 * `serializeError`, whatever it holds; an Error anywhere else, however deeply
 * nested in plain objects and arrays, is replaced by the same allowlisted form.
 */
function normaliseFields(fields) {
    const path = new Set([fields]);
    const entries = [];
    for (const key of Object.keys(fields)) {
        const value = read(fields, key);
        if (value === undefined)
            continue;
        entries.push([key, value === exports.unreadable ? exports.UNREADABLE : key === 'err' ? serializeError(value) : walk(value, 1, path)]);
    }
    // fromEntries defines own properties, so a hostile `__proto__` key stays data instead of reassigning the prototype.
    return Object.fromEntries(entries);
}
