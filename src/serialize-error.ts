import { types } from 'node:util';
import { sanitizeString } from './redact-string';
import type { LogFields } from './types';

export const TRUNCATION_MARKER = '…[truncated]';
export const UNREADABLE = '[unreadable]';
export const CIRCULAR = '[circular]';
export const TRUNCATED = '[truncated]';

const MAX_TYPE = 100;
const MAX_CODE = 100;
const MAX_MESSAGE = 2000;
const MAX_STACK = 8000;
const MAX_STACK_FRAMES = 50;
/** Error levels kept: the error itself is depth 1, so at most four nested causes. */
const MAX_ERROR_DEPTH = 5;
const MAX_AGGREGATE_ERRORS = 10;
/** How deep `sanitize` walks a caller's fields. */
export const MAX_FIELD_DEPTH = 8;

/** The only keys an error ever emits. Everything else on the source is ignored, whatever its name. */
export interface SerializedError {
  readonly type: string;
  readonly message: string;
  readonly stack?: string;
  readonly code?: string | number;
  readonly status?: number;
  readonly cause?: SerializedErrorRef;
  readonly errors?: readonly SerializedErrorRef[];
  readonly errors_truncated?: number;
}

/** A nested error, or a marker string: `[circular]`, `[truncated]` or `[unreadable]`. */
export type SerializedErrorRef = SerializedError | string;

export const unreadable = Symbol('unreadable');
const GENERIC_TYPE_NAMES: ReadonlySet<string> = new Set(['', 'Object', 'Error']);

/** Property read that survives a throwing getter or Proxy trap. */
export function read(source: object, key: string | number): unknown {
  try {
    return (source as Record<string | number, unknown>)[key];
  } catch {
    return unreadable;
  }
}

export const isObject = (value: unknown): value is object => typeof value === 'object' && value !== null;

export function isError(value: unknown): value is Error {
  try {
    return value instanceof Error || types.isNativeError(value);
  } catch {
    return false; // a Proxy whose getPrototypeOf trap throws
  }
}

function truncate(text: string, max: number): string {
  return text.length <= max ? text : text.slice(0, max - TRUNCATION_MARKER.length) + TRUNCATION_MARKER;
}

/** Whitespace, a quote, an angle bracket, a backtick or a backslash: none can be inside a URL or a credential. */
const isBreak = (code: number): boolean =>
  code <= 32 || code === 34 || code === 39 || code === 60 || code === 62 || code === 96 || code === 92;

/** How far back a cut looks for a break. A cut never gives up more than half of `limit` either. */
const MAX_CUT_BACKTRACK = 4096;

/**
 * The first `limit` characters of `text`, cut back to the last break so a word is either whole or gone. A word cut in
 * half loses the context that identifies it: `https://u:secret@host` cut before `@host` no longer has userinfo, and
 * `sk-abc` cut short is too short for its pattern. If there is no break nearby the partial word is dropped back to
 * the edge of the look-back window, so nothing recognisable is ever left half cut.
 */
function cutAtBreak(text: string, limit: number): string {
  const floor = limit - Math.min(MAX_CUT_BACKTRACK, limit >> 1);
  let end = limit;
  while (end > floor && !isBreak(text.charCodeAt(end - 1))) end--;
  return text.slice(0, end);
}

/**
 * Message-like text, redacted and then bounded to `max`. Redaction runs on at most `2 * max` characters, so a
 * 50 MB string costs the same as a 2 `max` one; anything cut ends in the truncation marker.
 */
export function boundedText(text: string, max: number): string {
  if (text.length <= max * 2) return truncate(sanitizeString(text), max);
  const redacted = sanitizeString(cutAtBreak(text, max * 2));
  return redacted.slice(0, max - TRUNCATION_MARKER.length) + TRUNCATION_MARKER;
}

function boundStack(stack: string): string {
  const kept: string[] = [];
  let frames = 0;
  let cutFrames = stack.length > MAX_STACK * 2;
  const input = cutFrames ? cutAtBreak(stack, MAX_STACK * 2) : stack;
  for (const line of sanitizeString(input).split('\n')) {
    if (/^\s+at /.test(line) && ++frames > MAX_STACK_FRAMES) {
      cutFrames = true;
      break;
    }
    kept.push(line);
  }
  if (cutFrames) kept.push(TRUNCATION_MARKER);
  return truncate(kept.join('\n'), MAX_STACK);
}

/** The constructor name, else `name`, else `type` (what a pre-serialised or JSON round-tripped error carries). */
function typeName(source: object): string {
  const ctor = read(source, 'constructor');
  const ctorName = typeof ctor === 'function' ? read(ctor, 'name') : undefined;
  for (const candidate of [ctorName, read(source, 'name'), read(source, 'type')]) {
    if (candidate === unreadable) return UNREADABLE;
    // A bare Error or plain object says nothing, so a more specific `name` (an AbortError) wins over it.
    if (typeof candidate === 'string' && !GENERIC_TYPE_NAMES.has(candidate)) return boundedText(candidate, MAX_TYPE);
  }
  return 'Error';
}

/** A real Error, or an object carrying a string `message`: axios's `toJSON()` output, an error that went through JSON. */
function isErrorLike(value: unknown): value is object {
  return isError(value) || (isObject(value) && typeof read(value, 'message') === 'string');
}

function describeNonError(value: unknown): string {
  if (!isObject(value) && typeof value !== 'function') return String(value);
  // Never String(value): that would run a caller's toString (or print a function's source).
  try {
    return Object.prototype.toString.call(value);
  } catch {
    return UNREADABLE;
  }
}

function fromNonError(value: unknown): SerializedError {
  return { type: typeof value, message: boundedText(describeNonError(value), MAX_MESSAGE) };
}

function readText(source: object, key: string, bound: (text: string) => string): string | undefined {
  const value = read(source, key);
  if (value === unreadable) return UNREADABLE;
  return typeof value === 'string' ? bound(value) : undefined;
}

function readStatus(source: object): number | undefined {
  for (const key of ['status', 'statusCode']) {
    const value = read(source, key);
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return undefined;
}

function readCode(source: object): string | number | undefined {
  const value = read(source, 'code');
  if (value === unreadable) return UNREADABLE;
  if (typeof value === 'string') return boundedText(value, MAX_CODE);
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function node(value: unknown, depth: number, path: Set<object>): SerializedErrorRef {
  if (value === unreadable) return UNREADABLE;
  if (isObject(value) && path.has(value)) return CIRCULAR;
  if (depth > MAX_ERROR_DEPTH) return TRUNCATED;
  return fromValue(value, depth, path);
}

function readErrors(source: object, depth: number, path: Set<object>): Pick<SerializedError, 'errors' | 'errors_truncated'> {
  const list = read(source, 'errors');
  if (list === unreadable) return { errors: [UNREADABLE] };
  if (!Array.isArray(list)) return {};
  const length = read(list, 'length');
  if (typeof length !== 'number' || length <= 0) return {};
  const shown = Math.min(length, MAX_AGGREGATE_ERRORS);
  const errors: SerializedErrorRef[] = [];
  for (let i = 0; i < shown; i++) errors.push(node(read(list, i), depth + 1, path));
  return length > shown ? { errors, errors_truncated: length - shown } : { errors };
}

function fromValue(value: unknown, depth: number, path: Set<object>): SerializedError {
  if (!isErrorLike(value)) return fromNonError(value);
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
  } finally {
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
export function serializeError(value: unknown): SerializedError {
  return fromValue(value, 1, new Set());
}

/** An array, or an object with no prototype beyond `Object`: data, as opposed to a class instance. */
export const isWalkable = (value: object): boolean => {
  if (Array.isArray(value)) return true;
  try {
    const proto: unknown = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
};

/**
 * Prepares caller fields for `sanitize`: the `err` key always goes through `serializeError`, whatever it holds, so
 * what is logged under it is the allowlisted form; undefined values are dropped. Everything else is left to
 * `sanitize`, which serialises an Error found anywhere inside the fields the same way and owns every bound.
 */
export function normaliseFields(fields: LogFields): LogFields {
  const entries: [string, unknown][] = [];
  for (const key of Object.keys(fields)) {
    const value = read(fields, key);
    if (value === undefined) continue;
    entries.push([key, value === unreadable ? UNREADABLE : key === 'err' ? serializeError(value) : value]);
  }
  // fromEntries defines own properties, so a hostile `__proto__` key stays data instead of reassigning the prototype.
  return Object.fromEntries(entries);
}
