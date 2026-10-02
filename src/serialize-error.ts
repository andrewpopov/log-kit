import { types } from 'node:util';
import { sanitizeString } from './sanitize';
import type { LogFields } from './types';

export const TRUNCATION_MARKER = '…[truncated]';
const UNREADABLE = '[unreadable]';
const CIRCULAR = '[circular]';
const TRUNCATED = '[truncated]';

const MAX_TYPE = 100;
const MAX_CODE = 100;
const MAX_MESSAGE = 2000;
const MAX_STACK = 8000;
const MAX_STACK_FRAMES = 50;
/** Error levels kept: the error itself is depth 1, so at most four nested causes. */
const MAX_ERROR_DEPTH = 5;
const MAX_AGGREGATE_ERRORS = 10;
/** How deep `normaliseFields` looks for an Error inside a caller's fields. */
const MAX_FIELD_DEPTH = 8;

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

const unreadable = Symbol('unreadable');
const GENERIC_TYPE_NAMES: ReadonlySet<string> = new Set(['', 'Object', 'Error']);

/** Property read that survives a throwing getter or Proxy trap. */
function read(source: object, key: string | number): unknown {
  try {
    return (source as Record<string | number, unknown>)[key];
  } catch {
    return unreadable;
  }
}

const isObject = (value: unknown): value is object => typeof value === 'object' && value !== null;

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

/** Message-like text: redacted first so a secret cut in half by the bound cannot survive as a prefix. */
const boundedText = (text: string, max: number): string => truncate(sanitizeString(text), max);

function boundStack(stack: string): string {
  const kept: string[] = [];
  let frames = 0;
  let cutFrames = false;
  for (const line of sanitizeString(stack).split('\n')) {
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
    if (typeof candidate === 'string' && !GENERIC_TYPE_NAMES.has(candidate)) return truncate(candidate, MAX_TYPE);
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
  if (typeof value === 'string') return truncate(value, MAX_CODE);
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

const isWalkable = (value: object): boolean => {
  if (Array.isArray(value)) return true;
  try {
    const proto: unknown = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  } catch {
    return false;
  }
};

function walk(value: unknown, depth: number, path: Set<object>): unknown {
  if (isError(value)) return serializeError(value);
  if (!isObject(value) || !isWalkable(value)) return value;
  if (path.has(value)) return CIRCULAR;
  if (depth > MAX_FIELD_DEPTH) return TRUNCATED;
  path.add(value);
  try {
    if (Array.isArray(value)) {
      const length = read(value, 'length');
      const items: unknown[] = [];
      for (let i = 0; typeof length === 'number' && i < length; i++) items.push(readField(value, i, depth, path));
      return items;
    }
    return Object.fromEntries(Object.keys(value).map((key) => [key, readField(value, key, depth, path)]));
  } catch {
    return UNREADABLE;
  } finally {
    path.delete(value);
  }
}

function readField(source: object, key: string | number, depth: number, path: Set<object>): unknown {
  const value = read(source, key);
  return value === unreadable ? UNREADABLE : walk(value, depth + 1, path);
}

/**
 * Makes every Error inside caller fields safe before pino sees it: pino's
 * stringifier would otherwise emit an Error's enumerable properties (an axios
 * error's `config.headers.Authorization`). The `err` key always goes through
 * `serializeError`, whatever it holds; an Error anywhere else, however deeply
 * nested in plain objects and arrays, is replaced by the same allowlisted form.
 */
export function normaliseFields(fields: LogFields): LogFields {
  const path = new Set<object>([fields]);
  const entries: [string, unknown][] = [];
  for (const key of Object.keys(fields)) {
    const value = read(fields, key);
    if (value === undefined) continue;
    entries.push([key, value === unreadable ? UNREADABLE : key === 'err' ? serializeError(value) : walk(value, 1, path)]);
  }
  // fromEntries defines own properties, so a hostile `__proto__` key stays data instead of reassigning the prototype.
  return Object.fromEntries(entries);
}
