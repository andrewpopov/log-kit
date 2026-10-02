import { types } from 'node:util';
import { classifyKey, DEFAULT_REDACT_POLICY } from './redact-policy';
import type { RedactPolicy } from './redact-policy';
import { REDACTED, sanitizeString } from './redact-string';
import {
  CIRCULAR,
  MAX_FIELD_DEPTH,
  TRUNCATED,
  UNREADABLE,
  isError,
  isObject,
  isWalkable,
  read,
  serializeError,
  unreadable,
} from './serialize-error';

export { sanitizeString };

const OMITTED = '[omitted]';
const MAX_KEYS = 200;
const MAX_ITEMS = 100;

/** A function or symbol: dropped from an object or array rather than rendered. */
const DROP = Symbol('drop');

interface Walk {
  readonly policy: RedactPolicy;
  /** The objects on the way down to the current node, for cycle detection. */
  readonly ancestors: Set<object>;
}

/** Where a node sits: how deep, under which keys (arrays add none), and whether it is inside a body. */
interface Position {
  readonly depth: number;
  readonly keys: readonly string[];
  readonly inBody: boolean;
}

const isCounterValue = (value: unknown): boolean =>
  value === null || value === undefined || ['number', 'bigint', 'boolean'].includes(typeof value);

/**
 * What an object property becomes. The key decides first: a credential key redacts whatever it holds, so an allowed
 * path can never expose one. Inside a body, only a value whose path is allowed, or that leads to one, survives.
 */
function sanitizeProperty(key: string, value: unknown, walk: Walk, parent: Position): unknown {
  if (typeof value === 'function' || typeof value === 'symbol') return DROP;
  const keyClass = classifyKey(key, walk.policy);
  if (keyClass === 'secret') return REDACTED;
  if (keyClass === 'counter' && !isCounterValue(value)) return REDACTED;

  const keys = [...parent.keys, key];
  const dotted = keys.join('.');
  const inBody = parent.inBody || keyClass === 'body';
  if (inBody && walk.policy.allowPaths.has(dotted)) return sanitizeValue(value, walk, { depth: parent.depth + 1, keys, inBody: false });
  if (inBody && !(walk.policy.allowPrefixes.has(dotted) && isObject(value) && isWalkable(value))) {
    return value === undefined ? DROP : OMITTED;
  }
  return sanitizeValue(value, walk, { depth: parent.depth + 1, keys, inBody });
}

function sanitizeObject(source: object, walk: Walk, at: Position): unknown {
  let keys: string[];
  try {
    keys = Object.keys(source);
  } catch {
    return UNREADABLE;
  }
  const entries: [string, unknown][] = [];
  for (const key of keys.slice(0, MAX_KEYS)) {
    const raw = read(source, key);
    const value = raw === unreadable ? UNREADABLE : sanitizeProperty(key, raw, walk, at);
    if (value !== DROP) entries.push([sanitizeString(key), value]);
  }
  if (keys.length > MAX_KEYS) entries.push([TRUNCATED, keys.length - MAX_KEYS]);
  // fromEntries defines own properties, so a hostile `__proto__` key stays data instead of reassigning the prototype.
  return Object.fromEntries(entries);
}

/** A list item or Map side. Inside a body only a container may be descended into; a bare value there is body content. */
function sanitizeElement(item: unknown, walk: Walk, at: Position): unknown {
  const deeper = { ...at, depth: at.depth + 1 };
  if (at.inBody && !isObject(item)) return typeof item === 'function' || typeof item === 'symbol' ? DROP : OMITTED;
  return sanitizeValue(item, walk, deeper);
}

function sanitizeItems(items: Iterable<unknown>, walk: Walk, at: Position): unknown[] {
  const out: unknown[] = [];
  for (const item of items) {
    if (out.length >= MAX_ITEMS) {
      out.push(TRUNCATED);
      break;
    }
    const value = sanitizeElement(item, walk, at);
    if (value !== DROP) out.push(value);
  }
  return out;
}

function sanitizeArray(source: unknown[], walk: Walk, at: Position): unknown[] {
  const length = read(source, 'length');
  const items: unknown[] = [];
  for (let i = 0; typeof length === 'number' && i < Math.min(length, MAX_ITEMS + 1); i++) {
    const item = read(source, i);
    items.push(item === unreadable ? UNREADABLE : item);
  }
  // Items are read once up front (a getter or hole is read exactly once), then bounded and sanitised like any list.
  return sanitizeItems(items, walk, at);
}

/** A Map entry is `[key, value]`; a string key applies the same key policy as an object property would. */
function sanitizeMap(source: Map<unknown, unknown>, walk: Walk, at: Position): unknown[] {
  const pairs: unknown[] = [];
  for (const [key, value] of Map.prototype.entries.call(source) as IterableIterator<[unknown, unknown]>) {
    if (pairs.length >= MAX_ITEMS) {
      pairs.push(TRUNCATED);
      break;
    }
    if (typeof key === 'string') {
      const entry = sanitizeProperty(key, value, walk, at);
      if (entry !== DROP) pairs.push([sanitizeString(key), entry]);
    } else {
      const sanitisedKey = sanitizeElement(key, walk, at);
      const sanitisedValue = sanitizeElement(value, walk, at);
      if (sanitisedKey !== DROP && sanitisedValue !== DROP) pairs.push([sanitisedKey, sanitisedValue]);
    }
  }
  return pairs;
}

const byteLengthOf = (view: object): number => {
  const length = read(view, 'byteLength');
  return typeof length === 'number' ? length : 0;
};

/** Built-ins that have a safe, fixed rendering. `undefined` means: not one of them, walk it as an object. */
function sanitizeBuiltin(value: object): unknown {
  if (ArrayBuffer.isView(value) || types.isAnyArrayBuffer(value)) return `[binary ${byteLengthOf(value)} bytes]`;
  if (types.isDate(value)) {
    const time = Date.prototype.getTime.call(value);
    return Number.isNaN(time) ? null : Date.prototype.toISOString.call(value);
  }
  if (types.isStringObject(value)) return sanitizeString(String.prototype.valueOf.call(value));
  if (types.isNumberObject(value)) return Number.prototype.valueOf.call(value);
  if (types.isBooleanObject(value)) return Boolean.prototype.valueOf.call(value);
  if (types.isBigIntObject(value) || types.isSymbolObject(value)) return DROP;
  if (value instanceof URL) {
    const href = read(value, 'href');
    return typeof href === 'string' ? sanitizeString(href) : UNREADABLE;
  }
  return undefined;
}

function sanitizeValue(value: unknown, walk: Walk, at: Position): unknown {
  if (typeof value === 'string') return sanitizeString(value);
  if (typeof value === 'function' || typeof value === 'symbol') return DROP;
  if (!isObject(value)) return value;
  if (isError(value)) return serializeError(value);
  if (walk.ancestors.has(value)) return CIRCULAR;
  walk.ancestors.add(value);
  try {
    const builtin = sanitizeBuiltin(value);
    if (builtin !== undefined) return builtin;
    if (at.depth > MAX_FIELD_DEPTH) return TRUNCATED;
    if (Array.isArray(value)) return sanitizeArray(value, walk, at);
    if (types.isMap(value)) return sanitizeMap(value, walk, at);
    if (types.isSet(value)) return sanitizeItems(Set.prototype.values.call(value) as IterableIterator<unknown>, walk, at);
    return sanitizeObject(value, walk, at);
  } catch {
    return UNREADABLE;
  } finally {
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
export function sanitize<T>(value: T, policy: RedactPolicy = DEFAULT_REDACT_POLICY): T {
  const result = sanitizeValue(value, { policy, ancestors: new Set() }, { depth: 0, keys: [], inBody: false });
  return (result === DROP ? undefined : result) as T;
}
