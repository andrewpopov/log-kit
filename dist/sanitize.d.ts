import type { RedactPolicy } from './redact-policy';
import { sanitizeString } from './redact-string';
export { sanitizeString };
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
export declare function sanitize<T>(value: T, policy?: RedactPolicy): T;
