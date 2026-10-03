import type { RedactPolicy } from './redact-policy';
import { sanitizeString } from './redact-string';
export { sanitizeString };
/** The constructor name, read from the prototype's own data property so no caller code runs. `[Object]` when there is none. */
export declare function describeInstance(value: object): string;
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
export declare function sanitize<T>(value: T, policy?: RedactPolicy): T;
