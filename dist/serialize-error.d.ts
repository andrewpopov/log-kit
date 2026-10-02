import type { LogFields } from './types';
export declare const TRUNCATION_MARKER = "\u2026[truncated]";
export declare const UNREADABLE = "[unreadable]";
export declare const CIRCULAR = "[circular]";
export declare const TRUNCATED = "[truncated]";
/** How deep `normaliseFields` looks for an Error inside a caller's fields. */
export declare const MAX_FIELD_DEPTH = 8;
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
export declare const unreadable: unique symbol;
/** Property read that survives a throwing getter or Proxy trap. */
export declare function read(source: object, key: string | number): unknown;
export declare const isObject: (value: unknown) => value is object;
export declare function isError(value: unknown): value is Error;
/**
 * Serializer for the `err` field: an allowlist, not a filter. Only the keys of
 * `SerializedError` are ever copied, so `config`, `request`, `response`,
 * `headers`, `body`, `data` and every other own or enumerable property are
 * dropped by construction, for real Errors and for pre-serialised look-alikes
 * alike. A caller's `toJSON` is never called.
 */
export declare function serializeError(value: unknown): SerializedError;
/** An array, or an object with no prototype beyond `Object`: data, as opposed to a class instance. */
export declare const isWalkable: (value: object) => boolean;
/**
 * Makes every Error inside caller fields safe before pino sees it: pino's
 * stringifier would otherwise emit an Error's enumerable properties (an axios
 * error's `config.headers.Authorization`). The `err` key always goes through
 * `serializeError`, whatever it holds; an Error anywhere else, however deeply
 * nested in plain objects and arrays, is replaced by the same allowlisted form.
 */
export declare function normaliseFields(fields: LogFields): LogFields;
