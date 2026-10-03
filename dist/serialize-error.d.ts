import type { LogFields } from './types';
export declare const TRUNCATION_MARKER = "\u2026[truncated]";
export declare const UNREADABLE = "[unreadable]";
export declare const CIRCULAR = "[circular]";
export declare const TRUNCATED = "[truncated]";
/** How deep `sanitize` walks a caller's fields. */
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
 * Message-like text, redacted and then bounded to `max`. Redaction runs on at most `2 * max` characters, so a
 * 50 MB string costs the same as a 2 `max` one; anything cut ends in the truncation marker.
 */
export declare function boundedText(text: string, max: number): string;
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
 * Prepares caller fields for `sanitize`: the `err` key always goes through `serializeError`, whatever it holds, so
 * what is logged under it is the allowlisted form; undefined values are dropped. Everything else is left to
 * `sanitize`, which serialises an Error found anywhere inside the fields the same way and owns every bound.
 */
export declare function normaliseFields(fields: LogFields): LogFields;
