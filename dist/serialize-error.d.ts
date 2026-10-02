import type { LogFields } from './types';
export declare const TRUNCATION_MARKER = "\u2026[truncated]";
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
export declare function isError(value: unknown): value is Error;
/**
 * Serializer for the `err` field: an allowlist, not a filter. Only the keys of
 * `SerializedError` are ever copied, so `config`, `request`, `response`,
 * `headers`, `body`, `data` and every other own or enumerable property are
 * dropped by construction, for real Errors and for pre-serialised look-alikes
 * alike. A caller's `toJSON` is never called.
 */
export declare function serializeError(value: unknown): SerializedError;
/**
 * Makes every Error inside caller fields safe before pino sees it: pino's
 * stringifier would otherwise emit an Error's enumerable properties (an axios
 * error's `config.headers.Authorization`). The `err` key always goes through
 * `serializeError`, whatever it holds; an Error anywhere else, however deeply
 * nested in plain objects and arrays, is replaced by the same allowlisted form.
 */
export declare function normaliseFields(fields: LogFields): LogFields;
