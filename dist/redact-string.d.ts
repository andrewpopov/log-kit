export declare const REDACTED = "[REDACTED]";
/**
 * Redaction for one string: the final message, string values anywhere in a line, object keys, error messages and
 * stacks. Idempotent, so a value that passes through twice (an already-serialised `err`) reads the same.
 */
export declare function sanitizeString(value: string): string;
