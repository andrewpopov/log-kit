export declare const LOG_LEVELS: readonly ["trace", "debug", "info", "warn", "error", "fatal"];
export type LogLevel = (typeof LOG_LEVELS)[number];
/** Free-form fields attached to a line. Reserved envelope keys are relocated, see README. */
export type LogFields = Record<string, unknown>;
export type LogDestination = {
    readonly file: string;
};
/** Extends the built-in redaction. It can only add to it: no option removes a built-in key rule. */
export interface RedactOptions {
    /** Extra key names whose value is replaced with `[REDACTED]`. Matched whole, after the same normalisation as the built-ins. */
    readonly keys?: readonly string[];
    /**
     * Dotted key paths, from the root of the logged fields, whose value may be logged even inside a body. Without an
     * entry, the value under `body`, `payload`, `data` or `rawBody` is `[omitted]`. See the README.
     */
    readonly allowPaths?: readonly string[];
}
export interface CreateLoggerOptions {
    /** Service name, emitted as `app` on every line. */
    readonly app: string;
    /** Minimum level. Defaults to a valid `LOG_LEVEL`, otherwise `info`. */
    readonly level?: LogLevel;
    /** Process role within the app (`web`, `worker`, ...), emitted as `proc`. */
    readonly proc?: string;
    /** Defaults to synchronous stdout. `{ file }` is the opt-in LOG_FILE path for hosts without pm2. */
    readonly destination?: LogDestination;
    /** Additions to the built-in redaction, see the README. */
    readonly redact?: RedactOptions;
}
export interface LogMethod {
    (msg: string): void;
    (fields: LogFields, msg: string): void;
    /** A bare Error is logged as `err`; `msg` defaults to the error's (bounded) message. */
    (err: Error, msg?: string): void;
}
export interface Logger {
    readonly trace: LogMethod;
    readonly debug: LogMethod;
    readonly info: LogMethod;
    readonly warn: LogMethod;
    readonly error: LogMethod;
    readonly fatal: LogMethod;
    child(bindings: LogFields): Logger;
}
