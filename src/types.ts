export const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'] as const;

export type LogLevel = (typeof LOG_LEVELS)[number];

/** Free-form fields attached to a line. Reserved envelope keys are relocated, see README. */
export type LogFields = Record<string, unknown>;

export type LogDestination = { readonly file: string };

export interface CreateLoggerOptions {
  /** Service name, emitted as `app` on every line. */
  readonly app: string;
  /** Minimum level. Defaults to a valid `LOG_LEVEL`, otherwise `info`. */
  readonly level?: LogLevel;
  /** Process role within the app (`web`, `worker`, ...), emitted as `proc`. */
  readonly proc?: string;
  /** Defaults to synchronous stdout. `{ file }` is the opt-in LOG_FILE path for hosts without pm2. */
  readonly destination?: LogDestination;
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
