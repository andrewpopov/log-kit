export type LogConfigErrorCode = 'INVALID_LOG_LEVEL' | 'INVALID_ARGUMENT';

export class LogConfigError extends Error {
  readonly code: LogConfigErrorCode;

  constructor(code: LogConfigErrorCode, message: string) {
    super(message);
    this.name = 'LogConfigError';
    this.code = code;
  }
}
