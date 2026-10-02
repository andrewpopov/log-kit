export type LogConfigErrorCode = 'INVALID_LOG_LEVEL' | 'INVALID_ARGUMENT';
export declare class LogConfigError extends Error {
    readonly code: LogConfigErrorCode;
    constructor(code: LogConfigErrorCode, message: string);
}
