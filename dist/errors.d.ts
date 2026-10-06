export type LogConfigErrorCode = 'INVALID_LOG_LEVEL' | 'INVALID_ARGUMENT' | 'INVALID_HEARTBEAT_INTERVAL';
export declare class LogConfigError extends Error {
    readonly code: LogConfigErrorCode;
    constructor(code: LogConfigErrorCode, message: string);
}
