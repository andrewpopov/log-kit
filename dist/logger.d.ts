import pino from 'pino';
import type { CreateLoggerOptions, Logger } from './types';
/** Internal: lets tests capture output through an injected stream instead of patching process.stdout. */
export declare function createLoggerWithStream(options: CreateLoggerOptions, stream: pino.DestinationStream): Logger;
export declare function createLogger(options: CreateLoggerOptions): Logger;
