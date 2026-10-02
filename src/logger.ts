import pino from 'pino';
import { LogConfigError } from './errors';
import { relocateReserved } from './reserved';
import { sanitize } from './sanitize';
import { serializeError } from './serialize-error';
import { LOG_LEVELS } from './types';
import type { CreateLoggerOptions, LogDestination, LogFields, Logger, LogLevel, LogMethod } from './types';

const SCHEMA_VERSION = 1;
const DEFAULT_LEVEL: LogLevel = 'info';

const isLogLevel = (value: unknown): value is LogLevel =>
  typeof value === 'string' && (LOG_LEVELS as readonly string[]).includes(value);

function resolveLevel(level: LogLevel | undefined): LogLevel {
  if (level !== undefined) {
    if (!isLogLevel(level)) {
      throw new LogConfigError('INVALID_LOG_LEVEL', `level must be one of ${LOG_LEVELS.join(', ')}; got ${String(level)}`);
    }
    return level;
  }
  const fromEnv = process.env.LOG_LEVEL;
  if (fromEnv === undefined || fromEnv === '') return DEFAULT_LEVEL;
  if (!isLogLevel(fromEnv)) {
    throw new LogConfigError(
      'INVALID_LOG_LEVEL',
      `LOG_LEVEL must be one of ${LOG_LEVELS.join(', ')}; got ${JSON.stringify(fromEnv)}`,
    );
  }
  return fromEnv;
}

function requireName(field: string, value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new LogConfigError('INVALID_ARGUMENT', `${field} must be a non-empty string`);
  }
  return value;
}

function openDestination(destination: LogDestination | undefined): pino.DestinationStream {
  if (destination === undefined) return pino.destination({ fd: 1, sync: true });
  return pino.destination({ dest: requireName('destination.file', destination.file), sync: true });
}

function wrap(base: pino.Logger): Logger {
  const method =
    (level: LogLevel): LogMethod =>
    (first: string | LogFields, msg?: string) => {
      if (typeof first === 'string') {
        base[level](sanitize(first));
        return;
      }
      base[level](relocateReserved(sanitize(first)), sanitize(msg));
    };
  return {
    trace: method('trace'),
    debug: method('debug'),
    info: method('info'),
    warn: method('warn'),
    error: method('error'),
    fatal: method('fatal'),
    child: (bindings) => wrap(base.child(relocateReserved(sanitize(bindings)))),
  };
}

interface ResolvedConfig {
  readonly app: string;
  readonly proc: string | undefined;
  readonly level: LogLevel;
}

function resolveConfig(options: CreateLoggerOptions): ResolvedConfig {
  return {
    app: requireName('app', options.app),
    proc: options.proc === undefined ? undefined : requireName('proc', options.proc),
    level: resolveLevel(options.level),
  };
}

function build({ app, proc, level }: ResolvedConfig, stream: pino.DestinationStream): Logger {
  const base = pino(
    {
      level,
      base: proc === undefined ? { v: SCHEMA_VERSION, app } : { v: SCHEMA_VERSION, app, proc },
      timestamp: pino.stdTimeFunctions.isoTime,
      formatters: { level: (label) => ({ level: label }) },
      serializers: { err: serializeError },
    },
    stream,
  );
  return wrap(base);
}

/** Internal: lets tests capture output through an injected stream instead of patching process.stdout. */
export function createLoggerWithStream(options: CreateLoggerOptions, stream: pino.DestinationStream): Logger {
  return build(resolveConfig(options), stream);
}

export function createLogger(options: CreateLoggerOptions): Logger {
  // Resolve before opening a file descriptor so a bad option cannot leak one.
  const config = resolveConfig(options);
  return build(config, openDestination(options.destination));
}
