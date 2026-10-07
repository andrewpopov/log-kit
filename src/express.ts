import { randomUUID } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { LogConfigError } from './errors';
import { sanitizeString } from './sanitize';
import type { Logger, LogFields } from './types';

declare module 'express-serve-static-core' {
  interface Request {
    /** A child logger carrying this request's `req_id`. Set by `httpLogger`. */
    log: Logger;
  }
  interface Locals {
    /** This request's id, the same value as `req_id` on every line. Set by `httpLogger`. */
    reqId?: string;
  }
}

export interface HttpLoggerOptions {
  readonly logger: Logger;
  /** Path templates (`/users/:id`) used for `http.route` when Express has no matched route, e.g. a 404 or a middleware-served path. */
  readonly routes?: readonly string[];
  /** Exact paths or whole-segment prefixes (`/health` matches `/health` and `/health/live`, never `/healthz`) not logged when status < 400. */
  readonly ignore?: readonly string[];
  /** Header the incoming request id is read from. Defaults to `x-request-id`. */
  readonly reqIdHeader?: string;
}

export const UNMATCHED_ROUTE = '__unmatched__';
const DEFAULT_REQ_ID_HEADER = 'x-request-id';
const REQ_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const METHOD_PATTERN = /^[A-Za-z]{1,16}$/;

const segmentsOf = (path: string): string[] => path.split('/').filter((segment) => segment !== '');

const pathnameOf = (url: string): string => {
  const end = url.search(/[?#]/);
  return end === -1 ? url : url.slice(0, end);
};

/** A template segment starting with `:` matches any one non-empty segment; every other segment must be equal. */
function matchesTemplate(template: string, path: string): boolean {
  const want = segmentsOf(template);
  const have = segmentsOf(path);
  return want.length === have.length && want.every((segment, i) => segment.startsWith(':') || segment === have[i]);
}

/** Whole-segment prefix: `/health` covers `/health` and `/health/x`, not `/healthz`. */
function coversPath(prefix: string, path: string): boolean {
  const want = segmentsOf(prefix);
  const have = segmentsOf(path);
  return want.length <= have.length && want.every((segment, i) => segment === have[i]);
}

function requireTemplates(field: string, value: readonly string[] | undefined): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.startsWith('/'))) {
    throw new LogConfigError('INVALID_ARGUMENT', `${field} must be an array of strings starting with "/"`);
  }
  return value;
}

/** A matched route's template, or undefined when Express has none (no route, or a regexp/array path that is not one template). */
function expressTemplate(req: Request): string | undefined {
  const routePath: unknown = req.route?.path;
  if (typeof routePath !== 'string') return undefined;
  const joined = `${req.baseUrl}${routePath === '/' ? '' : routePath}`;
  return joined === '' ? '/' : joined;
}

/**
 * Never the raw URL. Express does not expose a mount's template: under a mount (`req.baseUrl` non-empty) it reports the
 * concrete `baseUrl` (`/orgs/acme-77`), so a mounted route is a matching declared template or `__unmatched__`, never
 * Express's own joined path. Root-level routes use Express's template.
 */
function routeOf(req: Request, declared: readonly string[]): string {
  const viaDeclared = (): string | undefined => {
    const path = pathnameOf(req.originalUrl);
    return declared.find((template) => matchesTemplate(template, path));
  };
  if (req.baseUrl !== '') return viaDeclared() ?? UNMATCHED_ROUTE;
  return expressTemplate(req) ?? viaDeclared() ?? UNMATCHED_ROUTE;
}

const SENSITIVE_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'user-agent',
  'forwarded',
  'x-forwarded-for',
  'x-real-ip',
]);
const SENSITIVE_HEADER_PARTS = ['auth', 'token', 'key', 'secret', 'session', 'password', 'cookie'];

function requireReqIdHeader(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new LogConfigError('INVALID_ARGUMENT', 'reqIdHeader must be a non-empty string');
  }
  const header = value.toLowerCase();
  if (SENSITIVE_HEADERS.has(header) || SENSITIVE_HEADER_PARTS.some((part) => header.includes(part))) {
    throw new LogConfigError('INVALID_ARGUMENT', 'reqIdHeader must not name a header that can carry a credential or client identity');
  }
  return header;
}

function resolveReqId(req: Request, header: string): string {
  const incoming = req.headers[header];
  // A value that redaction would change looks like a credential, so it is replaced rather than logged as `[REDACTED]`.
  if (typeof incoming === 'string' && REQ_ID_PATTERN.test(incoming) && sanitizeString(incoming) === incoming) return incoming;
  return randomUUID();
}

const levelFor = (status: number): 'error' | 'warn' | 'info' => (status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info');

const isIgnored = (ignore: readonly string[], route: string, path: string, status: number): boolean =>
  status < 400 && ignore.some((entry) => coversPath(entry, route) || coversPath(entry, path));

/**
 * One line per request, from `finish` or `close`, whichever comes first. See the README for every field.
 * A request answered with an error carries `err` only when the app put it on `res.locals.err`.
 */
export function httpLogger(options: HttpLoggerOptions): RequestHandler {
  if (typeof options.logger?.child !== 'function') {
    throw new LogConfigError('INVALID_ARGUMENT', 'logger must be a log-kit Logger');
  }
  const { logger } = options;
  const declared = requireTemplates('routes', options.routes);
  const ignore = requireTemplates('ignore', options.ignore);
  const header = requireReqIdHeader(options.reqIdHeader ?? DEFAULT_REQ_ID_HEADER);

  return (req: Request, res: Response, next: NextFunction): void => {
    const startedAt = process.hrtime.bigint();
    const reqId = resolveReqId(req, header);
    const log = logger.child({ req_id: reqId });
    req.log = log;
    res.locals.reqId = reqId;

    let logged = false;
    const emit = (): void => {
      if (logged) return;
      logged = true;
      const completed = res.writableFinished;
      const status = res.statusCode;
      const route = routeOf(req, declared);
      const path = pathnameOf(req.originalUrl);
      if (completed && isIgnored(ignore, route, path, status)) return;

      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
      const http: LogFields = {
        method: METHOD_PATTERN.test(req.method) ? req.method : 'OTHER',
        route,
        // An aborted request may never have had a status written; the default 200 would read as a completed one.
        ...(completed || res.headersSent ? { status } : {}),
        duration_ms: Math.round(elapsedMs * 1000) / 1000,
        outcome: completed ? 'completed' : 'aborted',
      };
      const fields: LogFields = res.locals.err === undefined ? { http } : { http, err: res.locals.err };
      if (!completed) log.warn(fields, 'request aborted');
      else log[levelFor(status)](fields, 'request completed');
    };

    res.on('finish', emit);
    res.on('close', emit);
    next();
  };
}
