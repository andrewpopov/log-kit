"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UNMATCHED_ROUTE = void 0;
exports.httpLogger = httpLogger;
const node_crypto_1 = require("node:crypto");
const errors_1 = require("./errors");
const sanitize_1 = require("./sanitize");
exports.UNMATCHED_ROUTE = '__unmatched__';
const DEFAULT_REQ_ID_HEADER = 'x-request-id';
const REQ_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const METHOD_PATTERN = /^[A-Za-z]{1,16}$/;
const segmentsOf = (path) => path.split('/').filter((segment) => segment !== '');
const pathnameOf = (url) => {
    const end = url.search(/[?#]/);
    return end === -1 ? url : url.slice(0, end);
};
/** A template segment starting with `:` matches any one non-empty segment; every other segment must be equal. */
function matchesTemplate(template, path) {
    const want = segmentsOf(template);
    const have = segmentsOf(path);
    return want.length === have.length && want.every((segment, i) => segment.startsWith(':') || segment === have[i]);
}
/** Whole-segment prefix: `/health` covers `/health` and `/health/x`, not `/healthz`. */
function coversPath(prefix, path) {
    const want = segmentsOf(prefix);
    const have = segmentsOf(path);
    return want.length <= have.length && want.every((segment, i) => segment === have[i]);
}
function requireTemplates(field, value) {
    if (value === undefined)
        return [];
    if (!Array.isArray(value) || value.some((item) => typeof item !== 'string' || !item.startsWith('/'))) {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', `${field} must be an array of strings starting with "/"`);
    }
    return value;
}
/** A matched route's template, or undefined when Express has none (no route, or a regexp/array path that is not one template). */
function expressTemplate(req) {
    const routePath = req.route?.path;
    if (typeof routePath !== 'string')
        return undefined;
    const joined = `${req.baseUrl}${routePath === '/' ? '' : routePath}`;
    return joined === '' ? '/' : joined;
}
/**
 * Never the raw URL. Express does not expose a mount's template: under a mount (`req.baseUrl` non-empty) it reports the
 * concrete `baseUrl` (`/orgs/acme-77`), so a mounted route is a matching declared template or `__unmatched__`, never
 * Express's own joined path. Root-level routes use Express's template.
 */
function routeOf(req, declared) {
    const viaDeclared = () => {
        const path = pathnameOf(req.originalUrl);
        return declared.find((template) => matchesTemplate(template, path));
    };
    if (req.baseUrl !== '')
        return viaDeclared() ?? exports.UNMATCHED_ROUTE;
    return expressTemplate(req) ?? viaDeclared() ?? exports.UNMATCHED_ROUTE;
}
const SENSITIVE_HEADERS = new Set([
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
function requireReqIdHeader(value) {
    if (typeof value !== 'string' || value.trim() === '') {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', 'reqIdHeader must be a non-empty string');
    }
    const header = value.toLowerCase();
    if (SENSITIVE_HEADERS.has(header) || SENSITIVE_HEADER_PARTS.some((part) => header.includes(part))) {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', 'reqIdHeader must not name a header that can carry a credential or client identity');
    }
    return header;
}
function resolveReqId(req, header) {
    const incoming = req.headers[header];
    // A value that redaction would change looks like a credential, so it is replaced rather than logged as `[REDACTED]`.
    if (typeof incoming === 'string' && REQ_ID_PATTERN.test(incoming) && (0, sanitize_1.sanitizeString)(incoming) === incoming)
        return incoming;
    return (0, node_crypto_1.randomUUID)();
}
const levelFor = (status) => (status >= 500 ? 'error' : status >= 400 ? 'warn' : 'info');
const isIgnored = (ignore, route, path, status) => status < 400 && ignore.some((entry) => coversPath(entry, route) || coversPath(entry, path));
/**
 * One line per request, from `finish` or `close`, whichever comes first. See the README for every field.
 * A request answered with an error carries `err` only when the app put it on `res.locals.err`.
 */
function httpLogger(options) {
    if (typeof options.logger?.child !== 'function') {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', 'logger must be a log-kit Logger');
    }
    const { logger } = options;
    const declared = requireTemplates('routes', options.routes);
    const ignore = requireTemplates('ignore', options.ignore);
    const header = requireReqIdHeader(options.reqIdHeader ?? DEFAULT_REQ_ID_HEADER);
    return (req, res, next) => {
        const startedAt = process.hrtime.bigint();
        const reqId = resolveReqId(req, header);
        const log = logger.child({ req_id: reqId });
        req.log = log;
        res.locals.reqId = reqId;
        let logged = false;
        const emit = () => {
            if (logged)
                return;
            logged = true;
            const completed = res.writableFinished;
            const status = res.statusCode;
            const route = routeOf(req, declared);
            const path = pathnameOf(req.originalUrl);
            if (completed && isIgnored(ignore, route, path, status))
                return;
            const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
            const http = {
                method: METHOD_PATTERN.test(req.method) ? req.method : 'OTHER',
                route,
                // An aborted request may never have had a status written; the default 200 would read as a completed one.
                ...(completed || res.headersSent ? { status } : {}),
                duration_ms: Math.round(elapsedMs * 1000) / 1000,
                outcome: completed ? 'completed' : 'aborted',
            };
            const fields = res.locals.err === undefined ? { http } : { http, err: res.locals.err };
            if (!completed)
                log.warn(fields, 'request aborted');
            else
                log[levelFor(status)](fields, 'request completed');
        };
        res.on('finish', emit);
        res.on('close', emit);
        next();
    };
}
