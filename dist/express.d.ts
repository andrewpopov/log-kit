import type { RequestHandler } from 'express';
import type { Logger } from './types';
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
export declare const UNMATCHED_ROUTE = "__unmatched__";
/**
 * One line per request, from `finish` or `close`, whichever comes first. See the README for every field.
 * A request answered with an error carries `err` only when the app put it on `res.locals.err`.
 */
export declare function httpLogger(options: HttpLoggerOptions): RequestHandler;
