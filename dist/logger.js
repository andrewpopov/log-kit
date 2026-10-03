"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createLoggerWithStream = createLoggerWithStream;
exports.createLogger = createLogger;
const pino_1 = __importDefault(require("pino"));
const errors_1 = require("./errors");
const redact_policy_1 = require("./redact-policy");
const reserved_1 = require("./reserved");
const sanitize_1 = require("./sanitize");
const serialize_error_1 = require("./serialize-error");
const types_1 = require("./types");
const SCHEMA_VERSION = 1;
const DEFAULT_LEVEL = 'info';
const isLogLevel = (value) => typeof value === 'string' && types_1.LOG_LEVELS.includes(value);
function resolveLevel(level) {
    if (level !== undefined) {
        if (!isLogLevel(level)) {
            throw new errors_1.LogConfigError('INVALID_LOG_LEVEL', `level must be one of ${types_1.LOG_LEVELS.join(', ')}; got ${String(level)}`);
        }
        return level;
    }
    const fromEnv = process.env.LOG_LEVEL;
    if (fromEnv === undefined || fromEnv === '')
        return DEFAULT_LEVEL;
    if (!isLogLevel(fromEnv)) {
        throw new errors_1.LogConfigError('INVALID_LOG_LEVEL', `LOG_LEVEL must be one of ${types_1.LOG_LEVELS.join(', ')}; got ${JSON.stringify(fromEnv)}`);
    }
    return fromEnv;
}
function requireName(field, value) {
    if (typeof value !== 'string' || value.length === 0) {
        throw new errors_1.LogConfigError('INVALID_ARGUMENT', `${field} must be a non-empty string`);
    }
    return value;
}
function openDestination(destination) {
    if (destination === undefined)
        return pino_1.default.destination({ fd: 1, sync: true });
    return pino_1.default.destination({ dest: requireName('destination.file', destination.file), sync: true });
}
/**
 * A class instance given as the whole fields object or as child bindings would be enumerated before the sanitiser sees
 * it, so it is shown by name instead, under `key`, exactly as one nested in a field is.
 */
const plainFields = (fields, key) => (0, serialize_error_1.isObject)(fields) && !(0, serialize_error_1.isWalkable)(fields) ? { [key]: (0, sanitize_1.describeInstance)(fields) } : fields;
function wrap(base, policy) {
    const method = (level) => (first, msg) => {
        if (typeof first === 'string') {
            base[level]((0, sanitize_1.sanitize)(first, policy));
            return;
        }
        // Pino would special-case a bare Error and stringify its enumerable properties; normalise it ourselves.
        const fields = (0, serialize_error_1.isError)(first) ? { err: first } : plainFields(first, 'fields');
        base[level]((0, reserved_1.relocateReserved)((0, sanitize_1.sanitize)((0, serialize_error_1.normaliseFields)(fields), policy)), (0, sanitize_1.sanitize)(msg, policy));
    };
    return {
        trace: method('trace'),
        debug: method('debug'),
        info: method('info'),
        warn: method('warn'),
        error: method('error'),
        fatal: method('fatal'),
        child: (bindings) => wrap(base.child((0, reserved_1.relocateReserved)((0, sanitize_1.sanitize)((0, serialize_error_1.normaliseFields)(plainFields(bindings, 'bindings')), policy))), policy),
    };
}
function resolveConfig(options) {
    return {
        app: requireName('app', options.app),
        proc: options.proc === undefined ? undefined : requireName('proc', options.proc),
        level: resolveLevel(options.level),
        policy: (0, redact_policy_1.resolveRedactPolicy)(options.redact),
    };
}
function build({ app, proc, level, policy }, stream) {
    const base = (0, pino_1.default)({
        level,
        base: proc === undefined ? { v: SCHEMA_VERSION, app } : { v: SCHEMA_VERSION, app, proc },
        timestamp: pino_1.default.stdTimeFunctions.isoTime,
        formatters: { level: (label) => ({ level: label }) },
        // `err` arrives already normalised by `serializeError`. Pino ships its own `err` serializer by default and
        // would re-serialise our output (keeping aggregateErrors, dropping the allowlist), so it is replaced, not removed.
        serializers: { err: (alreadySerialised) => alreadySerialised },
    }, stream);
    return wrap(base, policy);
}
/** Internal: lets tests capture output through an injected stream instead of patching process.stdout. */
function createLoggerWithStream(options, stream) {
    return build(resolveConfig(options), stream);
}
function createLogger(options) {
    // Resolve before opening a file descriptor so a bad option cannot leak one.
    const config = resolveConfig(options);
    return build(config, openDestination(options.destination));
}
