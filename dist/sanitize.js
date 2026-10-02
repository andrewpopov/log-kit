"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.sanitize = sanitize;
exports.sanitizeString = sanitizeString;
/**
 * The single choke point every caller-supplied value passes through before it
 * reaches output: merge objects, child bindings and messages.
 *
 * TODO(PKG-203 S3): replace with redaction. Identity until then.
 */
function sanitize(value) {
    return value;
}
/**
 * Redaction for one string: error messages and stacks pass through here.
 *
 * TODO(PKG-203 S3): replace with redaction. Identity until then.
 */
function sanitizeString(value) {
    return value;
}
