"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.serializeError = serializeError;
/**
 * Serializer for the `err` field.
 *
 * TODO(PKG-203 S3): normalise causes, codes and non-Error throws. Minimal until then.
 */
function serializeError(value) {
    if (value instanceof Error) {
        return { type: value.name, message: value.message, stack: value.stack };
    }
    return { type: 'NonError', message: String(value) };
}
