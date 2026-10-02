"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LogConfigError = void 0;
class LogConfigError extends Error {
    constructor(code, message) {
        super(message);
        this.name = 'LogConfigError';
        this.code = code;
    }
}
exports.LogConfigError = LogConfigError;
