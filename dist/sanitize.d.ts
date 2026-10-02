/**
 * The single choke point every caller-supplied value passes through before it
 * reaches output: merge objects, child bindings and messages.
 *
 * TODO(PKG-203 S2): replace with redaction. Identity until then.
 */
export declare function sanitize<T>(value: T): T;
