export interface SerializedError {
    readonly type: string;
    readonly message: string;
    readonly stack?: string;
}
/**
 * Serializer for the `err` field.
 *
 * TODO(PKG-203 S3): normalise causes, codes and non-Error throws. Minimal until then.
 */
export declare function serializeError(value: unknown): SerializedError;
