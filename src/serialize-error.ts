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
export function serializeError(value: unknown): SerializedError {
  if (value instanceof Error) {
    return { type: value.name, message: value.message, stack: value.stack };
  }
  return { type: 'NonError', message: String(value) };
}
