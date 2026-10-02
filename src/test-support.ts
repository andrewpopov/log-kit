import type { DestinationStream } from 'pino';

export interface CapturedLines extends DestinationStream {
  readonly lines: Record<string, unknown>[];
}

/** In-memory destination: one parsed object per emitted line. */
export function captureStream(): CapturedLines {
  const lines: Record<string, unknown>[] = [];
  return {
    lines,
    write(chunk: string) {
      for (const line of chunk.split('\n')) {
        if (line.length > 0) lines.push(JSON.parse(line) as Record<string, unknown>);
      }
    },
  };
}
