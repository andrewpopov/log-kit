import type { DestinationStream } from 'pino';

export interface CapturedLines extends DestinationStream {
  readonly lines: Record<string, unknown>[];
  /** Every byte written, for asserting a value never reached output in any form. */
  raw: string;
}

/** In-memory destination: one parsed object per emitted line. */
export function captureStream(): CapturedLines {
  const lines: Record<string, unknown>[] = [];
  return {
    lines,
    raw: '',
    write(chunk: string) {
      this.raw += chunk;
      for (const line of chunk.split('\n')) {
        if (line.length > 0) lines.push(JSON.parse(line) as Record<string, unknown>);
      }
    },
  };
}
