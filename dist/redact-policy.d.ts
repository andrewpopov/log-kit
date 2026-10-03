import type { RedactOptions } from './types';
/** What a key says about its value. */
export type KeyClass = 'secret' | 'body' | 'counter' | 'plain';
/** The key policy for one logger: the built-in lists plus whatever the app extended them with. */
export interface RedactPolicy {
    /** Extra key names from `redact.keys`, already normalised. Matched whole, never as a substring. */
    readonly extraKeys: ReadonlySet<string>;
    /** `redact.allowPaths` entries, as dotted paths. */
    readonly allowPaths: ReadonlySet<string>;
    /** Every proper dotted prefix of an allowed path: the nodes a body walk must descend through to reach it. */
    readonly allowPrefixes: ReadonlySet<string>;
}
export declare const normaliseKey: (key: string) => string;
export declare function classifyKey(rawKey: string, policy: RedactPolicy): KeyClass;
export declare const DEFAULT_REDACT_POLICY: RedactPolicy;
/** Validates `createLogger({ redact })` and merges it over the built-in policy. Options can only add to it. */
export declare function resolveRedactPolicy(options: RedactOptions | undefined): RedactPolicy;
