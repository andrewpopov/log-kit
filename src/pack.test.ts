import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

const pkgRoot = join(__dirname, '..');
const pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8')) as {
  files: string[];
  exports: Record<string, string | { types: string; default: string }>;
};

describe('packed package', () => {
  it('ships the schema and declares dist, and exports the schema file', () => {
    // dist/ is built after the test step in `verify`; scripts/verify-pack.mjs asserts it in the real tarball.
    const [{ files }] = JSON.parse(
      execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: pkgRoot, encoding: 'utf8' }),
    ) as { files: { path: string }[] }[];
    expect(files.map((f) => f.path)).toContain('schema/log-line.json');
    expect(pkg.files).toEqual(expect.arrayContaining(['dist', 'schema']));
    expect(pkg.exports['./schema/log-line.json']).toBe('./schema/log-line.json');
  });
});
