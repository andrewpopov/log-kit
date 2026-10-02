#!/usr/bin/env node
/**
 * Pack the package, install the tarball into a throwaway consumer and assert:
 *   1. the declared entry points and the JSON schema ship in the tarball;
 *   2. CommonJS require() and native ESM import both resolve the root entry;
 *   3. the schema is reachable through its package export;
 *   4. a logger created from the installed tarball emits a schema-v1 line.
 * Exits non-zero with a clear message on any failure.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = fileURLToPath(new URL('..', import.meta.url));
const pkg = JSON.parse(readFileSync(join(pkgRoot, 'package.json'), 'utf8'));

const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: 'utf8', ...opts });
function fail(message) {
  console.error(`\n[verify:pack] FAIL: ${message}\n`);
  process.exit(1);
}

const REQUIRED_FILES = ['dist/index.js', 'dist/index.d.ts', 'schema/log-line.json'];

const workDir = mkdtempSync(join(tmpdir(), 'log-kit-verify-'));
try {
  console.log('[verify:pack] Building...');
  run('npm', ['run', 'build'], { cwd: pkgRoot, stdio: 'inherit' });

  console.log('[verify:pack] Packing tarball...');
  const [{ filename }] = JSON.parse(
    run('npm', ['pack', '--json', '--pack-destination', workDir], { cwd: pkgRoot }),
  );
  const tarballPath = join(workDir, filename);

  const contents = run('tar', ['-tzf', tarballPath]).split('\n');
  for (const file of REQUIRED_FILES) {
    if (!contents.includes(`package/${file}`)) fail(`${file} is not present in the packed tarball`);
  }
  console.log(`[verify:pack] OK: ${REQUIRED_FILES.join(', ')} ship in tarball`);

  const consumerDir = join(workDir, 'consumer');
  mkdirSync(consumerDir);
  writeFileSync(
    join(consumerDir, 'package.json'),
    JSON.stringify({ name: 'log-kit-consumer', version: '1.0.0', private: true }, null, 2),
  );
  console.log('[verify:pack] Installing tarball into consumer...');
  run('npm', ['install', '--no-audit', '--no-fund', tarballPath], { cwd: consumerDir, stdio: 'inherit' });

  const cjs = `
    const root = require('${pkg.name}');
    if (typeof root.createLogger !== 'function') throw new Error('cjs root export missing');
    const schema = require('${pkg.name}/schema/log-line.json');
    if (!Array.isArray(schema.properties.level.enum)) throw new Error('schema export unusable');
  `;
  run('node', ['-e', cjs], { cwd: consumerDir });
  console.log('[verify:pack] OK: CommonJS require() resolves root and schema');

  const esm = `
    import { createLogger } from '${pkg.name}';
    import schema from '${pkg.name}/schema/log-line.json' with { type: 'json' };
    if (typeof createLogger !== 'function') throw new Error('esm root export missing');
    if (!Array.isArray(schema.properties.level.enum)) throw new Error('schema export unusable');
  `;
  run('node', ['--input-type=module', '-e', esm], { cwd: consumerDir });
  console.log('[verify:pack] OK: native ESM import resolves root and schema');

  const emit = `require('${pkg.name}').createLogger({ app: 'pack-smoke' }).info('hello')`;
  const line = JSON.parse(run('node', ['-e', emit], { cwd: consumerDir }).trim());
  if (line.v !== 1 || line.level !== 'info' || line.app !== 'pack-smoke' || line.msg !== 'hello') {
    fail(`installed logger emitted an unexpected line: ${JSON.stringify(line)}`);
  }
  console.log('[verify:pack] OK: installed logger emits a schema-v1 line');

  console.log('[verify:pack] PASS');
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
} finally {
  rmSync(workDir, { recursive: true, force: true });
}
