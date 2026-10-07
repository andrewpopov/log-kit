import { readdirSync, readFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import express from 'express';
import type { Express, ErrorRequestHandler } from 'express';
import { afterEach, describe, expect, it } from 'vitest';
import { httpLogger } from './express';
import type { HttpLoggerOptions } from './express';
import { createLoggerWithStream } from './logger';
import { captureStream } from './test-support';

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((done) => server.close(() => done()))));
});

interface Harness {
  readonly out: ReturnType<typeof captureStream>;
  readonly port: number;
  readonly app: Express;
}

async function start(
  routes: (app: Express) => void,
  options: Partial<HttpLoggerOptions> = {},
): Promise<Harness> {
  const out = captureStream();
  const logger = createLoggerWithStream({ app: 'demo' }, out);
  const app = express();
  app.use(httpLogger({ logger, ...options }));
  routes(app);
  const server = await new Promise<Server>((ready) => {
    const listening = app.listen(0, '127.0.0.1', () => ready(listening));
  });
  servers.push(server);
  return { out, app, port: (server.address() as AddressInfo).port };
}

interface Reply {
  readonly status: number;
  readonly body: string;
}

function get(port: number, path: string, headers: Record<string, string> = {}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, headers, agent: false }, (res) => {
      let body = '';
      res.on('data', (chunk: Buffer) => (body += chunk.toString()));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

/** A response's `close` can land just after the client has its body; wait for the line count to settle. */
const settle = () => new Promise<void>((done) => setTimeout(done, 50));

const httpOf = (line: Record<string, unknown> | undefined) => line?.http as Record<string, unknown>;

describe('httpLogger', () => {
  it('logs 200 at info, 404 at warn and 500 at error, one line each', async () => {
    const { out, port } = await start((app) => {
      app.get('/ok', (_req, res) => void res.send('ok'));
      app.get('/boom', (_req, res) => void res.status(500).send('no'));
    });
    await get(port, '/ok');
    await get(port, '/missing');
    await get(port, '/boom');
    await settle();
    expect(out.lines.map((l) => [l.level, httpOf(l).status, l.msg])).toEqual([
      ['info', 200, 'request completed'],
      ['warn', 404, 'request completed'],
      ['error', 500, 'request completed'],
    ]);
    expect(httpOf(out.lines[0])).toMatchObject({ method: 'GET', outcome: 'completed' });
  });

  it('emits exactly one line per request even when finish and close both fire', async () => {
    const { out, port } = await start((app) => app.get('/ok', (_req, res) => void res.send('ok')));
    for (let i = 0; i < 5; i++) await get(port, '/ok');
    await settle();
    expect(out.lines).toHaveLength(5);
  });

  it('logs a request closed before finish as aborted and never also as completed', async () => {
    let release: () => void = () => undefined;
    const held = new Promise<void>((done) => (release = done));
    const { out, port } = await start((app) =>
      app.get('/slow', (_req, res) => void held.then(() => res.send('late'))),
    );
    await new Promise<void>((done) => {
      const req = httpRequest({ host: '127.0.0.1', port, path: '/slow', agent: false });
      req.on('error', () => undefined);
      req.on('socket', (socket) => socket.on('connect', () => setTimeout(() => (req.destroy(), done()), 30)));
      req.end();
    });
    await settle();
    release();
    await settle();
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0]).toMatchObject({ level: 'warn', msg: 'request aborted', http: { outcome: 'aborted' } });
    expect(httpOf(out.lines[0])).not.toHaveProperty('status');
  });

  it('reports a monotonic, non-negative duration', async () => {
    const { out, port } = await start((app) =>
      app.get('/wait', (_req, res) => void setTimeout(() => res.send('x'), 40)),
    );
    await get(port, '/wait');
    await settle();
    const duration = httpOf(out.lines[0]).duration_ms as number;
    expect(duration).toBeGreaterThanOrEqual(30);
    expect(duration).toBeLessThan(5000);
  });

  it('uses the route template, the declared template, or the unmatched sentinel, never the raw URL', async () => {
    const { out, port } = await start(
      (app) => {
        app.get('/users/:id', (_req, res) => void res.send('u'));
        const router = express.Router();
        router.get('/:slug', (_req, res) => void res.send('p'));
        app.use('/pages', router);
        app.use('/static', (_req, res) => void res.send('s'));
      },
      { routes: ['/static/:file', '/pages/:slug'] },
    );
    await get(port, '/users/12345');
    await get(port, '/pages/about');
    await get(port, '/static/secret-file-9');
    await get(port, '/nope/abc123');
    await settle();
    expect(out.lines.map((l) => httpOf(l).route)).toEqual(['/users/:id', '/pages/:slug', '/static/:file', '__unmatched__']);
    for (const raw of ['12345', 'secret-file-9', 'abc123']) expect(out.raw).not.toContain(raw);
  });

  it('prefers a declared template over a mount path that carries a concrete id', async () => {
    const { out, port } = await start(
      (app) => {
        const router = express.Router({ mergeParams: true });
        router.get('/items', (_req, res) => void res.send('i'));
        app.use('/orgs/:org', router);
      },
      { routes: ['/orgs/:org/items'] },
    );
    await get(port, '/orgs/acme-77/items');
    await settle();
    expect(httpOf(out.lines[0]).route).toBe('/orgs/:org/items');
    expect(out.raw).not.toContain('acme-77');
  });

  it.each([
    ['no declaration', undefined, ['__unmatched__']],
    ['a non-matching declaration', ['/orgs/:org/other'], ['__unmatched__']],
  ])('logs a parameterised mount with %s as __unmatched__, never the concrete value', async (_name, routes, expected) => {
    const { out, port } = await start(
      (app) => {
        const router = express.Router({ mergeParams: true });
        router.get('/items', (_req, res) => void res.send('i'));
        app.use('/orgs/:org', router);
      },
      routes === undefined ? {} : { routes },
    );
    await get(port, '/orgs/acme-77/items');
    await settle();
    expect(out.lines.map((l) => httpOf(l).route)).toEqual(expected);
    expect(out.raw).not.toContain('acme-77');
  });

  it('keeps Express template for a root-level parameterised route', async () => {
    const { out, port } = await start((app) => app.get('/users/:id', (_req, res) => void res.send('u')));
    await get(port, '/users/777');
    await settle();
    expect(httpOf(out.lines[0]).route).toBe('/users/:id');
    expect(out.raw).not.toContain('777');
  });

  it('never logs query strings', async () => {
    const { out, port } = await start((app) => app.get('/search', (_req, res) => void res.send('r')));
    await get(port, '/search?q=hello-world&page=2');
    await settle();
    expect(out.raw).not.toContain('hello-world');
    expect(out.raw).not.toContain('page=2');
    expect(out.raw).not.toContain('?');
  });

  describe('ignore', () => {
    const routes = (app: Express) => {
      app.get('/health', (_req, res) => void res.send('ok'));
      app.get('/health/live', (_req, res) => void res.send('ok'));
      app.get('/healthz', (_req, res) => void res.send('ok'));
      app.get('/health-check-admin', (_req, res) => void res.send('ok'));
      app.get('/health-bad', (_req, res) => void res.status(503).send('down'));
    };

    it('skips a healthy exact path and whole-segment children, not look-alike paths', async () => {
      const { out, port } = await start(routes, { ignore: ['/health'] });
      await get(port, '/health');
      await get(port, '/health?probe=1');
      await get(port, '/health/live');
      await get(port, '/healthz');
      await get(port, '/health-check-admin');
      await settle();
      expect(out.lines.map((l) => httpOf(l).route)).toEqual(['/healthz', '/health-check-admin']);
    });

    it('always logs a failing health path at error', async () => {
      const { out, port } = await start(
        (app) => app.get('/health', (_req, res) => void res.status(500).send('down')),
        { ignore: ['/health'] },
      );
      await get(port, '/health');
      await settle();
      expect(out.lines).toHaveLength(1);
      expect(out.lines[0]).toMatchObject({ level: 'error', http: { status: 500, route: '/health' } });
    });

    it('logs a client abort on an ignored health path once as aborted', async () => {
      let release: () => void = () => undefined;
      const held = new Promise<void>((done) => (release = done));
      const { out, port } = await start((app) => app.get('/health', (_req, res) => void held.then(() => res.send('ok'))), {
        ignore: ['/health'],
      });
      await new Promise<void>((done) => {
        const req = httpRequest({ host: '127.0.0.1', port, path: '/health', agent: false });
        req.on('error', () => undefined);
        req.on('socket', (socket) => socket.on('connect', () => setTimeout(() => (req.destroy(), done()), 30)));
        req.end();
      });
      await settle();
      release();
      await settle();
      expect(out.lines).toHaveLength(1);
      expect(out.lines[0]).toMatchObject({ msg: 'request aborted', http: { route: '/health', outcome: 'aborted' } });
    });

    it('also logs a health path answering 4xx', async () => {
      const { out, port } = await start((app) => app.get('/health', (_req, res) => void res.status(401).send('no')), {
        ignore: ['/health'],
      });
      await get(port, '/health');
      await settle();
      expect(out.lines[0]).toMatchObject({ level: 'warn' });
    });
  });

  describe('req_id', () => {
    const setup = () =>
      start((app) =>
        app.get('/id', (req, res) => {
          req.log.info('inside handler');
          res.send(String(res.locals.reqId));
        }),
      );

    it('passes a valid header through to the lines, res.locals and req.log', async () => {
      const { out, port } = await setup();
      const reply = await get(port, '/id', { 'x-request-id': 'abc-123.DEF_9' });
      await settle();
      expect(reply.body).toBe('abc-123.DEF_9');
      expect(out.lines.map((l) => l.req_id)).toEqual(['abc-123.DEF_9', 'abc-123.DEF_9']);
      expect(out.lines[0]?.msg).toBe('inside handler');
    });

    it.each([
      ['too long', 'a'.repeat(65)],
      ['injection-looking', 'a"},"level":"fatal'],
      ['with spaces', 'a b'],
      ['token-looking', 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz'],
    ])('regenerates an id that is %s', async (_name, value) => {
      const { out, port } = await setup();
      const reply = await get(port, '/id', { 'x-request-id': value });
      await settle();
      expect(reply.body).toMatch(/^[0-9a-f-]{36}$/);
      expect(out.lines[1]?.req_id).toBe(reply.body);
      expect(out.raw).not.toContain(value);
    });

    it('reads a custom header and generates when it is absent', async () => {
      const { out, port } = await start((app) => app.get('/id', (_req, res) => void res.send('x')), {
        reqIdHeader: 'X-Correlation-Id',
      });
      await get(port, '/id', { 'x-correlation-id': 'corr-1' });
      await get(port, '/id');
      await settle();
      expect(out.lines[0]?.req_id).toBe('corr-1');
      expect(out.lines[1]?.req_id).toMatch(/^[0-9a-f-]{36}$/);
    });
  });

  describe('reqIdHeader validation', () => {
    const logger = createLoggerWithStream({ app: 'demo' }, captureStream());
    it.each([
      'authorization', 'Proxy-Authorization', 'cookie', 'Set-Cookie', 'user-agent', 'forwarded', 'X-Forwarded-For', 'x-real-ip',
      'x-api-key', 'x-auth-id', 'x-access-token', 'x-client-secret', 'x-session-id', 'x-password-hint', 'x-cookie-id',
    ])('refuses sensitive header %s', (name) => {
      expect(() => httpLogger({ logger, reqIdHeader: name })).toThrowError(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    });
    it.each(['', '   ', 42 as unknown as string])('refuses empty or non-string header %j', (name) => {
      expect(() => httpLogger({ logger, reqIdHeader: name })).toThrowError(expect.objectContaining({ code: 'INVALID_ARGUMENT' }));
    });
    it('accepts the default and x-correlation-id', () => {
      expect(() => httpLogger({ logger })).not.toThrow();
      expect(() => httpLogger({ logger, reqIdHeader: 'x-correlation-id' })).not.toThrow();
    });
  });

  describe('errors', () => {
    it('includes res.locals.err through the error serialiser, and nothing for a bare 500', async () => {
      const handler: ErrorRequestHandler = (err: Error, _req, res, _next) => {
        res.locals.err = err;
        res.status(500).send('failed');
      };
      const { out, port } = await start((app) => {
        app.get('/throws', () => {
          throw new Error('kaput token=hunter2hunter2');
        });
        app.get('/plain', (_req, res) => void res.status(500).send('x'));
        app.use(handler);
      });
      await get(port, '/throws');
      await get(port, '/plain');
      await settle();
      expect(out.lines[0]?.err).toMatchObject({ type: 'Error' });
      expect(out.raw).not.toContain('hunter2hunter2');
      expect(out.lines[1]).not.toHaveProperty('err');
    });
  });

  it('never lets request secrets reach output', async () => {
    const { out, port } = await start((app) => {
      app.get('/login/:password', (_req, res) => void res.send('x'));
      app.get('/other/:token', (_req, res) => void res.send('x'));
    });
    const headers = {
      authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.canary-bearer-payload.canary-bearer-sig',
      cookie: 'session=canary-cookie-value; theme=dark',
      'x-api-key': 'canary-header-key',
      'user-agent': 'canary-agent/1.0',
    };
    await get(port, '/login/canary-password-segment?api_key=canary-query-key&token=canary-query-token', headers);
    await get(port, '/other/canary-token-segment', headers);
    await get(port, '/unknown/canary-unknown-segment?password=canary-q-pass', headers);
    await settle();
    expect(out.lines).toHaveLength(3);
    expect(out.raw).not.toMatch(/canary|eyJhbGci|Bearer|session=|dark|127\.0\.0\.1/);
  });

  it('rejects bad options at construction', () => {
    const logger = createLoggerWithStream({ app: 'demo' }, captureStream());
    expect(() => httpLogger({ logger, ignore: ['health'] })).toThrow(/ignore/);
    expect(() => httpLogger({ logger, routes: [1 as unknown as string] })).toThrow(/routes/);
    expect(() => httpLogger({ logger: undefined as never })).toThrow(/logger/);
  });
});

describe('core entry point', () => {
  it('has no module outside express.ts that references express (the pack script proves it on the installed tarball)', () => {
    const offenders = readdirSync(__dirname)
      .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && file !== 'express.ts')
      .filter((file) => /from 'express'|require\('express'\)|import\('express'\)/.test(readFileSync(join(__dirname, file), 'utf8')));
    expect(offenders).toEqual([]);
  });
});
