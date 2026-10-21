import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createBlackBoxServer } from '../src/server.mjs';

test('my guided showcase serves static resources without adding tool or approval endpoints', async () => {
  const root = mkdtempSync(join(tmpdir(), 'bbx-showcase-'));
  const workspaceRoot = join(root, 'workspace');
  mkdirSync(workspaceRoot);
  const { server } = createBlackBoxServer({workspaceRoot, dataFile:join(root,'audit.jsonl')});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const [route, type, snippet] of [
      ['/showcase', 'text/html', 'Illustrative walkthrough'],
      ['/showcase.js', 'application/javascript', 'showcase-scenarios.mjs'],
      ['/showcase.css', 'text/css', 'design-system.css'],
      ['/design-system.css', 'text/css', 'prefers-reduced-motion'],
      ['/showcase-scenarios.mjs', 'application/javascript', 'SHOWCASE_MODE']
    ]) {
      const response = await fetch(base + route);
      assert.equal(response.status, 200, `GET ${route}`);
      assert.match(response.headers.get('content-type') ?? '', new RegExp(type));
      assert.match(response.headers.get('content-security-policy') ?? '', /script-src 'self'/);
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.match(await response.text(), new RegExp(snippet, 'i'));
    }
    assert.equal((await fetch(base + '/api/health')).status, 200);
    assert.equal((await fetch(base + '/showcase', {method:'POST'})).status, 404);
    assert.equal((await fetch(base + '/docs/SECURITY.md')).status, 404);
    assert.equal((await fetch(base + '/showcase/anything')).status, 404);
    assert.equal((await (await fetch(base + '/api/events')).json()).events.length, 0);
  } finally {
    await new Promise(resolve => server.close(resolve));
    rmSync(root, {recursive:true, force:true});
  }
});
