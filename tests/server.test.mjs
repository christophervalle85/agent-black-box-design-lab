import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createBlackBoxServer } from '../src/server.mjs';

test('local API serves stats and enforces same-origin POST', async () => {
  const root = mkdtempSync(join(tmpdir(), 'blackbox-server-'));
  const workspaceRoot = join(root, 'workspace'); mkdirSync(workspaceRoot);
  writeFileSync(join(workspaceRoot, 'notes.txt'), 'hello');
  const { server } = createBlackBoxServer({ workspaceRoot, dataFile: join(root, 'audit.jsonl') });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  try {
    const health = await (await fetch(endpoint + '/api/health')).json();
    assert.equal(health.ok, true);
    const packageVersion=JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
    assert.equal(health.version, packageVersion);
    const bad = await fetch(endpoint + '/api/demo/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(bad.status, 403);
    const accepted = await fetch(endpoint + '/api/demo/run', { method: 'POST', headers: { Origin: endpoint, 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(accepted.status, 200);
    assert.equal((await accepted.json()).total, 9);
    const response = await fetch(endpoint + '/api/events?decision=block');
    const { events } = await response.json();
    assert.equal(events.length, 6);
    assert.ok(events.every(e => e.decision === 'block'));
    const page = await fetch(endpoint + '/');
    assert.equal(page.status, 200);
    assert.match(await page.text(), /Agent Black Box/);
  } finally {
    await new Promise(resolve => server.close(resolve));
    rmSync(root, { recursive: true, force: true });
  }
});

test('model-driven agent endpoint requires origin and returns audited events using a mock model', async () => {
  const root = mkdtempSync(join(tmpdir(), 'blackbox-agent-api-'));
  const workspaceRoot = join(root, 'workspace'); mkdirSync(workspaceRoot);
  writeFileSync(join(workspaceRoot, 'notes.txt'), 'hello model');
  let chatCalls = 0;
  const agentClient = {
    model: 'test:mock',
    status: async () => ({reachable:true,ready:true,model:'test:mock'}),
    chat: async () => ++chatCalls === 1
      ? {role:'assistant',tool_calls:[{type:'function',function:{name:'read_file',arguments:{path:'notes.txt'}}}]}
      : {role:'assistant',content:'I read the local file.'}
  };
  const { server } = createBlackBoxServer({workspaceRoot,dataFile:join(root,'audit.jsonl'),agentClient});
  server.listen(0,'127.0.0.1'); await once(server,'listening');
  const endpoint = `http://127.0.0.1:${server.address().port}`;
  const post = (headers, body) => fetch(endpoint + '/api/agent/run', {method:'POST',headers,body});
  try {
    const status = await (await fetch(endpoint + '/api/agent/status')).json();
    assert.equal(status.ready, true);
    assert.equal((await post({'Content-Type':'application/json'}, JSON.stringify({prompt:'read'}))).status,403);
    assert.equal((await post({'Origin':endpoint,'Content-Type':'application/json'}, JSON.stringify({prompt:''}))).status,400);
    const response = await post({'Origin':endpoint,'Content-Type':'application/json'},JSON.stringify({prompt:'Read notes'}));
    assert.equal(response.status,200);
    const data = await response.json();
    assert.equal(data.toolCalls,1);
    assert.equal(data.events[0].ruleId,'ALLOW_WORKSPACE_READ');
    assert.equal(data.answer,'I read the local file.');
    assert.equal((await (await fetch(endpoint + '/api/events')).json()).events.length,1);
    assert.equal((await post({'Origin':endpoint,'Content-Type':'application/json'}, JSON.stringify({prompt:'second'}))).status,429);
  } finally { await new Promise(resolve=>server.close(resolve)); rmSync(root,{recursive:true,force:true}); }
});
