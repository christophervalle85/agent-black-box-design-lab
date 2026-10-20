import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditStore } from '../src/audit.mjs';
import { guardedToolCall, redact } from '../src/monitor.mjs';
import { runDemo } from '../src/demo.mjs';

async function fixture(fn) {
  const root = mkdtempSync(join(tmpdir(), 'blackbox-monitor-'));
  const workspaceRoot = join(root, 'workspace'); mkdirSync(workspaceRoot);
  writeFileSync(join(workspaceRoot, 'notes.txt'), 'harmless demo note');
  const store = new AuditStore(join(root, 'audit.jsonl'));
  try { await fn({ store, root, workspaceRoot }); } finally { rmSync(root, { recursive: true, force: true }); }
}
test('denied action never invokes the execution callback', async () => fixture(async ({ store, workspaceRoot }) => {
  let called = false;
  const { event, result } = await guardedToolCall({
    store, workspaceRoot, agentId: 'test', runId: 'one', tool: 'shell.exec',
    args: { command: 'echo unsafe' }, execute: async () => { called = true; return { value: 'bad' }; }
  });
  assert.equal(called, false);
  assert.equal(event.outcome, 'blocked');
  assert.equal(result, null);
  assert.equal(store.list()[0].ruleId, 'DENY_SHELL');
}));
test('allowed action invokes adapter and persists a successful event', async () => fixture(async ({ store, workspaceRoot }) => {
  let called = 0;
  const { event, result } = await guardedToolCall({
    store, workspaceRoot, agentId: 'test', runId: 'two', tool: 'file.read', args: { path: 'notes.txt' },
    execute: async () => { called++; return { value: 'data', summary: 'Allowed result' }; }
  });
  assert.equal(called, 1);
  assert.equal(result, 'data');
  assert.equal(event.decision, 'allow');
  assert.equal(store.stats().allowed, 1);
}));
test('failed tool execution records error without raw stacktrace', async () => fixture(async ({ store, workspaceRoot }) => {
  const { event, error } = await guardedToolCall({
    store, workspaceRoot, agentId: 'test', runId: 'three', tool: 'file.read', args: { path: 'notes.txt' },
    execute: async () => { throw new Error('TOP_SECRET_DO_NOT_LOG'); }
  });
  assert.equal(event.outcome, 'error');
  assert.match(error.message, /TOP_SECRET/);
  assert.doesNotMatch(readFileSync(store.filename, 'utf8'), /TOP_SECRET/);
}));
test('redactor masks example API credentials', () => {
  assert.doesNotMatch(redact('token=sk-EXAMPLESECRET12345678'), /EXAMPLESECRET/);
  assert.doesNotMatch(redact('password=super-secret'), /super-secret/);
});
test('demo generates nine recorded decisions and no real network activity', async () => fixture(async ({ store, workspaceRoot }) => {
  const result = await runDemo({ store, workspaceRoot });
  assert.equal(result.total, 9);
  assert.equal(result.allowed, 3);
  assert.equal(result.blocked, 6);
  assert.equal(result.errors, 1);
  assert.equal(store.list().length, 9);
  assert.equal(store.list().filter(e => e.outcome === 'simulated').length, 1);
  assert.doesNotMatch(readFileSync(store.filename, 'utf8'), /EXAMPLESECRET/);
}));

test('cancellation during approval cannot create a falsely successful approval event', async () => fixture(async ({ store, workspaceRoot }) => {
  const controller = new AbortController();
  let executed = false;
  const result = await guardedToolCall({
    store, workspaceRoot, agentId:'test', runId:'cancel-approval',
    tool:'file.write', args:{path:'cancelled.txt',content:'SYNTHETIC_CANCEL_CONTENT'},
    signal:controller.signal,
    requestApproval:async()=>{controller.abort();return {approved:true};},
    execute:async()=>{executed=true;return {value:'unexpected'};}
  });
  assert.equal(executed,false);
  assert.equal(result.event.decision,'block');
  assert.equal(result.event.outcome,'blocked');
  assert.equal(result.event.ruleId,'MCP_CANCELLED');
  assert.equal(result.result,null);
  store.verify();
  assert.doesNotMatch(readFileSync(store.filename,'utf8'),/SYNTHETIC_CANCEL_CONTENT/);
}));

test('abort before adapter dispatch records MCP_CANCELLED, never invokes executor', async () => fixture(async ({ store, workspaceRoot }) => {
  const controller = new AbortController();
  controller.abort();
  let executed = false;
  const result = await guardedToolCall({
    store, workspaceRoot, agentId:'test', runId:'cancel-before',
    tool:'file.read', args:{path:'notes.txt'}, signal:controller.signal,
    execute:async()=>{executed=true;return {value:'unexpected'};}
  });
  assert.equal(executed,false);
  assert.equal(result.event.ruleId,'MCP_CANCELLED');
  assert.equal(result.event.outcome,'blocked');
  store.verify();
}));

test('cancel while adapter executes classifies a possibly committed write as UNKNOWN', async () => fixture(async ({ store, workspaceRoot }) => {
  const controller = new AbortController();
  let executed = false;
  const result = await guardedToolCall({
    store, workspaceRoot, agentId:'test', runId:'cancel-after-dispatch',
    tool:'file.write', args:{path:'cancelled.txt',content:'SYNTHETIC_CANCEL_CONTENT'},
    signal:controller.signal, requestApproval:async()=>({approved:true}),
    execute:async()=>{executed=true;controller.abort();return {value:'committed',summary:'Tool succeeded.'};}
  });
  assert.equal(executed,true);
  assert.equal(result.result,null);
  assert.equal(result.event.outcome,'error');
  assert.equal(result.event.ruleId,'MCP_OUTCOME_UNKNOWN');
  assert.equal(store.list().filter(event=>event.ruleId==='MCP_OUTCOME_UNKNOWN').length,1);
  store.verify();
  const audit=readFileSync(store.filename,'utf8');
  assert.doesNotMatch(audit,/SYNTHETIC_CANCEL_CONTENT|Tool succeeded\./);
}));
