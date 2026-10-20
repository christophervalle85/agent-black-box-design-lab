import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditStore } from '../src/audit.mjs';
import { groupAuditEvents, filterActivity } from '../src/activity.mjs';
import { ApprovalQueue } from '../src/approvals.mjs';
import { guardedToolCall } from '../src/monitor.mjs';
import { createDemoAdapters } from '../src/tools.mjs';

async function fixture(fn) {
  const root = mkdtempSync(join(tmpdir(), 'blackbox-activity-'));
  const workspaceRoot = join(root, 'workspace'); mkdirSync(workspaceRoot);
  const store = new AuditStore(join(root, 'audit.jsonl'));
  try { await fn({ root, store, workspaceRoot }); }
  finally { rmSync(root, { recursive: true, force: true }); }
}

const requestedWrite = (ctx, queue, args, runId) => guardedToolCall({
  agentId: 'test', runId, tool: 'file.write', args, store: ctx.store,
  workspaceRoot: ctx.workspaceRoot, execute: createDemoAdapters(ctx.workspaceRoot)['file.write'],
  requestApproval: req => queue.wait(req)
});

test('groups review and denial into one tool request while preserving immutable audit entries', () => fixture(async ctx => {
  const queue = new ApprovalQueue();
  const promise = requestedWrite(ctx, queue, { path: 'denied.txt', content: 'No' }, 'run-1');
  const rawPending = ctx.store.list()[0];
  assert.equal(ctx.store.stats().total, 1);
  assert.equal(ctx.store.stats().pending, 1);
  assert.equal(ctx.store.activity()[0].decision, 'review');
  assert.equal(queue.finish(queue.list()[0].id, false), true);
  await promise;
  const raw = ctx.store.list();
  const [activity] = ctx.store.activity();
  assert.equal(raw.length, 2);
  assert.equal(activity.auditEventCount, 2);
  assert.equal(activity.events[0].decision, 'review');
  assert.equal(activity.events[1].ruleId, 'APPROVAL_DENIED');
  assert.equal(activity.id, rawPending.id);
  assert.equal(activity.latestEventId, raw[0].id);
  assert.notEqual(activity.latestEventId, activity.id);
  assert.equal(activity.decision, 'block');
  assert.equal(activity.ruleId, 'APPROVAL_DENIED');
  assert.deepEqual(ctx.store.stats(), {
    total: 1, auditEvents: 2, allowed: 0, blocked: 1, pending: 0,
    errors: 0, highRisk: 0, runs: 1,
    window: 'Tool requests represented in latest 1,000 audit events'
  });
  assert.deepEqual(ctx.store.activity({decision:'review'}), []);
  assert.equal(ctx.store.activity({decision:'reviewed'}).length, 1);
  assert.equal(ctx.store.activity({decision:'block'}).length, 1);
  assert.deepEqual(JSON.parse(readFileSync(ctx.store.filename,'utf8').trim().split('\n')[0]), rawPending);
}));

test('approved write counts once and later unrelated tool request remains distinct', () => fixture(async ctx => {
  const queue = new ApprovalQueue();
  const promise = requestedWrite(ctx, queue, { path: 'approved.txt', content: 'yes' }, 'run-2');
  queue.finish(queue.list()[0].id, true);
  await promise;
  await guardedToolCall({
    agentId: 'test', runId: 'run-2', tool: 'shell.exec', args: { command: 'pwd' },
    store: ctx.store, workspaceRoot: ctx.workspaceRoot, execute: async () => { throw new Error('shell executed'); }
  });
  assert.equal(ctx.store.list().length, 3);
  assert.equal(ctx.store.activity().length, 2);
  assert.deepEqual(ctx.store.activity().map(item => item.decision), ['block', 'allow']);
  assert.equal(ctx.store.stats().total, 2);
  assert.equal(ctx.store.stats().auditEvents, 3);
  assert.equal(ctx.store.stats().allowed, 1);
  assert.equal(ctx.store.stats().blocked, 1);
  assert.equal(ctx.store.stats().runs, 1);
  assert.equal(ctx.store.activity({ runId: 'other' }).length, 0);
  assert.equal(ctx.store.activity({decision:'reviewed'}).length, 1);
}));

test('grouping does not mutate data, counts standalone legacy events and filters only final state', () => {
  const pending = {id:'initial',approvalId:'initial',timestamp:'2026-10-12T14:00:00Z',decision:'review',outcome:'pending',runId:'r',tool:'file.write'};
  const final = {id:'final',approvalId:'initial',timestamp:'2026-10-12T14:00:02Z',decision:'block',outcome:'blocked',runId:'r',tool:'file.write'};
  const older = {id:'standalone',timestamp:'2026-10-12T13:58:00Z',decision:'allow',outcome:'success',runId:'r',tool:'file.read'};
  const raw=[final,pending,older];
  const copy=JSON.stringify(raw);
  const groups=groupAuditEvents(raw);
  assert.equal(groups.length,2);
  assert.deepEqual(groups.map(g=>g.id), ['initial','standalone']);
  assert.equal(groups[0].startedAt, pending.timestamp);
  assert.equal(groups[0].timestamp, final.timestamp);
  assert.equal(filterActivity(groups,'review').length,0);
  assert.equal(filterActivity(groups,'reviewed').length,1);
  assert.equal(filterActivity(groups,'allow')[0].id,'standalone');
  assert.equal(JSON.stringify(raw),copy);
});


test('interleaved request lifecycles are ordered by latest activity, not first appearance', () => {
  const pending = {id:'pending',approvalId:'req-A',timestamp:'2026-10-12T14:00:00Z',decision:'review'};
  const standalone = {id:'req-B',timestamp:'2026-10-12T14:00:01Z',decision:'allow'};
  const resolved = {id:'resolved',approvalId:'req-A',timestamp:'2026-10-12T14:00:02Z',decision:'block'};
  const grouped = groupAuditEvents([resolved,standalone,pending]);
  assert.deepEqual(grouped.map(g=>g.id), ['req-A','req-B']);
  assert.deepEqual(grouped[0].events.map(e=>e.id), ['pending','resolved']);
});
