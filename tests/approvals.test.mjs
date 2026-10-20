import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { ApprovalQueue } from '../src/approvals.mjs';
import { AuditStore } from '../src/audit.mjs';
import { guardedToolCall } from '../src/monitor.mjs';
import { evaluatePolicy } from '../src/policy.mjs';
import { createDemoAdapters } from '../src/tools.mjs';
import { createBlackBoxServer } from '../src/server.mjs';

async function fixture(fn) {
  const root = mkdtempSync(join(tmpdir(), 'blackbox-approvals-'));
  const workspaceRoot = join(root, 'workspace'); mkdirSync(workspaceRoot);
  const store = new AuditStore(join(root, 'audit.jsonl'));
  try { await fn({root, workspaceRoot, store}); }
  finally { rmSync(root, {recursive:true, force:true}); }
}
const write = (ctx, args, approvalQueue) => guardedToolCall({
  tool:'file.write', args, store:ctx.store, workspaceRoot:ctx.workspaceRoot,
  agentId:'test-agent', runId:'test-run', execute:createDemoAdapters(ctx.workspaceRoot)['file.write'],
  requestApproval:approvalQueue ? req => approvalQueue.wait(req) : undefined
});

async function eventually(fn, maxMs=1000) {
  const start=Date.now();
  while (Date.now() - start < maxMs) {
    const found = await fn();
    if (found) return found;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  throw new Error('Timed out waiting for asynchronous approval request');
}

test('policy allows review only for bounded new top-level text notes', () => fixture(async ctx => {
  const good = {path:'approved-note.txt',content:'public demo note'};
  assert.equal(evaluatePolicy('file.write',good,ctx.workspaceRoot).decision,'review');
  for (const bad of [
    {path:'.env', content:'secret'}, {path:'../escape.txt',content:'x'},
    {path:'nested/file.txt',content:'x'}, {path:'private.key',content:'x'},
    {path:'note.txt',content:'x'.repeat(2100)}, {path:'note.txt',content:''}
  ]) assert.equal(evaluatePolicy('file.write',bad,ctx.workspaceRoot).decision,'block');
  assert.equal(evaluatePolicy('shell.exec',{command:'pwd'},ctx.workspaceRoot).decision,'block');
}));

test('without an approval queue, a reviewable write fails closed and is logged', () => fixture(async ctx => {
  const result=await write(ctx,{path:'unapproved.txt',content:'no'},null);
  assert.equal(result.event.ruleId,'APPROVAL_DENIED');
  assert.equal(result.event.decision,'block');
  assert.equal(existsSync(join(ctx.workspaceRoot,'unapproved.txt')),false);
  assert.deepEqual(ctx.store.list().map(e=>e.decision),['block','review']);
}));

test('approval is single-use, audited, and writes only the reviewed content', () => fixture(async ctx => {
  const queue=new ApprovalQueue();
  const args={path:'summary.txt',content:'exact approved text'};
  const run=write(ctx,args,queue);
  const [request] = queue.list();
  assert.ok(request);
  assert.equal(existsSync(join(ctx.workspaceRoot,'summary.txt')),false);
  assert.equal(ctx.store.list()[0].decision,'review');
  args.content='ATTACKER CHANGED CONTENT';
  assert.equal(queue.finish(request.id,true),true);
  assert.equal(queue.finish(request.id,true),false);
  const result=await run;
  assert.equal(result.event.ruleId,'APPROVAL_GRANTED');
  assert.equal(result.event.outcome,'success');
  assert.equal(readFileSync(join(ctx.workspaceRoot,'summary.txt'),'utf8'),'exact approved text');
  assert.equal(ctx.store.list().length,2);
  assert.equal(ctx.store.list()[0].approvalId,request.id);
  assert.doesNotMatch(readFileSync(ctx.store.filename,'utf8'), /exact approved text|ATTACKER CHANGED CONTENT/);
}));

test('denied note request cannot execute and timeouts deny automatically', () => fixture(async ctx => {
  const queue = new ApprovalQueue({timeoutMs:25});
  const denied=write(ctx,{path:'denied.txt',content:'NO'},queue);
  assert.equal(queue.finish(queue.list()[0].id,false),true);
  assert.equal((await denied).event.ruleId,'APPROVAL_DENIED');
  assert.equal(existsSync(join(ctx.workspaceRoot,'denied.txt')),false);
  const expired=write(ctx,{path:'expired.txt',content:'NO'},queue);
  // Keep the event loop alive for the expiry; approval timers are unref'd in production.
  await new Promise(resolve=>setTimeout(resolve,35));
  assert.equal((await expired).event.decision,'block');
  assert.equal(queue.list().length,0);
  assert.deepEqual(readdirSync(ctx.workspaceRoot),[]);
}));

test('approval cannot overwrite an existing file or approve a blocked shell request', () => fixture(async ctx => {
  writeFileSync(join(ctx.workspaceRoot,'existing.txt'),'ORIGINAL');
  const queue = new ApprovalQueue();
  const run=write(ctx,{path:'existing.txt',content:'REPLACE'},queue);
  assert.equal(queue.finish(queue.list()[0].id,true),true);
  const result=await run;
  assert.equal(result.event.outcome,'error');
  assert.equal(readFileSync(join(ctx.workspaceRoot,'existing.txt'),'utf8'),'ORIGINAL');
  const shell=await guardedToolCall({agentId:'test',runId:'test',tool:'shell.exec',args:{command:'pwd'},store:ctx.store,workspaceRoot:ctx.workspaceRoot,
    execute:()=>{ throw new Error('Executed shell'); },requestApproval:req=>queue.wait(req)});
  assert.equal(shell.event.ruleId,'DENY_SHELL');
  assert.equal(queue.list().length,0);
}));

test('HTTP approval round-trip pauses agent, rejects CSRF, and only resumes after approval', () => fixture(async ctx => {
  let chats=0;
  const agentClient = {model:'mock:tools',status:async()=>({ready:true,reachable:true,model:'mock:tools'}),
    chat:async()=> ++chats===1 ? {role:'assistant',tool_calls:[{type:'function',function:{name:'write_note',arguments:{path:'api-note.txt',content:'Approved from HTTP'}}}]}
      : {role:'assistant',content:'Note created after review.'}};
  const {server,approvalQueue}=createBlackBoxServer({dataFile:ctx.store.filename,workspaceRoot:ctx.workspaceRoot,agentClient});
  server.listen(0,'127.0.0.1'); await once(server,'listening');
  const base=`http://127.0.0.1:${server.address().port}`;
  const jsonHeaders={Origin:base,'Content-Type':'application/json'};
  try {
    const run=fetch(base+'/api/agent/run',{method:'POST',headers:jsonHeaders,body:JSON.stringify({prompt:'Write note'})});
    const request=await eventually(async()=>{
      const body=await (await fetch(base+'/api/approvals')).json();
      return body.pending?.[0];
    });
    assert.equal(existsSync(join(ctx.workspaceRoot,'api-note.txt')),false);
    const endpoint=base+`/api/approvals/${request.id}/decision`;
    assert.equal((await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:'{"decision":"approve"}'})).status,403);
    assert.equal(approvalQueue.list().length,1);
    assert.equal((await fetch(endpoint,{method:'POST',headers:jsonHeaders,body:'{"decision":"whatever"}'})).status,400);
    assert.equal((await fetch(endpoint,{method:'POST',headers:jsonHeaders,body:'{"decision":"approve"}'})).status,200);
    assert.equal((await fetch(endpoint,{method:'POST',headers:jsonHeaders,body:'{"decision":"approve"}'})).status,409);
    const response=await run;
    assert.equal(response.status,200);
    const body=await response.json();
    assert.equal(body.status,'finished');
    assert.equal(body.toolCalls,1);
    assert.equal(body.events[0].ruleId,'APPROVAL_GRANTED');
    assert.equal(readFileSync(join(ctx.workspaceRoot,'api-note.txt'),'utf8'),'Approved from HTTP');
    const activityResponse = await fetch(base + '/api/activity');
    assert.equal(activityResponse.status, 200);
    const { activity } = await activityResponse.json();
    assert.equal(activity.length, 1);
    assert.equal(activity[0].auditEventCount, 2);
    assert.equal(activity[0].ruleId, 'APPROVAL_GRANTED');
    assert.deepEqual(activity[0].events.map(event => event.decision), ['review', 'allow']);
    const pendingFilter = await (await fetch(base + '/api/activity?decision=review')).json();
    assert.equal(pendingFilter.activity.length, 0);
    const reviewHistory = await (await fetch(base + '/api/activity?decision=reviewed')).json();
    assert.equal(reviewHistory.activity.length, 1);
    const stats = await (await fetch(base + '/api/stats')).json();
    assert.equal(stats.total, 1);
    assert.equal(stats.auditEvents, 2);
    assert.equal(stats.allowed, 1);
    assert.equal(stats.pending, 0);

  } finally {
    await new Promise(resolve=>server.close(resolve));
  }
}));
