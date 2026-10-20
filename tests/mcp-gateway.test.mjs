import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createBlackBoxServer } from '../src/server.mjs';
import { readJsonLines, sendJsonLine, McpPeer } from '../src/mcp-wire.mjs';

const project = resolve(import.meta.dirname,'..');
const gateway = join(project,'src/mcp-gateway.mjs');

async function fixture(fn,{dashboard=true}={}) {
  const root=mkdtempSync(join(tmpdir(),'bb-mcp-'));
  const workspaceRoot=join(root,'workspace');mkdirSync(workspaceRoot);
  writeFileSync(join(workspaceRoot,'notes.txt'),'MCP integration test content');
  const dataFile=join(root,'data','audit.jsonl');
  const controller=createBlackBoxServer({dataFile,workspaceRoot,agentClient:{status:async()=>({reachable:false})}});
  if(dashboard){controller.server.listen(0,'127.0.0.1'); await once(controller.server,'listening');}
  const port=dashboard?controller.server.address().port:1;
  const child=spawn(process.execPath,[gateway],{
    cwd:project,env:{...process.env,MCP_WORKSPACE_ROOT:workspaceRoot,MCP_AUDIT_FILE:dataFile,MCP_TOKEN_FILE:controller.tokenFile,MCP_CONTROLLER_PORT:String(port)},
    stdio:['pipe','pipe','pipe']
  });
  let next=1;
  const pending=new Map();const notifications=[];
  const unlisten=readJsonLines(child.stdout,{onMessage:msg=>{
    if(Object.hasOwn(msg,'id')){const p=pending.get(msg.id);if(p){pending.delete(msg.id);p.resolve(msg);}}
    else notifications.push(msg);
  },onError:e=>{for(const p of pending.values())p.reject(e);pending.clear();}});
  const client={
    raw(msg){sendJsonLine(child.stdin,msg);},
    request(method,params={}){
      const id=next++;
      let timer;
      const p=new Promise((resolve,reject)=>{
        pending.set(id,{resolve:x=>{clearTimeout(timer);resolve(x);},reject});
        timer=setTimeout(()=>{pending.delete(id);reject(Error('Timed out waiting for gateway'));},5500);
        sendJsonLine(child.stdin,{jsonrpc:'2.0',id,method,params});
      });
      return {id,p};
    },
    async initialize(){
      const init=await this.request('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'test',version:'1.0'}}).p;
      assert.equal(init.result?.protocolVersion,'2025-11-25');
      this.raw({jsonrpc:'2.0',method:'notifications/initialized'});
      return init;
    }
  };
  try {await fn({root,workspaceRoot,dataFile,controller,client,child,port});}
  finally{
    child.stdin.end();child.kill('SIGTERM');await Promise.race([once(child,'exit').catch(()=>{}),new Promise(r=>setTimeout(r,1800))]);
    unlisten();
    if(dashboard)await new Promise(r=>controller.server.close(r));
    else controller.approvalQueue.close();
    rmSync(root,{recursive:true,force:true});
  }
}

const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function waitForApproval(controller){
  for(let i=0;i<100;i++){const p=controller.approvalQueue.list()[0];if(p)return p;await sleep(20)}
  throw Error('Approval did not arrive');
}

test('MCP stdio initialization gates requests, advertises only approved tools, and forwards real read',()=>fixture(async({client,controller,dataFile})=>{
  const early=await client.request('tools/list').p;
  assert.equal(early.error?.code,-32002);
  const init=await client.initialize();
  assert.deepEqual(init.result.capabilities,{tools:{}});
  const list=await client.request('tools/list').p;
  assert.deepEqual(list.result.tools.map(x=>x.name),['read_note','write_note']);
  const read=await client.request('tools/call',{name:'read_note',arguments:{path:'notes.txt'}}).p;
  assert.match(read.result.content[0].text,/MCP integration test/);
  const secret=await client.request('tools/call',{name:'read_note',arguments:{path:'.env'}}).p;
  assert.equal(secret.result.isError,true);
  assert.match(secret.result.content[0].text,/DENY_SENSITIVE_FILE/);
  const unknown=await client.request('tools/call',{name:'shell_command',arguments:{command:'pwd'}}).p;
  assert.equal(unknown.result.isError,true);
  assert.equal((await client.request('resources/list').p).error.code,-32601);
  const events=readFileSync(dataFile,'utf8');
  assert.match(events,/mcp-stdio/);
  assert.doesNotMatch(events,/MCP integration test content/);
  assert.equal(controller.store.stats().total,3);
}));

test('real downstream note creation waits for dashboard approval; denied and duplicate writes do not execute',()=>fixture(async({client,controller,workspaceRoot,dataFile})=>{
  await client.initialize();
  const first=client.request('tools/call',{name:'write_note',arguments:{path:'approved.txt',content:'approved content'}});
  const pending=await waitForApproval(controller);
  assert.equal(pending.filename,'approved.txt');
  assert.equal(pending.content,'approved content');
  assert.equal(existsSync(join(workspaceRoot,'approved.txt')),false);
  const browser=await fetch(`http://127.0.0.1:${controller.server.address().port}/api/approvals/${pending.id}/decision`,{
    method:'POST',headers:{origin:`http://127.0.0.1:${controller.server.address().port}`,'content-type':'application/json'},
    body:JSON.stringify({decision:'approve'})
  });
  assert.equal(browser.status,200);
  const result=await first.p;
  assert.equal(result.result.isError,undefined);
  assert.equal(readFileSync(join(workspaceRoot,'approved.txt'),'utf8'),'approved content');
  const second=client.request('tools/call',{name:'write_note',arguments:{path:'denied.txt',content:'never here'}});
  const denied=await waitForApproval(controller);
  controller.approvalQueue.finish(denied.id,false);
  const blocked=await second.p;
  assert.equal(blocked.result.isError,true);
  assert.equal(existsSync(join(workspaceRoot,'denied.txt')),false);
  const overwrite=client.request('tools/call',{name:'write_note',arguments:{path:'approved.txt',content:'overwrite'}});
  const overlap=await waitForApproval(controller);
  controller.approvalQueue.finish(overlap.id,true);
  const noOverwrite=await overwrite.p;
  assert.equal(noOverwrite.result.isError,true);
  assert.equal(readFileSync(join(workspaceRoot,'approved.txt'),'utf8'),'approved content');
  const grouped=controller.store.activity();
  assert.equal(grouped.length,3);
  assert.equal(grouped.filter(x=>x.decision==='block').length,1);
  assert.equal(grouped.filter(x=>x.outcome==='error').length,1);
  assert.ok(grouped.some(x=>x.events.length===2&&x.ruleId==='APPROVAL_GRANTED'));
  assert.match(readFileSync(dataFile,'utf8'),/APPROVAL_DENIED/);
}));

test('MCP gate fails closed if approval controller is offline',()=>fixture(async({client,workspaceRoot})=>{
  await client.initialize();
  const answer=await client.request('tools/call',{name:'write_note',arguments:{path:'offline.txt',content:'no'}}).p;
  assert.equal(answer.result.isError,true);
  assert.equal(existsSync(join(workspaceRoot,'offline.txt')),false);
},{dashboard:false}));

test('MCP cancellation before approval prevents a later write',()=>fixture(async({client,workspaceRoot,controller})=>{
  await client.initialize();
  const call=client.request('tools/call',{name:'write_note',arguments:{path:'cancel.txt',content:'no'}});
  // A cancelled MCP request intentionally receives no response; consume the tester timeout.
  call.p.catch(() => {});
  const p=await waitForApproval(controller);
  client.raw({jsonrpc:'2.0',method:'notifications/cancelled',params:{requestId:call.id}});
  for(let i=0;i<50&&controller.approvalQueue.list().length;i++)await sleep(20);
  assert.equal(controller.approvalQueue.list().length,0);
  assert.equal(controller.approvalQueue.finish(p.id,true),false);
  await sleep(80);
  assert.equal(existsSync(join(workspaceRoot,'cancel.txt')),false);
}));

test('MCP approval endpoint rejects missing bearer and browser origins',()=>fixture(async({port,controller})=>{
  const address=`http://127.0.0.1:${port}/api/mcp/approval`;
  const unauth=await fetch(address,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  assert.equal(unauth.status,403);
  const token=readFileSync(controller.tokenFile,'utf8').trim();
  const forged=await fetch(address,{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${token}`,origin:`http://127.0.0.1:${port}`},body:'{}'});
  assert.equal(forged.status,403);
  assert.equal(controller.approvalQueue.list().length,0);
}));


test('MCP blocks traversal, unsafe writes, unregistered tools, and duplicate active IDs',()=>fixture(async({client,controller,workspaceRoot})=>{
  await client.initialize();
  const traversal=await client.request('tools/call',{name:'read_note',arguments:{path:'../secrets.txt'}}).p;
  assert.equal(traversal.result.isError,true);
  const invalid=await client.request('tools/call',{name:'write_note',arguments:{path:'../evil.txt',content:'unsafe'}}).p;
  assert.equal(invalid.result.isError,true);
  const mutation=await client.request('tools/call',{name:'shell_command',arguments:{command:'echo hello'}}).p;
  assert.equal(mutation.result.isError,true);
  const pending=client.request('tools/call',{name:'write_note',arguments:{path:'pending.txt',content:'awaiting review'}});
  pending.p.catch(()=>{});
  const approval=await waitForApproval(controller);
  client.raw({jsonrpc:'2.0',id:pending.id,method:'tools/call',params:{name:'read_note',arguments:{path:'notes.txt'}}});
  // The original pending call will receive the duplicate-ID error in this test harness.
  const duplicate=await pending.p;
  assert.equal(duplicate.error?.code,-32600);
  controller.approvalQueue.finish(approval.id,false);
  await sleep(60);
  assert.equal(existsSync(join(workspaceRoot,'pending.txt')),false);
}));

const META = Object.freeze({
  'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientCapabilities': {},
  'io.modelcontextprotocol/clientInfo': {name:'interoperability-test',version:'1.0.0'}
});
const modern = (params={}) => ({...params,_meta:{...META}});

test('modern stdio: server/discover, per-request metadata and complete tool results',()=>fixture(async({client,workspaceRoot,controller})=>{
  const discover=await client.request('server/discover',modern()).p;
  assert.deepEqual(discover.result.supportedVersions,['2026-07-28']);
  assert.equal(discover.result.resultType,'complete');
  assert.equal(discover.result._meta['io.modelcontextprotocol/serverInfo'].name,'agent-black-box-gateway');
  const list=await client.request('tools/list',modern()).p;
  assert.equal(list.result.resultType,'complete');
  assert.equal(list.result.ttlMs,0);
  assert.equal(list.result.cacheScope,'private');
  assert.deepEqual(list.result.tools.map(x=>x.name),['read_note','write_note']);
  const read=await client.request('tools/call',modern({name:'read_note',arguments:{path:'notes.txt'}})).p;
  assert.equal(read.result.resultType,'complete');
  assert.match(read.result.content[0].text,/MCP integration test/);
  const unsafe=await client.request('tools/call',modern({name:'read_note',arguments:{path:'.env'}})).p;
  assert.equal(unsafe.result.isError,true);
  assert.match(unsafe.result.content[0].text,/DENY_SENSITIVE_FILE/);
  assert.equal((await client.request('resources/list',modern()).p).error.code,-32601);
  assert.equal((await client.request('ping',modern()).p).error.code,-32601);
  assert.equal(controller.store.stats().total,2);
  assert.equal(existsSync(join(workspaceRoot,'.env')),false);
}));

test('modern stdio: missing metadata and unknown versions fail closed without execution',()=>fixture(async({client,controller})=>{
  const invalid=await client.request('server/discover',{_meta:{'io.modelcontextprotocol/protocolVersion':'2026-07-28'}}).p;
  assert.equal(invalid.error.code,-32602);
  const wrong=await client.request('server/discover',{_meta:{...META,'io.modelcontextprotocol/protocolVersion':'2099-01-01'}}).p;
  assert.equal(wrong.error.code,-32022);
  assert.deepEqual(wrong.error.data.supported,['2026-07-28','2025-11-25']);
  const discover=await client.request('server/discover',modern()).p;
  assert.equal(discover.result.resultType,'complete');
  const unauth=await client.request('tools/call',{name:'read_note',arguments:{path:'notes.txt'}}).p;
  assert.equal(unauth.error.code,-32602);
  const badVersion=await client.request('tools/call',{name:'read_note',arguments:{path:'notes.txt'},_meta:{...META,'io.modelcontextprotocol/protocolVersion':'1999-01-01'}}).p;
  assert.equal(badVersion.error.code,-32022);
  const unsupported=await client.request('tools/call',modern({name:'read_note',arguments:{path:'notes.txt'},requestState:'forged'})).p;
  assert.equal(unsupported.error.code,-32602);
  assert.equal(controller.store.stats().total,0);
  assert.equal((await client.request('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'bad',version:'1'}}).p).error.code,-32600);
}));

test('modern stdio: approval-gated write resumes on exact operator authorization',()=>fixture(async({client,controller,workspaceRoot})=>{
  await client.request('server/discover',modern()).p;
  const pending=client.request('tools/call',modern({name:'write_note',arguments:{path:'modern.txt',content:'Modern MCP approval.'}}));
  const p=await waitForApproval(controller);
  assert.equal(existsSync(join(workspaceRoot,'modern.txt')),false);
  controller.approvalQueue.finish(p.id,true);
  const result=await pending.p;
  assert.equal(result.result.resultType,'complete');
  assert.equal(result.result.isError,undefined);
  assert.equal(readFileSync(join(workspaceRoot,'modern.txt'),'utf8'),'Modern MCP approval.');
  const grouped=controller.store.activity();
  assert.equal(grouped.length,1);
  assert.equal(grouped[0].events.length,2);
}));

test('legacy stdio and modern stdio cannot switch eras mid-connection',()=>fixture(async({client})=>{
  await client.initialize();
  const modernProbe=await client.request('server/discover',modern()).p;
  assert.equal(modernProbe.error.code,-32601);
}));

test('modern stdio: direct tools/list without discover is accepted, as MCP v2 permits',()=>fixture(async({client})=>{
  const list=await client.request('tools/list',modern()).p;
  assert.equal(list.result.resultType,'complete');
  const read=await client.request('tools/call',modern({name:'read_note',arguments:{path:'notes.txt'}})).p;
  assert.equal(read.result.isError,undefined);
  assert.match(read.result.content[0].text,/MCP integration test/);
}));

test('modern stdio cancellation during cold downstream discovery prevents tool dispatch',()=>fixture(async({client,controller,workspaceRoot})=>{
  const call=client.request('tools/call',modern({
    name:'write_note',arguments:{path:'cancel-before-dispatch.txt',content:'SYNTHETIC_CANCEL_CONTENT'}
  }));
  call.p.catch(()=>{}); // MCP recommends no response for a cancelled request.
  client.raw({jsonrpc:'2.0',method:'notifications/cancelled',
    params:{requestId:call.id,reason:'Cancel before native dispatch'}});
  await sleep(350);
  assert.equal(controller.approvalQueue.list().length,0);
  assert.equal(controller.store.stats().total,0);
  assert.equal(existsSync(join(workspaceRoot,'cancel-before-dispatch.txt')),false);
  const read=await client.request('tools/call',modern({
    name:'read_note',arguments:{path:'notes.txt'}
  })).p;
  assert.match(read.result?.content?.[0]?.text??'',/MCP integration test/);
}));
