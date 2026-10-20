import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {guardedToolCall} from '../src/monitor.mjs';
import {evaluatePolicy} from '../src/policy.mjs';

test('a dispatched approved write with lost acknowledgement records UNKNOWN, never success',async()=>{
 const workspace=mkdtempSync(join(tmpdir(),'bb-unknown-outcome-'));
 const events=[];
 const store={verify(){},add(event){events.push({...event})}};
 try {
  const result=await guardedToolCall({
   agentId:'fault-test',runId:'fault-test',tool:'file.write',
   args:{path:'bbx-test-fault-crash-1234.txt',content:'synthetic note'},
   workspaceRoot:workspace,store,requestApproval:async()=>({approved:true}),
   execute:async()=>{
     const error=new Error('Synthetic native acknowledgement lost.');
     error.outcomeUnknown=true;
     throw error;
   }
  });
  assert.equal(result.event.outcome,'error');
  assert.equal(result.event.ruleId,'MCP_OUTCOME_UNKNOWN');
  assert.match(result.event.reason,/acknowledgement was lost/);
  assert.equal(events.at(-1).ruleId,'MCP_OUTCOME_UNKNOWN');
  assert.equal(events.filter(e=>e.outcome==='success').length,0);
  assert.equal(events.filter(e=>e.outcome==='pending').length,1);
  assert.equal(events.some(e=>JSON.stringify(e).includes('synthetic note')),false);
 }finally{rmSync(workspace,{recursive:true,force:true});}
});
test('known denied execution does not incorrectly claim outcome unknown',async()=>{
 const workspace=mkdtempSync(join(tmpdir(),'bb-known-denial-'));
 const events=[],store={verify(){},add(event){events.push({...event})}};
 try{
  const result=await guardedToolCall({
   agentId:'fault-test',runId:'fault-test',tool:'file.write',
   args:{path:'bbx-test-fault-hang-1234.txt',content:'synthetic note'},
   workspaceRoot:workspace,store,requestApproval:async()=>({approved:false}),
   execute:async()=>{throw Error('MUST NOT execute');}
  });
  assert.equal(result.event.ruleId,'APPROVAL_DENIED');
  assert.equal(result.event.outcome,'blocked');
  assert.equal(events.filter(e=>e.ruleId==='MCP_OUTCOME_UNKNOWN').length,0);
 }finally{rmSync(workspace,{recursive:true,force:true});}
});
test('fault host only injects synthetic pre-write hang and post-write crash',()=>{
 const source=readFileSync(new URL('../native/macos/xpc/FaultBridgeHost.c',import.meta.url),'utf8');
 assert.match(source,/getenv\("BLACKBOX_XPC_TEST_FAULT"\)/);
 assert.match(source,/bbx-test-fault-hang-/);
 assert.match(source,/bbx-test-fault-crash-/);
 assert.match(source,/for\(;;\)pause\(\)/);
 assert.match(source,/raise\(SIGKILL\)/);
 assert.match(source,/xpc_connection_send_message_with_reply_sync/);
 const normal=readFileSync(new URL('../native/macos/xpc/AuthorityBridgeHost.c',import.meta.url),'utf8');
 assert.doesNotMatch(normal,/BLACKBOX_XPC_TEST_FAULT|raise\(SIGKILL\)/);
});
test('native adapter marks unknown for timeout/crash but not known refused operations',()=>{
 const source=readFileSync(new URL('../examples/mcp-macos-xpc-mcp-downstream.mjs',import.meta.url),'utf8');
 const gw=readFileSync(new URL('../src/mcp-gateway.mjs',import.meta.url),'utf8');
 const monitor=readFileSync(new URL('../src/monitor.mjs',import.meta.url),'utf8');
 assert.match(source,/outcomeUnknown:true/);
 assert.match(source,/'dev\.agentblackbox\/outcomeUnknown':true/);
 assert.match(source,/BLACKBOX_XPC_TEST_FAULT/);
 assert.match(gw,/response\?\._meta\?\.\['dev\.agentblackbox\/outcomeUnknown'\]===true/);
 assert.match(monitor,/error\?\.outcomeUnknown === true/);
 assert.match(monitor,/event\.ruleId = 'MCP_OUTCOME_UNKNOWN'/);
});
test('real gateway fault acceptance tests visible error, committed write and HMAC uncertainty',()=>{
 const source=readFileSync(new URL('../examples/mcp-macos-xpc-fault-acceptance.mjs',import.meta.url),'utf8');
 assert.match(source,/FaultBridgeHost\.c/);
 assert.match(source,/BLACKBOX_XPC_TEST_FAULT:'1'/);
 assert.match(source,/hung native host/i);
 assert.match(source,/crash-after-write synthetic note/i);
 assert.match(source,/await pendingApproval\(controller\)/);
 assert.match(source,/ruleId==='MCP_OUTCOME_UNKNOWN'&&x\.outcome==='error'/);
 assert.match(source,/controller\.store\.verify\(\)/);
 assert.match(source,/nativeResult\(host,frameBridgeRequest\('REMOVE',syntheticName\)\)/);
});
