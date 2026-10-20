import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  assessSignedInboundEvidence
} from '../examples/mcp-macos-xpc-inbound-signed.mjs';

const healthy=()=>({
  status:0,signal:null,error:null,stderr:'',
  stdout:'BBX_XPC_SIGNED_INBOUND_OS_REJECTED\n'
});
test('signed inbound peer result requires exact native evidence and healthy exit',()=>{
  assert.equal(assessSignedInboundEvidence(healthy()),true);
  for(const faulty of [
    null,{...healthy(),status:87},{...healthy(),status:null},
    {...healthy(),signal:'SIGKILL'},
    {...healthy(),error:new Error('timeout')},
    {...healthy(),stdout:'BBX_XPC_SIGNED_INBOUND_NOT_ESTABLISHED\n'},
    {...healthy(),stdout:'BBX_XPC_SIGNED_INBOUND_OS_REJECTED\nextra\n'},
    {...healthy(),stdout:'BBX_XPC_SIGNED_INBOUND_OS_REJECTED /Users/test\n'},
    {...healthy(),stderr:'private key details'},
    {...healthy(),stdout:'BBX_XPC_SIGNED_OUTBOUND_OS_REJECTED\n'}
  ])assert.throws(()=>assessSignedInboundEvidence(faulty));
});
test('worker-side inbound signing requirement precedes all handler delivery',()=>{
  const worker=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptService.m',import.meta.url),'utf8');
  const host=readFileSync(new URL(
    '../native/macos/xpc/SignedInboundHost.c',import.meta.url),'utf8');
  const run=readFileSync(new URL(
    '../examples/mcp-macos-xpc-inbound-signed.mjs',import.meta.url),'utf8');
  const gate=worker.indexOf('bbx_install_same_team_peer_requirement(');
  const resume=worker.indexOf('xpc_connection_resume(peer)',gate);
  const handler=worker.indexOf('xpc_connection_set_event_handler(peer',gate);
  assert.ok(gate>0 && resume>gate && handler>gate);
  assert.match(worker,/#ifdef BBX_TEST_SIGNED_INBOUND_EVIDENCE/);
  assert.match(worker,/delivered=\+\+acceptedMessageCount/);
  assert.match(worker,/xpc_dictionary_set_uint64\(result,"workerPID"/);
  assert.match(worker,/xpc_dictionary_set_uint64\(result,"delivered"/);
  assert.match(worker,/strcmp\(operation,"signed_inbound_stats"\)==0/);
  assert.match(host,/bbx_install_same_team_peer_requirement\(peer,BBX_WORKER_ID\)/);
  assert.match(host,/XPC_TYPE_ERROR/);
  assert.match(host,/XPC_ERROR_CONNECTION_INVALID/);
  assert.match(host,/XPC_ERROR_CONNECTION_INTERRUPTED/);
  assert.match(host,/XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT/);
  assert.match(host,/strcmp\(status,"ACCEPTED"\)==0/);
  assert.match(host,/pid1==pid2 && count1==2 && count2==3/);
  assert.match(host,/spawnWrongSibling\(argv\[0\]\)/);
  assert.match(host,/BBX_XPC_SIGNED_INBOUND_OS_REJECTED/);
  assert.doesNotMatch(host,/\b(?:open|openat|fwrite|write|unlink|mkdir|system|popen)\s*\(/);
  assert.match(run,/copyFileSync\(host,wrong\)/);
  assert.match(run,/--identifier',WRONG_HOST_ID,wrong/);
  assert.match(run,/--identifier',HOST_ID,app/);
  assert.match(run,/--identifier',WORKER_ID/);
  assert.match(run,/--verify','--strict','--deep',app/);
  assert.match(run,/inspectCode\(wrong,WRONG_HOST_ID\)/);
  assert.match(run,/if\(teams.some\(t=>t!==teams\[0\]\)\)/);
  assert.match(run,/requireWorkerSandbox\(service\)/);
  assert.match(run,/MCP_SANDBOX!=='off'/);
  assert.match(run,/rmSync\(temp,\{recursive:true,force:true\}\)/);
  assert.doesNotMatch(run,/createBlackBoxServer|createAuditedMacTransferController/);
});
