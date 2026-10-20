import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessSyntheticXpcReceipt} from '../examples/mcp-macos-xpc-transfer-receipt.mjs';

const expected={
  valid:'BBX_XPC_RECEIPT_VALID_ACCEPTED\n',
  tamper:'BBX_XPC_RECEIPT_TAMPER_BLOCKED\n',
  replay:'BBX_XPC_RECEIPT_REPLAY_BLOCKED\n'
};
const outcome=mode=>({status:0,signal:null,error:null,stderr:'',
  stdout:expected[mode]});
test('receipt acceptance is mode-specific with exact native process output',()=>{
  for(const mode of Object.keys(expected)){
    assert.equal(assessSyntheticXpcReceipt(mode,outcome(mode)),true);
    for(const other of Object.keys(expected).filter(x=>x!==mode))
      assert.throws(()=>assessSyntheticXpcReceipt(mode,outcome(other)));
    for(const bad of [
      {...outcome(mode),status:87},
      {...outcome(mode),stderr:'debug: private data\n'},
      {...outcome(mode),stdout:expected[mode]+'unexpected\n'},
      {...outcome(mode),stdout:'BBX_XPC_RECEIPT_NOT_ACCEPTED\n'},
      {...outcome(mode),signal:'SIGKILL'},
      {...outcome(mode),error:new Error('spawn failed')},
      {...outcome(mode),status:null}
    ])assert.throws(()=>assessSyntheticXpcReceipt(mode,bad));
  }
  assert.throws(()=>assessSyntheticXpcReceipt('approve',outcome('valid')));
});
test('synthetic worker enforces bounded data, digest, replay and no filesystem writes',()=>{
  const worker=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptService.m',import.meta.url),'utf8');
  const host=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptHost.c',import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../examples/mcp-macos-xpc-transfer-receipt.mjs',import.meta.url),'utf8');
  assert.match(worker,/xpc_main\(acceptPeer\)/);
  assert.match(worker,/xpc_get_type\(item\)==type/);
  assert.match(worker,/xpc_dictionary_apply\(request/);
  assert.match(worker,/count==5/);
  assert.match(worker,/count>BBX_MAX_PAYLOAD/);
  assert.match(worker,/testName\(name\)/);
  assert.match(worker,/lowerHex\(nonce,32\)/);
  assert.match(worker,/lowerHex\(sha,64\)/);
  assert.match(worker,/CC_SHA256\(data/);
  assert.match(worker,/dispatch_sync\(nonceQueue/);
  assert.match(worker,/strcmp\(seen\[i\],nonce\)==0/);
  assert.match(worker,/CAPACITY_EXHAUSTED/);
  assert.match(worker,/DIGEST_MISMATCH/);
  assert.match(worker,/BAD_REQUEST/);
  assert.match(worker,/REPLAY/);
  assert.match(worker,/memset_s\(actual/);
  assert.doesNotMatch(worker,/\b(?:open|openat|fopen|fwrite|write|unlink|mkdir)\s*\(/);
  assert.match(host,/xpc_connection_send_message_with_reply_sync/);
  assert.match(host,/xpc_dictionary_set_data\(message,"payload",payload,n\)/);
  assert.match(host,/arc4random_buf/);
  assert.match(host,/tampered\[0\]\^=1/);
  assert.match(host,/request\(peer,nonce,sha,payload,size,"REPLAY"\)/);
  assert.match(host,/request\(peer,nonce,sha,tampered,size,"DIGEST_MISMATCH"\)/);
  assert.match(runner,/process\.platform!=='darwin'/);
  assert.match(runner,/process\.env\.MCP_SANDBOX!=='off'/);
  assert.match(runner,/com\\\.apple\\\.security\\\.app-sandbox/);
  assert.match(runner,/--verify','--strict','--deep'/);
  assert.match(runner,/rmSync\(temp,\{recursive:true,force:true\}\)/);
  assert.doesNotMatch(runner,/createBlackBoxServer|createAuditedMacTransferController/);
});
