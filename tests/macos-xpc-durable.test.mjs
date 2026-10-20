import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const file=path=>readFileSync(new URL(path,import.meta.url),'utf8');

test('durable sandbox notes resolve Documents from Foundation, never client-provided paths',()=>{
  const worker=file('../native/macos/xpc/DurableNotesService.m');
  assert.match(worker, /URLForDirectory:NSDocumentDirectory/);
  assert.match(worker, /create:YES/);
  assert.match(worker, /\/Library\/Containers\//);
  assert.match(worker, /\/Data\/Documents/);
  assert.match(worker, /O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(worker, /mkdirat\(parent,"AgentBlackBoxScratchNotes",0700\)/);
  assert.match(worker, /st\.st_uid!=geteuid\(\)/);
  assert.match(worker, /openat\(dir,name,O_WRONLY\|O_CREAT\|O_EXCL\|O_NOFOLLOW\|O_CLOEXEC,0600\)/);
  assert.match(worker, /xpc_main\(accept_peer\)/);
  assert.doesNotMatch(worker, /getenv\("TMPDIR"\)/);
});

test('durable XPC app and service use independent identities and private service type',()=>{
  const host=file('../native/macos/xpc/DurableHost-Info.plist');
  const worker=file('../native/macos/xpc/DurableService-Info.plist');
  const bridge=file('../native/macos/xpc/DurableBridgeHost.c');
  assert.match(host,/dev\.agentblackbox\.xpc-durable\.host/);
  assert.match(worker,/dev\.agentblackbox\.xpc-durable\.worker/);
  assert.match(worker,/<string>XPC!<\/string>/);
  assert.match(bridge,/xpc_connection_create\("dev\.agentblackbox\.xpc-durable\.worker"/);
  assert.doesNotMatch(bridge,/\b(?:system|popen|execvp|execlp)\s*\(/);
});

test('cross-host durable acceptance has two invocations and cleanup with no MCP gateway changes',()=>{
  const script=file('../examples/mcp-macos-xpc-durable.mjs');
  assert.match(script,/const first=await executeBatch\(host,firstRequests\)/);
  assert.match(script,/const later=await executeBatch\(host,laterRequests\)/);
  assert.match(script,/frameBridgeRequest\('REMOVE',filename\)/);
  assert.match(script,/'-framework','Foundation'/);
  assert.match(script,/checkWorkerSignature\(bundle,app\)/);
  assert.match(script,/status:proc\.status/);
  const sandbox=file('../src/sandbox.mjs');
  assert.match(sandbox,/if\(platform!==['"]linux['"]\) throw Error/);
});
