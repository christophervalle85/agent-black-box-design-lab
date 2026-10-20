import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {evaluateNativeNotes} from '../examples/mcp-macos-xpc-notes.mjs';

const good=()=>({hostPID:33,workerPID:99,writeAllowed:true,readMatched:true,
  traversalRejected:true,cleanupAllowed:true});
test('native XPC notes require independent process and all positive/negative checks',()=>{
 const v=evaluateNativeNotes(good());
 assert.equal(v.ok,true);assert.equal(v.checks.length,5);
 for(const variation of [{workerPID:33},{writeAllowed:false},{readMatched:false},
   {traversalRejected:false},{cleanupAllowed:false}]){
   assert.equal(evaluateNativeNotes({...good(),...variation}).ok,false);
 }
});
test('native XPC notes proof fails closed on malformed output',()=>{
 for(const variation of [null,[],undefined,{}, {...good(),workerPID:'99'},
   {...good(),cleanupAllowed:1}]) assert.throws(()=>evaluateNativeNotes(variation));
});
test('native XPC worker permits only bounded synthetic filenames and safe open flags',()=>{
 const worker=readFileSync(new URL('../native/macos/xpc/NotesService.c',import.meta.url),'utf8');
 assert.match(worker,/allowed_name\(const char \*name\)/);
 assert.match(worker,/bbx-test-/);
 assert.match(worker,/openat\(dir,name,O_WRONLY\|O_CREAT\|O_EXCL\|O_NOFOLLOW\|O_CLOEXEC,0600\)/);
 assert.match(worker,/length>2000/);
 assert.match(worker,/xpc_main\(accept_peer\)/);
 assert.match(worker,/cleanup_test_note/);
});
test('notes service and native host have distinct stable app/XPC identities',()=>{
 const host=readFileSync(new URL('../native/macos/xpc/NotesHost-Info.plist',import.meta.url),'utf8');
 const service=readFileSync(new URL('../native/macos/xpc/NotesService-Info.plist',import.meta.url),'utf8');
 assert.match(host,/dev\.agentblackbox\.xpc-notes\.host/);
 assert.match(service,/dev\.agentblackbox\.xpc-notes\.worker/);
 assert.match(service,/<string>XPC!<\/string>/);
 assert.match(service,/<key>XPCService<\/key>/);
});
