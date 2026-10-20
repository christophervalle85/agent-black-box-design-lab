import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessXpc} from '../examples/mcp-macos-xpc-probe.mjs';

const valid=()=>({hostPID:100,workerPID:101,hostFileDenied:true,hostFileErrno:1,
 networkDenied:true,networkErrorNumber:13,temporaryWriteAllowed:true,temporaryWriteErrno:0});
test('XPC acceptance requires different PID and genuine permission-denied results',()=>{
 const result=assessXpc(valid());
 assert.equal(result.ok,true);assert.equal(result.checks.length,4);
 for(const changes of [{workerPID:100},{hostFileErrno:2},{networkErrorNumber:61},
   {hostFileDenied:false},{networkDenied:false},{temporaryWriteAllowed:false},
   {temporaryWriteErrno:13}])assert.equal(assessXpc({...valid(),...changes}).ok,false);
});
test('XPC probe rejects missing, malformed or untrusted results',()=>{
 for(const candidate of [null,[],{},undefined,{...valid(),workerPID:'101'},
   {...valid(),networkDenied:1}, {...valid(),temporaryWriteErrno:null}])
   assert.throws(()=>assessXpc(candidate));
});
test('XPC private service bundle has correct package type and distinct ID',()=>{
 const h=readFileSync(new URL('../native/macos/xpc/Host-Info.plist',import.meta.url),'utf8');
 const x=readFileSync(new URL('../native/macos/xpc/Service-Info.plist',import.meta.url),'utf8');
 assert.match(h,/<string>APPL<\/string>/);
 assert.match(x,/<string>XPC!<\/string>/);
 assert.match(x,/dev\.agentblackbox\.xpc-probe\.worker/);
 assert.match(x,/<key>XPCService<\/key>/);
 assert.match(h,/dev\.agentblackbox\.xpc-probe\.host/);
});

test('XPC C code links against macOS libSystem, not unavailable standalone -lxpc',()=>{
 const script=readFileSync(new URL('../examples/mcp-macos-xpc-probe.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(script, /['\"]-lxpc['\"]/);
 assert.match(script, /join\(sources,src\)\],label\+' compilation'/);
});

test('XPC service hands xpc_main a C function pointer, not an event block',()=>{
 const source=readFileSync(new URL('../native/macos/xpc/ProbeService.c',import.meta.url),'utf8');
 assert.match(source,/static void accept_peer\(xpc_connection_t peer\)/);
 assert.match(source,/xpc_main\(accept_peer\)/);
 assert.doesNotMatch(source,/xpc_main\(\s*\^/);
 assert.match(source,/xpc_connection_set_event_handler\(peer,\s*\^\(xpc_object_t event\)/);
});
