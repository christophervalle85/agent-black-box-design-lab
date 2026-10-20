import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=path=>readFileSync(new URL(path,import.meta.url),'utf8');

test('Phase 3D has a separate XPC service identity and bundle, leaving accepted worker untouched',()=>{
 const host=source('../native/macos/xpc/ServiceFailureHost-Info.plist');
 const worker=source('../native/macos/xpc/ServiceFailureService-Info.plist');
 const usual=source('../native/macos/xpc/AuthorityNotesService.m');
 const fault=source('../native/macos/xpc/ServiceFailureNotesService.m');
 assert.match(host,/dev\.agentblackbox\.xpc-servicefault\.host/);
 assert.match(worker,/dev\.agentblackbox\.xpc-servicefault\.worker/);
 assert.match(worker,/<string>XPC!<\/string>/);
 assert.match(fault,/_exit\(86\)/);
 assert.match(fault,/bbx-test-xpc-crash-/);
 assert.match(fault,/bool good=n==\(ssize_t\)length && fsync\(file\)==0/);
 assert.ok(fault.indexOf('fsync(file)')<fault.indexOf('_exit(86)'));
 assert.doesNotMatch(usual,/_exit\(86\)|bbx-test-xpc-crash-/);
});
test('Phase 3D XPC interruption cannot be converted to an ordinary native denial',()=>{
 const sourceText=source('../native/macos/xpc/ServiceFailureBridgeHost.c');
 const normal=source('../native/macos/xpc/AuthorityBridgeHost.c');
 assert.match(sourceText,/xpc_get_type\(reply\)==XPC_TYPE_ERROR/);
 assert.match(sourceText,/return 78;/);
 assert.match(sourceText,/const bool pidOp=strcmp\(op,"PID"\)==0/);
 assert.match(sourceText,/xpc_dictionary_get_int64\(reply,"workerPID"\)/);
 assert.match(sourceText,/dev\.agentblackbox\.xpc-servicefault\.worker/);
 assert.doesNotMatch(normal,/const bool pidOp/);
});
test('real MCP service death acceptance checks committed data, new PID, and UNKNOWN signed audit',()=>{
 const harness=source('../examples/mcp-macos-xpc-service-failure.mjs');
 assert.match(harness,/ServiceFailureBridgeHost\.c/);
 assert.match(harness,/ServiceFailureNotesService\.m/);
 assert.match(harness,/const pidBeforeReply=await nativeResult\(host/);
 assert.match(harness,/afterPid===beforePid/);
 assert.match(harness,/const committed=await nativeResult\(host,frameBridgeRequest\('READ',crash\)\)/);
 assert.match(harness,/result\.result\?\.isError!==true/);
 assert.match(harness,/controller\.store\.verify\(\)/);
 assert.match(harness,/ruleId==='MCP_OUTCOME_UNKNOWN'&&e\.outcome==='error'/);
 assert.match(harness,/JSON\.stringify\(e\)\.includes\(content\)/);
 assert.match(harness,/viaMcp=await request\('tools\/call'/);
 assert.match(harness,/nativeResult\(host,frameBridgeRequest\('REMOVE',syntheticName\)\)/);
 assert.match(harness,/MCP_SANDBOX:'off'/);
 assert.doesNotMatch(harness,/BLACKBOX_XPC_TEST_FAULT:'1'/);
});
