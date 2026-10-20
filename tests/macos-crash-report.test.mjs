import {test} from 'node:test';
import assert from 'node:assert/strict';
import {summarizeProbeCrash} from '../examples/mcp-macos-crash.mjs';

test('macOS IPS summary identifies faulting frame and secinit diagnostic',()=>{
 const first={app_name:'blackbox-sandbox-probe'};
 const second={procName:'blackbox-sandbox-probe',exception:{type:'EXC_BREAKPOINT',signal:'SIGTRAP'},
  termination:{namespace:'SIGNAL',code:5},faultingThread:0,
  asi:{'libsystem_secinit.dylib':['sandbox container failed initialization']},
  usedImages:[{name:'libsystem_secinit.dylib'}],
  threads:[{triggered:true,frames:[{imageIndex:0,symbol:'_libsecinit_appsandbox'}]}]};
 const summary=summarizeProbeCrash(JSON.stringify(first)+'\n'+JSON.stringify(second));
 assert.equal(summary.format,'ips');
 assert.equal(summary.exceptionSignal,'SIGTRAP');
 assert.equal(summary.frames[0].image,'libsystem_secinit.dylib');
 assert.equal(summary.terminationNamespace,'SIGNAL');
 assert.match(summary.applicationSpecificInformation['libsystem_secinit.dylib'],/container/);
});
test('macOS old-style crash summary finds exception and termination reason',()=>{
 const summary=summarizeProbeCrash('Process: blackbox-sandbox-probe [42]\nException Type: EXC_BREAKPOINT (SIGTRAP)\nTermination Reason: SIGNAL 5\nThread 0 libsystem_secinit.dylib\n');
 assert.equal(summary.format,'crash');
 assert.equal(summary.exceptionType,'EXC_BREAKPOINT (SIGTRAP)');
 assert.equal(summary.frames.length,1);
});
test('macOS crash summary handles sparse new report without assuming a cause',()=>{
 const summary=summarizeProbeCrash(JSON.stringify({procName:'blackbox-sandbox-probe',threads:[]}));
 assert.deepEqual(summary.frames,[]);
 assert.equal(summary.exceptionSignal,'');
 assert.equal(summary.terminationNamespace,'');
});
