import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { assessMacProbe } from '../src/macos-probe-verdict.mjs';

const good=()=>({hostFileDenied:true,hostFileError:'NSCocoaErrorDomain:257',
  networkDenied:true,networkErrorNumber:1,sandboxHomeWriteAllowed:true,sandboxHomeError:''});

test('macOS probe verdict needs all three genuine OS-denial outcomes',()=>{
  const v=assessMacProbe(good());
  assert.equal(v.ok,true);assert.equal(v.checks.length,3);
});
test('macOS verdict rejects refused, unreachable, and unsuccessful loopback attempts',()=>{
  for(const networkErrorNumber of [60,61,65,51,0]){
    assert.equal(assessMacProbe({...good(),networkDenied:true,networkErrorNumber}).ok,false);
  }
  assert.equal(assessMacProbe({...good(),networkDenied:false}).ok,false);
});
test('macOS verdict rejects wrong missing-file error, readable host file and failed container write',()=>{
  assert.equal(assessMacProbe({...good(),hostFileError:'NSCocoaErrorDomain:260'}).ok,false);
  assert.equal(assessMacProbe({...good(),hostFileDenied:false}).ok,false);
  assert.equal(assessMacProbe({...good(),sandboxHomeWriteAllowed:false}).ok,false);
  assert.equal(assessMacProbe({...good(),sandboxHomeError:'EACCES'}).ok,false);
});
test('macOS verdict rejects malformed or incomplete diagnostics',()=>{
  for(const input of [undefined,null,[],{},{...good(),networkDenied:'yes'},
    {...good(),networkErrorNumber:'1'}, {...good(),hostFileError:undefined}]){
    assert.throws(()=>assessMacProbe(input));
  }
});
test('native helper probe refuses to masquerade as macOS on non-Mac CI',()=>{
  if(process.platform==='darwin')return;
  const run=spawnSync(process.execPath,[new URL('../examples/mcp-macos-probe.mjs',import.meta.url).pathname],{encoding:'utf8',timeout:5000});
  assert.equal(run.status,1);
  assert.match(run.stderr,/requires macOS/i);
});
