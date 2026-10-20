import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {chooseGatewayLaunch} from '../src/mcp-experimental-launch.mjs';
import {frameBridgeRequest} from '../src/macos-xpc-bridge-wire.mjs';

const trial=()=>({command:'/usr/local/bin/node',args:['/test/downstream.mjs'],
  env:{MCP_SANDBOX:'off',BLACKBOX_EXPERIMENTAL_XPC_HOST:'/test/BlackBoxAuthorityHost'}});
test('normal gateway uses its existing downstream unchanged',()=>{
  const existing={command:'/usr/bin/node',args:['/project/notes.mjs'],env:{}};
  assert.equal(chooseGatewayLaunch({standard:existing,mode:'off',platform:'darwin'}),existing);
  assert.equal(chooseGatewayLaunch({standard:existing,mode:'required',platform:'linux'}),existing);
});
test('native MCP test launch is never accepted for macOS required mode or Linux',()=>{
  const existing={command:'/usr/bin/node',args:[],env:{}};
  assert.throws(()=>chooseGatewayLaunch({
    standard:existing,experimental:trial(),mode:'required',platform:'darwin'
  }),/only permitted/);
  assert.throws(()=>chooseGatewayLaunch({
    standard:existing,experimental:trial(),mode:'off',platform:'linux'
  }),/only permitted/);
  assert.equal(chooseGatewayLaunch({
    standard:existing,experimental:trial(),mode:'off',platform:'darwin'
  }).command,'/usr/local/bin/node');
});
test('invalid in-process launch and non-absolute executable fail closed',()=>{
  for(const experimental of [{...trial(),command:'node'}, {...trial(),args:['ok',1]},
    {...trial(),env:null},{}])assert.throws(()=>chooseGatewayLaunch({
      standard:{},experimental,platform:'darwin',mode:'off'
    }),/Malformed/);
});
test('MCP test adapter can only address the test namespace, no shell requests',()=>{
  const frame=frameBridgeRequest('WRITE','bbx-test-mcp-accept.txt','approved test note');
  assert.match(frame.toString(),/^WRITE bbx-test-mcp-accept\.txt /);
  assert.throws(()=>frameBridgeRequest('WRITE','real-user.txt','not allowed'));
  assert.throws(()=>frameBridgeRequest('EXEC','bbx-test-mcp-accept.txt','pwd'));
});
test('acceptance harness uses actual gateway, approval controller, isolated HMAC audit and native worker',()=>{
  const harness=readFileSync(new URL('../examples/mcp-macos-xpc-mcp-acceptance.mjs',import.meta.url),'utf8');
  const adapter=readFileSync(new URL('../examples/mcp-macos-xpc-mcp-downstream.mjs',import.meta.url),'utf8');
  assert.match(harness,/startGateway\(requiredInstalled\?/);
  assert.match(harness,/env:testEnv,experimentalLaunch/);
  assert.match(harness,/MCP_SANDBOX:requiredInstalled\?'required':'off'/);
  assert.match(harness,/createBlackBoxServer\(\{dataFile:auditFile,workspaceRoot:nativeRoot/);
  assert.match(harness,/validateMacWorkspaceBinding/);
  assert.match(harness,/\/api\/approvals\//);
  assert.match(harness,/controller\.store\.verify\(\)/);
  assert.match(harness,/audit\.includes\(content\)/);
  assert.match(harness,/MCP_SANDBOX:'off'/);
  assert.match(adapter,/frameBridgeRequest\(/);
  assert.match(adapter,/nativeRequest\(host/);
  assert.doesNotMatch(adapter,/\b(?:execSync|execFileSync)\s*\(/);
  const gateway=readFileSync(new URL('../src/mcp-gateway.mjs',import.meta.url),'utf8');
  assert.match(gateway,/chooseGatewayLaunch/);
  assert.match(gateway,/downstreamLaunch\(\{env,workspaceRoot,scriptPath:/);
  assert.match(gateway,/guardedToolCall\(\{/);
});
