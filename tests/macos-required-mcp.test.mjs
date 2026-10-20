import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assertMacRequiredPin,planMacRequiredMcp} from '../src/macos-required-mcp.mjs';

const source=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const workspace='/synthetic/Library/Containers/dev.agentblackbox.xpc-authority.worker/Data/Documents/AgentBlackBoxScratchNotes';
test('required native MCP trust pin has exact version, Team ID and no hidden overrides',()=>{
  assert.equal(assertMacRequiredPin({version:1,teamId:'ABCDEFGHI1'}),'ABCDEFGHI1');
  for(const item of [null,{},[],{version:2,teamId:'ABCDEFGHI1'},
    {version:1,teamId:'AAAAAAAAAA',extra:true},
    {version:1,teamId:'invalid!'},
    {version:1,teamId:'ABCDEFGHI1',allowUnsigned:true}])
    assert.throws(()=>assertMacRequiredPin(item));
});
test('required native MCP always refuses unsupported or unconfigured platforms',()=>{
  const options={platform:'linux',workspaceRoot:workspace,
    env:{MCP_WORKSPACE_ROOT:workspace}};
  assert.throws(()=>planMacRequiredMcp(options),/macOS/);
  assert.throws(()=>planMacRequiredMcp({...options,platform:'darwin',
    env:{}}),/explicitly configured/);
  assert.throws(()=>planMacRequiredMcp({...options,platform:'darwin',
    env:{MCP_WORKSPACE_ROOT:'/different'},workspaceRoot:workspace}),
    /differs/);
});
test('planned macOS required-mode launches a fixed dependency-free controller adapter only after signed workspace handshake',()=>{
  let verified=0,handshakes=0,bound=0;
  const plan=planMacRequiredMcp({
    platform:'darwin',workspaceRoot:workspace,
    env:{MCP_WORKSPACE_ROOT:workspace,MCP_SANDBOX:'required',
      NODE_OPTIONS:'--eval=evil()',BLACKBOX_EXPERIMENTAL_XPC_HOST:'/evil'},
    verify:()=>{verified++;return {host:'/signed/native/BlackBoxAuthorityHost'};},
    probe:host=>{handshakes++;assert.equal(host,'/signed/native/BlackBoxAuthorityHost');return workspace;},
    bind:binding=>{bound++;assert.deepEqual(binding,{configuredRoot:workspace,
      reportedRoot:workspace,platform:'darwin'});}
  });
  assert.deepEqual([verified,handshakes,bound],[1,1,1]);
  assert.equal(plan.command,process.execPath);
  assert.ok(plan.args[0].endsWith('/examples/mcp-macos-xpc-mcp-downstream.mjs'));
  assert.equal(plan.enabled,true);
  assert.equal(plan.env.MCP_SANDBOX,'required');
  assert.equal(plan.env.BLACKBOX_NATIVE_REQUIRED_XPC_HOST,'/signed/native/BlackBoxAuthorityHost');
  assert.equal(plan.env.NODE_OPTIONS,undefined);
  assert.equal(plan.env.BLACKBOX_EXPERIMENTAL_XPC_HOST,undefined);
  assert.ok(!plan.args.join(' ').includes('mcp-notes-server.mjs'));
});
test('actual macOS required worker has inbound AND outbound OS signatures, no REMOVE or generic MCP fallback',()=>{
  const worker=source('native/macos/xpc/AuthorityNotesService.m');
  const host=source('native/macos/xpc/AuthorityBridgeHost.c');
  const runtime=source('src/macos-required-mcp.mjs');
  const bootstrap=source('examples/mcp-macos-native-required.mjs');
  const gateway=source('src/sandbox.mjs');
  const adapter=source('examples/mcp-macos-xpc-mcp-downstream.mjs');
  assert.match(worker,/BBX_NATIVE_REQUIRED_MCP/);
  assert.match(worker,/bbx_install_same_team_peer_requirement\(peer,/);
  assert.match(worker,/#ifndef BBX_NATIVE_REQUIRED_MCP\s*}else if\(strcmp\(op,"cleanup_test_note"\)/);
  assert.match(host,/#ifdef BBX_NATIVE_REQUIRED_MCP/);
  assert.match(host,/bbx_install_same_team_peer_requirement\(\s*connection,/);
  assert.match(host,/const bool removeOp=false/);
  assert.match(runtime,/validateMacWorkspaceBinding/);
  assert.match(runtime,/trust-pin\.json/);
  assert.match(runtime,/--verify','--strict','--deep/);
  assert.match(runtime,/BLACKBOX_NATIVE_REQUIRED_XPC_HOST:host/);
  assert.match(bootstrap,/'-DBBX_NATIVE_REQUIRED_MCP=1'/);
  assert.match(bootstrap,/selectLocalDevelopmentIdentity/);
  assert.match(bootstrap,/trust!==null&&trust!==built\.team/);
  assert.match(bootstrap,/flag:'wx'/);
  assert.match(gateway,/platform==='darwin'\)return planMacRequiredMcp/);
  assert.match(adapter,/process\.env\.BLACKBOX_NATIVE_REQUIRED_XPC_HOST/);
  assert.ok(!source('src/mcp-gateway.mjs').includes('operator-transfer'));
  assert.ok(!source('src/mcp-gateway.mjs').includes('import_file'));
});
