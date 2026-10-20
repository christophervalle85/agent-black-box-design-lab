import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=()=>readFileSync(new URL('../examples/mcp-macos-xpc-mcp-acceptance.mjs',import.meta.url),'utf8');

test('Phase 3B modern mode retains explicit modern protocol metadata on every MCP call',()=>{
 const script=source();
 assert.match(script,/const MODERN='2026-07-28'/);
 assert.match(script,/'io\.modelcontextprotocol\/protocolVersion':MODERN/);
 assert.match(script,/'io\.modelcontextprotocol\/clientCapabilities':\{\}/);
 assert.match(script,/modernMode=args\.includes\('--modern'\)/);
 assert.match(script,/const request=\(method,params=\{\}\)=>client\.send\(method,\s*modernMode\?modern\(params\):params\)/);
 assert.match(script,/const credential=await request\('tools\/call'/);
 assert.match(script,/const deniedCall=request\('tools\/call'/);
 assert.match(script,/const acceptedCall=request\('tools\/call'/);
 assert.match(script,/const readback=await request\('tools\/call'/);
 assert.match(script,/const duplicateCall=request\('tools\/call'/);
});

test('Phase 3B modern test rejects unknown versions and missing metadata before native calls',()=>{
 const script=source();
 assert.match(script,/const wrong=await client\.send\('server\/discover'/);
 assert.match(script,/wrong\.error\?\.code!==-32022/);
 assert.match(script,/const discover=await request\('server\/discover'/);
 assert.match(script,/const missing=await client\.send\('tools\/list',\{\}\)/);
 assert.match(script,/missing\.error\?\.code!==-32602/);
 assert.match(script,/discover\.result\?\.cacheScope!=='private'/);
 assert.match(script,/discover\.result\?\.ttlMs!==0/);
 assert.match(script,/listed\.result\._meta\?\.\['io\.modelcontextprotocol\/serverInfo'\]/);
});

test('Phase 3B acceptance still uses disposable HMAC records and verified XPC boundaries',()=>{
 const script=source();
 assert.match(script,/createBlackBoxServer\(\{dataFile:auditFile,workspaceRoot:nativeRoot/);
 assert.match(script,/command\('\/usr\/bin\/codesign'/);
 assert.match(script,/validateMacWorkspaceBinding/);
 assert.match(script,/controller\.store\.verify\(\)/);
 assert.match(script,/audit\.includes\(content\)/);
 assert.match(script,/syntheticName&&nativeRoot/);
 assert.match(script,/MCP_SANDBOX:'off'/);
 assert.match(script,/if\(requiredInstalled&&process\.env\.MCP_SANDBOX!=='required'\)/);
 assert.match(script,/if\(!requiredInstalled&&process\.env\.MCP_SANDBOX==='required'\)/);
 assert.match(script,/gateway=await startGateway\(requiredInstalled\?/);
 assert.match(script,/verifyMacRequiredInstallation/);
 assert.match(script,/probeMacRequiredWorkspace/);
});
