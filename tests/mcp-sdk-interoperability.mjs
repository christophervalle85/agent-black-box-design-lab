/** Official @modelcontextprotocol/client v2 interoperability tests.
 * Run with: npm install --no-save --package-lock=false @modelcontextprotocol/client@2.3.1
 *           npm run test:mcp-sdk
 * This is a separate suite because the educational gateway has no runtime npm dependencies.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

const gateway = resolve(import.meta.dirname,'../src/mcp-gateway.mjs');
async function withClient(options, fn) {
  const home=mkdtempSync(join(tmpdir(),'agent-black-box-sdk-'));
  const workspace=join(home,'workspace');mkdirSync(workspace);
  writeFileSync(join(workspace,'notes.txt'),'Official SDK integration content');
  const client=new Client({name:'abb-official-sdk-interoperability',version:'0.5.0'},options);
  const transport=new StdioClientTransport({
    command:process.execPath,args:[gateway],
    env:{...process.env,MCP_WORKSPACE_ROOT:workspace,MCP_AUDIT_FILE:join(home,'audit.jsonl'),MCP_TOKEN_FILE:join(home,'missing-controller-token'),MCP_CONTROLLER_PORT:'1'}
  });
  try {await client.connect(transport);await fn(client);} finally {await client.close().catch(()=>{});rmSync(home,{recursive:true,force:true});}
}

async function checkTools(client) {
  const listed=await client.listTools();
  assert.deepEqual(listed.tools.map(x=>x.name),['read_note','write_note']);
  const read=await client.callTool({name:'read_note',arguments:{path:'notes.txt'}});
  assert.notEqual(read.isError,true);
  assert.match(read.content[0].text,/Official SDK integration content/);
  const blocked=await client.callTool({name:'read_note',arguments:{path:'.env'}});
  assert.equal(blocked.isError,true);
  assert.match(blocked.content[0].text,/DENY_SENSITIVE_FILE/);
  const extra=await client.callTool({name:'shell_command',arguments:{command:'pwd'}});
  assert.equal(extra.isError,true);
}

test('Official MCP SDK v2: legacy stdio session',()=>withClient({},async client=>{
  assert.equal(client.getProtocolEra(),'legacy');
  await checkTools(client);
}));

test('Official MCP SDK v2: modern 2026-07-28 pinned stdio session',()=>withClient({versionNegotiation:{mode:{pin:'2026-07-28'}}},async client=>{
  assert.equal(client.getProtocolEra(),'modern');
  await checkTools(client);
}));

test('Official MCP SDK v2: automatic protocol-era negotiation',()=>withClient({versionNegotiation:{mode:'auto'}},async client=>{
  assert.equal(client.getProtocolEra(),'modern');
  await checkTools(client);
}));
