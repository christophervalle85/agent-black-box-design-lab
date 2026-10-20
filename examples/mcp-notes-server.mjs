// Deliberately limited, genuine downstream MCP stdio server for gateway tests.
// This program must never be launched directly as the client-facing gateway.
import { createInterface } from 'node:readline';
import { mkdirSync, openSync, readFileSync, closeSync, writeFileSync, realpathSync, statSync, constants } from 'node:fs';
import { join, resolve } from 'node:path';
import { resolveWorkspaceFile } from '../src/policy.mjs';
import { sendJsonLine } from '../src/mcp-wire.mjs';

const workspaceRoot = resolve(process.env.BLACKBOX_WORKSPACE_ROOT ?? join(process.cwd(), 'demo-workspace'));
mkdirSync(workspaceRoot, { recursive: true });
const tools = [
  { name:'read_note', description:'Read a file in the demo workspace.', inputSchema:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false}},
  { name:'write_note', description:'Create a NEW top-level .txt note. The gateway requires human approval.',inputSchema:{type:'object',properties:{path:{type:'string'},content:{type:'string'}},required:['path','content'],additionalProperties:false}},
  { name:'shell_command', description:'Intentionally unsafe test tool; MUST NOT be exposed or forwarded by gateway.',inputSchema:{type:'object'}}
];
function reply(id, result) { sendJsonLine(process.stdout, {jsonrpc:'2.0',id,result}); }
function error(id, code, message) { sendJsonLine(process.stdout,{jsonrpc:'2.0',id,error:{code,message}}); }

for await (const line of createInterface({input:process.stdin,crlfDelay:Infinity})) {
  let msg;
  try { msg=JSON.parse(line); } catch { continue; }
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') continue;
  if (!Object.hasOwn(msg,'id')) continue;
  const { id, method } = msg;
  if (method === 'initialize') { reply(id,{ protocolVersion:'2025-11-25', capabilities:{tools:{}}, serverInfo:{name:'blackbox-demo-mcp',version:'0.4.0'} }); continue; }
  if (method === 'tools/list') { reply(id,{ tools }); continue; }
  if (method !== 'tools/call') { error(id,-32601,'Unsupported method.'); continue; }
  const {name,arguments:args} = msg.params ?? {};
  // Defense in depth: validate again inside downstream, not only in gateway.
  try {
    if (name === 'read_note') {
      const check=resolveWorkspaceFile(args?.path,workspaceRoot);
      if (!check.ok || typeof args.path !== 'string') throw Error('Restricted file path.');
      const canonical=realpathSync(check.candidate);
      if (!statSync(canonical).isFile() || statSync(canonical).size > 65536) throw Error('File not readable.');
      reply(id,{ content:[{type:'text',text:readFileSync(canonical,'utf8').slice(0,4096)}] });
    } else if (name === 'write_note') {
      const check=resolveWorkspaceFile(args?.path,workspaceRoot);
      if (!check.ok || !/^[a-z0-9][a-z0-9_-]{0,39}\.txt$/i.test(args.path) || typeof args.content !== 'string' || !args.content.length || Buffer.byteLength(args.content)>2000) throw Error('Unsafe note.');
      let fd;
      try {
        fd=openSync(check.candidate, constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
        writeFileSync(fd,args.content,'utf8');
      } finally { if (fd !== undefined) closeSync(fd); }
      reply(id,{content:[{type:'text',text:'Note created with exclusive new-file semantics.'}]});
    } else { error(id,-32601,'Tool not permitted.'); }
  } catch { reply(id,{isError:true,content:[{type:'text',text:'Operation could not be completed safely.'}]}); }
}
