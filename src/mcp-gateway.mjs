/**
 * Agent Black Box: dual-era, allowlisted MCP stdio gateway.
 * 2025-11-25: legacy initialize / initialized handshake.
 * 2026-07-28: per-request metadata and server/discover, no handshake.
 *
 * Deliberately NOT a generic pass-through: two safe demo tools only, one
 * fixed downstream executable. Do not expose this as a network service.
 */
import { spawn } from 'node:child_process';
import { readFileSync, realpathSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { AuditStore } from './audit.mjs';
import { guardedToolCall } from './monitor.mjs';
import { McpPeer, readJsonLines, sendJsonLine } from './mcp-wire.mjs';
import { downstreamLaunch } from './sandbox.mjs';
import { chooseGatewayLaunch } from './mcp-experimental-launch.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LEGACY = '2025-11-25';
const MODERN = '2026-07-28';
const SUPPORTED = Object.freeze([MODERN, LEGACY]);
const IDENTITY = Object.freeze({ name: 'agent-black-box-gateway', version: '0.6.0' });
const ALLOWED = Object.freeze({ read_note: 'file.read', write_note: 'file.write' });
const schema = { type: 'object', additionalProperties: false };
const EXPOSED_TOOLS = Object.freeze([
  { name: 'read_note', description: 'Read UTF-8 data from the demo workspace, subject to path and credential policy.', inputSchema: { ...schema, properties: { path: { type: 'string' } }, required: ['path'] } },
  { name: 'write_note', description: 'Create a new demo .txt note after one-time human approval of exact filename and content.', inputSchema: { ...schema, properties: { path: { type: 'string' }, content: { type: 'string' } }, required: ['path','content'] } }
]);
const fail = (id,code,message,data) => ({jsonrpc:'2.0',id,error:{code,message,...(data?{data}:{})}});
const toolFailure = message => ({content:[{type:'text',text:message}],isError:true});
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const versionMeta = params => object(params?._meta) ? params._meta['io.modelcontextprotocol/protocolVersion'] : undefined;
const stamp = result => ({...result,ttlMs:result.ttlMs??0,cacheScope:result.cacheScope??'private',_meta:{...(object(result._meta)?result._meta:{}),'io.modelcontextprotocol/serverInfo':IDENTITY},resultType:'complete'});

function validArgs(name,args) {
  if (!object(args) || Object.keys(args).some(key => !['path','content'].includes(key))) return false;
  if (typeof args.path !== 'string') return false;
  if (name === 'read_note') return Object.keys(args).length === 1;
  return name === 'write_note' && Object.keys(args).length === 2 && typeof args.content === 'string';
}

// In-process experimentalLaunch is ONLY for the isolated macOS acceptance
// harness. No CLI environment variable can enable it; required mode still
// refuses macOS execution. Remove before production distribution.
export async function startGateway({ input=process.stdin, output=process.stdout, env=process.env, onReady, experimentalLaunch }={}) {
  const workspaceRoot = realpathSync(resolve(env.MCP_WORKSPACE_ROOT ?? join(root,'demo-workspace')));
  const auditFile = resolve(env.MCP_AUDIT_FILE ?? join(root,'data','audit.jsonl'));
  const tokenFile = resolve(env.MCP_TOKEN_FILE ?? join(dirname(auditFile),'mcp-controller-token'));
  const port = Number(env.MCP_CONTROLLER_PORT ?? 4317);
  if (!Number.isSafeInteger(port) || port<1 || port>65535) throw Error('Invalid MCP_CONTROLLER_PORT.');
  const store = new AuditStore(auditFile);
  const standard = downstreamLaunch({env,workspaceRoot,scriptPath:fileURLToPath(new URL('../examples/mcp-notes-server.mjs',import.meta.url))});
  const launch = chooseGatewayLaunch({
    standard,experimental:experimentalLaunch,platform:process.platform,mode:env.MCP_SANDBOX??'off'
  });
  const downstream = spawn(launch.command,launch.args,{
    cwd:root, shell:false, stdio:['pipe','pipe','inherit'], env:launch.env
  });
  const peer = new McpPeer(downstream,{timeoutMs:12000});
  let era = null; // one process cannot switch from modern to legacy (or reverse)
  let initialized = false, closed = false, downstreamPromise;
  const active = new Map();
  const runId = randomUUID();
  const write = msg => { if(!closed) sendJsonLine(output,msg); };
  const answer = (id,result) => write({jsonrpc:'2.0',id,result:era==='modern'?stamp(result):result});
  const error = (id,code,message,data) => write(fail(id,code,message,data));
  const incompatible = (id,version) => error(id,-32022,'Unsupported protocol version.',{supported:SUPPORTED,requested:version ?? null});

  // Downstream is pinned to the bundled, audited 2025-era notes executable.
  // It needs the initialized notification BEFORE tools/list (the v0.4 order
  // violated the legacy lifecycle). A single promise prevents init races.
  async function ensureDownstream() {
    if (!downstreamPromise) downstreamPromise = (async()=>{
      const result=await peer.request('initialize',{protocolVersion:LEGACY,capabilities:{},clientInfo:IDENTITY});
      if(result.protocolVersion!==LEGACY || !object(result.capabilities?.tools))throw Error('Unsupported downstream protocol/capabilities.');
      peer.notify('notifications/initialized');
      const listed=await peer.request('tools/list',{});
      if(!Array.isArray(listed?.tools) || !['read_note','write_note'].every(name => listed.tools.filter(x=>x?.name===name).length===1)) throw Error('Required downstream tools missing or duplicated.');
      // An allowlisted name must actually have the expected input interface.
      for (const name of Object.keys(ALLOWED)) {
        const tool=listed.tools.find(x=>x.name===name);
        if(!object(tool.inputSchema) || tool.inputSchema.type!=='object' || !object(tool.inputSchema.properties) ||
          !Array.isArray(tool.inputSchema.required) || !(['path',...(name==='write_note'?['content']:[])].every(key=>tool.inputSchema.required.includes(key) && tool.inputSchema.properties[key]?.type==='string')))
          throw Error('Downstream tool schema changed; refusing startup.');
      }
    })().catch(err=>{peer.close(err);throw err;});
    return downstreamPromise;
  }

  function checkModern(id,params){
    const meta=params?._meta;
    if(!object(params)||!object(meta) || typeof meta['io.modelcontextprotocol/protocolVersion']!=='string' ||
        !object(meta['io.modelcontextprotocol/clientCapabilities']) ||
        (meta['io.modelcontextprotocol/clientInfo']!==undefined &&
          (!object(meta['io.modelcontextprotocol/clientInfo']) || typeof meta['io.modelcontextprotocol/clientInfo'].name!=='string' || typeof meta['io.modelcontextprotocol/clientInfo'].version!=='string'))) {
      error(id,-32602,'Missing or invalid modern MCP request metadata.'); return false;
    }
    const version=versionMeta(params);
    if(version!==MODERN){incompatible(id,version);return false;}
    return true;
  }

  async function requestApproval(request,{signal}) {
    if(signal.aborted)return {approved:false};
    const token = readFileSync(tokenFile,'utf8').trim();
    const body=JSON.stringify({id:request.id,runId:request.runId,agentId:request.agentId,tool:request.tool,args:request.args});
    const response=await fetch(`http://127.0.0.1:${port}/api/mcp/approval`,{
      method:'POST',headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},body,
      signal:AbortSignal.any([signal,AbortSignal.timeout(95000)])
    });
    if(!response.ok)return {approved:false};
    const result=await response.json();
    return {approved:result.approved===true && !signal.aborted};
  }

  // Track in-flight tool calls before asynchronous downstream discovery.
  async function dispatch(msg) {
    const {id,method}=msg;
    if(method!=='tools/call')return dispatchCore(msg,null);
    if(active.has(id))return error(id,-32600,'Duplicate active request ID.');
    if(active.size>=8)return error(id,-32000,'Gateway concurrency limit exceeded.');
    const abort=new AbortController();
    active.set(id,abort);
    try{return await dispatchCore(msg,abort);}
    finally{active.delete(id);}
  }

  async function dispatchCore(msg,abort) {
    const {id,method}=msg;
    // Allow modern clients to probe without an initialize handshake.
    if(method==='server/discover') {
      if(era==='legacy')return error(id,-32601,'Method not supported by legacy MCP session.');
      if(!checkModern(id,msg.params))return;
      era='modern'; // pin the protocol era before async initialization
      try{await ensureDownstream();}catch{return error(id,-32000,'MCP downstream unavailable.');}
      return answer(id,{supportedVersions:[MODERN],capabilities:{tools:{}},ttlMs:0,cacheScope:'private'});
    }
    if(method==='initialize') {
      if(era || !object(msg.params) || typeof msg.params.protocolVersion!=='string')return error(id,-32600,'Invalid or repeated MCP initialization.');
      // For backwards compatibility the server only negotiates our tested
      // legacy protocol, rather than falsely echoing unsupported revisions.
      if(msg.params.protocolVersion!==LEGACY)return error(id,-32602,'Legacy protocol 2025-11-25 required.');
      if(!object(msg.params.capabilities)||!object(msg.params.clientInfo))return error(id,-32602,'Invalid client initialization parameters.');
      era='legacy'; // prevent concurrent or mixed-era handshakes
      try{await ensureDownstream();}catch{return error(id,-32000,'MCP downstream initialization failed.');}
      return answer(id,{protocolVersion:LEGACY,capabilities:{tools:{}},serverInfo:IDENTITY});
    }
    // Modern clients MAY skip discovery and send a versioned tools/list or
    // tools/call immediately (notably SDK v2 with a pinned/cached era).
    // The per-request metadata, not server/discover, is the authority.
    if(!era && versionMeta(msg.params)!==undefined){
      if(!checkModern(id,msg.params))return;
      era='modern';
      try{await ensureDownstream();}catch{
        if(abort?.signal.aborted)return;
        return error(id,-32000,'MCP downstream unavailable.');
      }
    }
    if(abort?.signal.aborted)return;
    if(!era)return error(id,-32002,'Initialize or send a versioned modern request first.');
    if(era==='legacy' && !initialized)return error(id,-32002,'Legacy MCP session not initialized.');
    if(era==='modern' && !checkModern(id,msg.params))return;
    if(method==='ping' && era==='legacy')return answer(id,{});
    if(method==='tools/list') {
      if((msg.params!==undefined && !object(msg.params)) || (msg.params?.cursor!==undefined && msg.params.cursor!==null))return error(id,-32602,'No tool pagination supported.');
      return answer(id,{tools:EXPOSED_TOOLS});
    }
    if(method!=='tools/call')return error(id,-32601,'Method not permitted by MCP gateway.');
    if(!object(msg.params) || typeof msg.params.name!=='string' || msg.params.name.length>128 || !object(msg.params.arguments))return error(id,-32602,'Invalid MCP tool parameters.');
    if(JSON.stringify(msg.params.arguments).length>3500)return error(id,-32602,'Tool arguments too large.');
    // Disallow modern multi-round-trip request payloads we cannot enforce.
    if(era==='modern' && (msg.params.requestState!==undefined || msg.params.inputResponses!==undefined))return error(id,-32602,'Multi-round-trip MCP requests not supported.');
    const {name}=msg.params, args=msg.params.arguments;
    if(abort.signal.aborted)return;
    try {
      const tool=Object.hasOwn(ALLOWED,name)?ALLOWED[name]:`mcp.unknown.${name.slice(0,40)}`;
      const safeArgs=validArgs(name,args)?structuredClone(args):{};
      const checked=await guardedToolCall({
        agentId:'mcp-client',runId,tool,args:safeArgs,store,workspaceRoot,
        source:'mcp-stdio',recordStart:true,signal:abort.signal,
        requestApproval:req=>requestApproval(req,{signal:abort.signal}),
        execute:async fixedArgs=>{
          if(abort.signal.aborted)throw Error('MCP call cancelled.');
          let response;
          try {
            response=await peer.request('tools/call',{name,arguments:fixedArgs},{signal:abort.signal});
          }catch(error){
            // The write may have committed before the downstream transport
            // died or timed out. Never log that uncertainty as a known denial.
            if(name==='write_note')error.outcomeUnknown=true;
            throw error;
          }
          if(!Array.isArray(response?.content)||response.isError) {
            const error=new Error('Downstream tool failed.');
            if(name==='write_note' &&
              response?._meta?.['dev.agentblackbox/outcomeUnknown']===true)
              error.outcomeUnknown=true;
            throw error;
          }
          return {value:response,summary:`MCP tool ${name} executed; output omitted from audit.`};
        }
      });
      if(abort.signal.aborted)return;
      if(checked.event.decision==='block')return answer(id,toolFailure(`Denied: ${checked.event.ruleId}`));
      if(checked.event.outcome==='error')return answer(id,toolFailure('Downstream MCP tool failed; see local audit.'));
      return answer(id,checked.result);
    }catch {if(!abort.signal.aborted)answer(id,toolFailure('MCP gateway unavailable; request not authorized.'));}
  }

  const unlisten=readJsonLines(input,{
    maxBytes:16384,
    onMessage:msg=>{
      if(closed)return;
      const hasId=Object.hasOwn(msg,'id');
      if(msg.method==='notifications/cancelled' && !hasId){active.get(msg.params?.requestId)?.abort();return;}
      if(msg.method==='notifications/initialized' && !hasId && era==='legacy'){initialized=true;return;}
      if(!hasId || (typeof msg.id!=='string'&&typeof msg.id!=='number'))return;
      if(typeof msg.method!=='string')return error(msg.id,-32600,'Invalid MCP request.');
      dispatch(msg).catch(()=>{try{error(msg.id,-32603,'MCP internal failure.');}catch{}});
    },
    onError:()=>close()
  });
  function close(){if(closed)return;closed=true;unlisten();for(const ctrl of active.values())ctrl.abort();peer.close();}
  input.on('end',close);
  process.once('SIGTERM',close);
  onReady?.({close,downstream,peer,sandbox:launch.description});
  return {close,downstream,peer};
}

if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  startGateway().catch(err=>{console.error('MCP gateway failed to start:',err.message);process.exitCode=1;});
}
