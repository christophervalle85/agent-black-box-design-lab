/**
 * Experimental MCP downstream over the signed native App Sandbox/XPC note
 * worker. Only synthetic bbx-test-*.txt content, NOT production user data.
 * This Node control-plane subprocess itself is NOT sandboxed. It delegates
 * the only file operations to the signed native XPC host/worker. In required
 * mode, the gateway verifies a separately pinned Apple Team/signature and
 * exact sandbox workspace BEFORE spawning this fixed control-plane adapter.
 * The normal off-mode acceptance harness is retained separately. No generic
 * model-directed host filesystem access, shell, transport or export is added.
 */
import {spawn} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import {readJsonLines,sendJsonLine} from '../src/mcp-wire.mjs';
import {frameBridgeRequest,parseBridgeReply} from '../src/macos-xpc-bridge-wire.mjs';

const names=Object.freeze([
 {name:'read_note',description:'Read synthetic note inside the private native test workspace.',
  inputSchema:{type:'object',properties:{path:{type:'string'}},required:['path'],additionalProperties:false}},
 {name:'write_note',description:'Create a synthetic note only after gateway approval.',
  inputSchema:{type:'object',properties:{path:{type:'string'},content:{type:'string'}},
    required:['path','content'],additionalProperties:false}}
]);
const nativeRequired=process.env.MCP_SANDBOX==='required';
const host=nativeRequired?process.env.BLACKBOX_NATIVE_REQUIRED_XPC_HOST:
  process.env.BLACKBOX_EXPERIMENTAL_XPC_HOST;
const EXAMPLE_ERA='2025-11-25';
const nativeTimeout=process.env.BLACKBOX_XPC_TEST_FAULT==='1'?2500:8500;
let initialized=false;
let ended=false;
const nativeHosts=new Set();

/** Process-group isolation limits a native host surviving parent shutdown. */
function killNativeHost(child){
  if(!child?.pid)return;
  try{process.kill(-child.pid,'SIGKILL');}
  catch{try{child.kill('SIGKILL');}catch{}}
}
function stopActiveNativeHosts(){
  for(const child of nativeHosts)killNativeHost(child);
}
/** Called on the adapter's SIGTERM from the gateway's cancellation path. */
export function installNativeHostSupervisor(){
  process.once('SIGTERM',()=>{stopActiveNativeHosts();process.exit(143);});
  process.once('SIGINT',()=>{stopActiveNativeHosts();process.exit(130);});
  process.once('exit',stopActiveNativeHosts);
}
const send=(id,result)=>sendJsonLine(process.stdout,{jsonrpc:'2.0',id,result});
const reject=(id,code,message)=>sendJsonLine(process.stdout,{jsonrpc:'2.0',id,error:{code,message}});
const noDetails={isError:true,content:[{type:'text',text:'Native operation could not be completed safely.'}]};

export async function nativeRequest(executable,method,path,content='',{timeoutMs=8500}={}) {
  const frame=frameBridgeRequest(method,path,content);
  if(process.platform!=='darwin'||typeof executable!=='string'||!executable.startsWith('/'))
    throw Error('Native test host unavailable.');
  return new Promise((resolve,rejectPromise)=>{
    let data=Buffer.alloc(0);
    let settled=false,overflow=false,timedOut=false;
    const child=spawn(executable,[],{shell:false,detached:true,stdio:['pipe','pipe','pipe'],
      env:{PATH:'/usr/bin:/bin',HOME:process.env.HOME??'',TMPDIR:process.env.TMPDIR??'/tmp',
        LANG:'C.UTF-8',
        ...(process.env.BLACKBOX_XPC_TEST_FAULT==='1'?{BLACKBOX_XPC_TEST_FAULT:'1'}:{})}});
    nativeHosts.add(child);
    let stderrBuffer='',readyWritten=false;
    const readyFile=process.env.BLACKBOX_XPC_CANCEL_READY_FILE;
    const finish=(err,answer)=>{
      if(settled)return;
      settled=true;
      clearTimeout(timer);
      if(err)rejectPromise(err);else resolve(answer);
    };
    const timer=setTimeout(()=>{
      timedOut=true;
      killNativeHost(child);
    },timeoutMs);
    child.stdout.on('data',chunk=>{
      data=Buffer.concat([data,chunk]);
      if(data.length>2500){overflow=true;killNativeHost(child);}
    });
    child.stderr.on('data',chunk=>{
      // Opt-in synthetic test signal: no note contents or sensitive data.
      if(typeof readyFile!=='string'||!readyFile.startsWith('/')||readyWritten)return;
      stderrBuffer=(stderrBuffer+chunk.toString('utf8')).slice(-200);
      const marker=/BBX_CANCEL_(?:COMMITTED|STARTED)_PID=([1-9][0-9]{0,9})\n/.exec(stderrBuffer);
      if(!marker)return;
      readyWritten=true;
      if(Number(marker[1])!==child.pid){killNativeHost(child);return;}
      try{writeFileSync(readyFile,marker[1]+'\n',{mode:0o600,flag:'wx'});}
      catch{killNativeHost(child);}
    });
    child.stdin.on('error',()=>{});
    child.on('error',err=>finish(Error('Native host launch failed.')));
    child.on('close',(status,signal)=>{
      nativeHosts.delete(child);
      if(timedOut||overflow||status!==0||signal)
        return finish(Object.assign(
          Error('Native XPC result unavailable; write outcome may be unknown.'),
          {outcomeUnknown:true}));
      try{finish(null,parseBridgeReply(data));}
      catch{finish(Object.assign(Error('Malformed native XPC response.'),
        {outcomeUnknown:true}));}
    });
    child.stdin.end(frame);
  });
}

async function dispatch(message) {
  if(!message||message.jsonrpc!=='2.0'||!Object.hasOwn(message,'id')||
     (typeof message.id!=='number'&&typeof message.id!=='string')||
     typeof message.method!=='string')return;
  const {id,method}=message;
  if(method==='initialize') {
    if(initialized||message.params?.protocolVersion!==EXAMPLE_ERA)
      return reject(id,-32602,'Native test downstream supports one legacy initialization.');
    initialized=true;
    return send(id,{protocolVersion:EXAMPLE_ERA,capabilities:{tools:{}},
      serverInfo:{name:'agent-black-box-native-test-downstream',version:'0.8.0-dev.0'}});
  }
  if(!initialized)return reject(id,-32002,'Downstream not initialized.');
  if(method==='tools/list')return send(id,{tools:names});
  if(method!=='tools/call')return reject(id,-32601,'Only fixed native test notes allowed.');
  const name=message.params?.name;
  const args=message.params?.arguments;
  if(!args||typeof args!=='object'||Array.isArray(args)||
     !Object.keys(args).every(x=>x==='path'||x==='content')||
     !['read_note','write_note'].includes(name)||
     Object.keys(args).length!==(name==='read_note'?1:2)||
     typeof args.path!=='string'||
     (name==='write_note'&&typeof args.content!=='string'))
    return send(id,noDetails);
  try{
    const reply=await nativeRequest(host,name==='read_note'?'READ':'WRITE',
      args.path,name==='write_note'?args.content:'',{timeoutMs:nativeTimeout});
    if(!reply.ok)return send(id,noDetails);
    return send(id,{content:[{type:'text',text:
      name==='read_note'?reply.content:'Synthetic native note created with exclusive-new-file semantics.'}]});
  }catch(error){
    // Internal gateway adapter protocol: a timeout or crashed host after
    // dispatch can no longer prove whether a WRITE created its note.
    const unknown=name==='write_note'&&error?.outcomeUnknown===true;
    return send(id,unknown?{...noDetails,
      _meta:{'dev.agentblackbox/outcomeUnknown':true}}:noDetails);
  }
}
if(process.argv[1] && new URL('file://'+process.argv[1]).href===import.meta.url) {
  if(process.platform!=='darwin'||!['required','off'].includes(process.env.MCP_SANDBOX)||
     !host||!host.startsWith('/')||
     (nativeRequired&&process.env.BLACKBOX_EXPERIMENTAL_XPC_HOST)){
    console.error('Native MCP adapter requires verified native host; refusing untrusted launch.');
    process.exitCode=1;
  }else{
    installNativeHostSupervisor();
    readJsonLines(process.stdin,{maxBytes:8192,onMessage:msg=>{
      Promise.resolve(dispatch(msg)).catch(()=>{});
    },onError:()=>{ended=true;process.exitCode=1;}});
  }
}
