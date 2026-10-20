/**
 * v0.8 Phase 3E: post-commit MCP cancellation and native-host supervision.
 * native host→private XPC worker→audit acceptance using SYNTHETIC notes.
 *
 * This test is not MCP_SANDBOX=required and is not a production gateway
 * configuration. It creates an independent disposable HMAC audit history;
 * no real audit keys, credentials, user notes or old checkpoints are touched.
 */
import {PassThrough} from 'node:stream';
import {spawn,spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {copyFileSync,mkdirSync,mkdtempSync,readFileSync,rmSync,existsSync} from 'node:fs';
import {tmpdir,homedir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {once} from 'node:events';
import {createBlackBoxServer} from '../src/server.mjs';
import {startGateway} from '../src/mcp-gateway.mjs';
import {readJsonLines,sendJsonLine} from '../src/mcp-wire.mjs';
import {frameBridgeRequest,parseBridgeReply} from '../src/macos-xpc-bridge-wire.mjs';
import {validateMacWorkspaceBinding} from '../src/macos-workspace-binding.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const args=process.argv.slice(2);
if(args.some(arg=>!['--modern','--during'].includes(arg)) ||
   args.filter(arg=>arg==='--modern').length>1 ||
   args.filter(arg=>arg==='--during').length>1)
  throw Error('Usage: npm run mcp:mac-xpc-cancellation [-- --modern] [-- --during]');
const modernMode=args.includes('--modern');
const duringMode=args.includes('--during');
const MODERN='2026-07-28';
const META=Object.freeze({
  'io.modelcontextprotocol/protocolVersion':MODERN,
  'io.modelcontextprotocol/clientCapabilities':{},
  'io.modelcontextprotocol/clientInfo':{name:'native-xpc-modern-acceptance',version:'0.8.0'}
});
const modern=params=>({...params,_meta:{...META}});
function command(tool,args,label,timeout=90000) {
  const r=spawnSync(tool,args,{encoding:'utf8',timeout,maxBuffer:128*1024});
  if(r.error||r.status!==0)
    throw Error(label+' failed: '+(r.error?.message??r.stderr?.trim()??'unknown')+' (exit '+r.status+')');
  return r;
}
function verifySigner(app,service) {
  command('/usr/bin/codesign',['--verify','--deep','--strict',app],'Host+XPC nested signature');
  command('/usr/bin/codesign',['--verify','--strict',service],'Native worker signature');
  const info=command('/usr/bin/codesign',['--display','--entitlements','-','--xml',service],'Native worker entitlement');
  const xml=info.stdout+'\n'+info.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Native notes worker has no App Sandbox entitlement.');
  if(/<key>com\.apple\.security\.network\.(?:client|server)<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Native notes worker has unexpected network entitlement.');
  console.log('PASS: Signed private XPC worker entitlements and nested app signature verified.');
}
function nativeCall(exe,frame,{timeoutMs=11000}={}) {
  return new Promise(resolve=>{
    let data=Buffer.alloc(0),error=null,tooMuch=false,timedOut=false;
    const child=spawn(exe,[],{shell:false,stdio:['pipe','pipe','pipe'],
      env:{HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8',PATH:'/usr/bin:/bin'}});
    child.stdout.on('data',chunk=>{
      data=Buffer.concat([data,chunk]);
      if(data.length>3000){tooMuch=true;child.kill('SIGKILL');}
    });
    child.stderr.on('data',()=>{});
    child.stdin.on('error',()=>{});
    child.on('error',e=>{error=e.message;});
    const timeout=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeoutMs);
    child.stdin.end(frame);
    child.on('close',(status,signal)=>{
      clearTimeout(timeout);
      resolve({status,signal,error,timedOut,tooMuch,data});
    });
  });
}
async function nativeResult(exe,frame) {
  const r=await nativeCall(exe,frame);
  if(r.status!==0||r.signal||r.error||r.timedOut||r.tooMuch)
    throw Error('Native XPC host unavailable; in-flight writes have UNKNOWN outcomes.');
  return parseBridgeReply(r.data);
}
function clientFor(input,output){
  const pending=new Map();
  let id=0;
  const detach=readJsonLines(output,{maxBytes:32768,onMessage:message=>{
    const wait=pending.get(message.id);
    if(!wait)return;
    pending.delete(message.id);clearTimeout(wait.timer);wait.resolve(message);
  },onError:error=>{
    for(const wait of pending.values()){clearTimeout(wait.timer);wait.reject(error);}
    pending.clear();
  }});
  return {
    send(method,params={},timeoutMs=25000){
      const next=++id;
      const promise=new Promise((resolve,reject)=>{
        const timer=setTimeout(()=>{pending.delete(next);reject(Error('MCP gateway request timeout'));},timeoutMs);
        pending.set(next,{resolve,reject,timer});
        sendJsonLine(input,{jsonrpc:'2.0',id:next,method,params});
      });
      return Object.assign(promise,{requestId:next});
    },
    notify(method,params={}){sendJsonLine(input,{jsonrpc:'2.0',method,params});},
    close(){detach();for(const p of pending.values()){clearTimeout(p.timer);p.reject(Error('Client closed'));}pending.clear();}
  };
}
async function pendingApproval(controller,timeoutMs=6500){
  const began=Date.now();
  while(Date.now()-began<timeoutMs){
    const item=controller.approvalQueue.list()[0];
    if(item)return item;
    await new Promise(r=>setTimeout(r,35));
  }
  throw Error('No review request reached the real approval controller.');
}
async function decide(port,id,decision){
  const origin='http://127.0.0.1:'+port;
  const r=await fetch(origin+'/api/approvals/'+encodeURIComponent(id)+'/decision',{
    method:'POST',headers:{origin,'content-type':'application/json'},
    body:JSON.stringify({decision})
  });
  if(r.status!==200)throw Error('Dashboard approval decision endpoint returned '+r.status);
}
async function main(){
  if(process.platform!=='darwin')throw Error('Phase 3E requires real macOS.');
  if(process.env.MCP_SANDBOX==='required')
    throw Error('MCP_SANDBOX=required is NOT available on macOS; no fallback.');
  command('/usr/bin/xcrun',['--find','clang'],'Native Xcode compiler');
  const directory=mkdtempSync(join(tmpdir(),'bb-mcp-xpc-cancellation-'));
  const app=join(directory,'BlackBoxCancelHost.app');
  const host=join(app,'Contents','MacOS','BlackBoxCancelHost');
  const bundle=join(app,'Contents','XPCServices','BlackBoxCancelWorker.xpc');
  const worker=join(bundle,'Contents','MacOS','BlackBoxCancelWorker');
  let controller, gateway, client, input, output, syntheticName=null, syntheticMarker=null, nativeRoot=null;
  try{
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(sources,'CancellationHost-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'CancellationService-Info.plist'),join(bundle,'Contents','Info.plist'));
    command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',host,join(sources,'CancellationBridgeHost.c')],'XPC service-failure test host build');
    command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',worker,join(sources,'CancellationNotesService.m'),'-framework','Foundation'],'Native worker build');
    command('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-cancel.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),bundle],
      'Private XPC worker signature');
    command('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-cancel.host',app],'Native host signature');
    verifySigner(app,bundle);
    const location=await nativeResult(host,Buffer.from('ROOT - 0\n','ascii'));
    if(!location.ok)throw Error('Native service did not report a workspace.');
    nativeRoot=location.content;
    const unrelated=join(root,'demo-workspace');
    let mismatch=false;
    try{validateMacWorkspaceBinding({configuredRoot:unrelated,reportedRoot:nativeRoot});}
    catch{mismatch=true;}
    if(!mismatch)throw Error('Unexpected acceptance of unrelated demo workspace.');
    validateMacWorkspaceBinding({configuredRoot:nativeRoot,reportedRoot:nativeRoot});
    console.log('PASS: Real XPC Documents identity bound; unrelated workspace denied.');

    const auditFile=join(directory,'audit','events.jsonl');
    controller=createBlackBoxServer({dataFile:auditFile,workspaceRoot:nativeRoot,
      agentClient:{status:async()=>({reachable:false})}});
    controller.server.listen(0,'127.0.0.1');
    await once(controller.server,'listening');
    const port=controller.server.address().port;
    input=new PassThrough();output=new PassThrough();
    client=clientFor(input,output);
    const testEnv={MCP_WORKSPACE_ROOT:nativeRoot,MCP_AUDIT_FILE:auditFile,
      MCP_CONTROLLER_PORT:String(port),MCP_TOKEN_FILE:controller.tokenFile,
      MCP_SANDBOX:'off'};
    const cancellationReady=join(directory,duringMode?'native-cancel-started.pid':'native-cancel-committed.pid');
    const childEnv={PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8',
      MCP_SANDBOX:'off',BLACKBOX_EXPERIMENTAL_XPC_HOST:host,
      BLACKBOX_WORKSPACE_ROOT:nativeRoot,
      BLACKBOX_XPC_CANCEL_READY_FILE:cancellationReady};
    gateway=await startGateway({input,output,env:testEnv,experimentalLaunch:{
      command:process.execPath,
      args:[join(root,'examples','mcp-macos-xpc-mcp-downstream.mjs')],
      env:childEnv,description:'EXPERIMENTAL native XPC synthetic-only acceptance'
    }});
    // Real client-visible MCP calls use the same gateway and downstream.
    // Modern requests carry per-request metadata; no legacy handshake.
    const request=(method,params={})=>client.send(method,
      modernMode?modern(params):params);
    if(modernMode) {
      const wrong=await client.send('server/discover',{
        _meta:{...META,'io.modelcontextprotocol/protocolVersion':'2099-01-01'}
      });
      if(wrong.error?.code!==-32022)
        throw Error('Modern unknown protocol version was not rejected.');
      const discover=await request('server/discover',{});
      if(discover.result?.supportedVersions?.join(',')!==MODERN ||
         discover.result?.resultType!=='complete' ||
         discover.result?.cacheScope!=='private' ||
         discover.result?.ttlMs!==0)
        throw Error('Native-backed modern MCP discovery or metadata invalid.');
      const missing=await client.send('tools/list',{});
      if(missing.error?.code!==-32602)
        throw Error('Modern MCP requests missing metadata were unexpectedly allowed.');
      console.log('PASS: Modern MCP discovery/version/missing-metadata fail-closed checks.');
    }else{
      const initialization=await client.send('initialize',{protocolVersion:'2025-11-25',
        capabilities:{},clientInfo:{name:'native-integration-test',version:'0.8.0'}});
      if(initialization.result?.protocolVersion!=='2025-11-25')
        throw Error('Experimental legacy MCP initialization failed.');
      client.notify('notifications/initialized');
    }
    const listed=await request('tools/list',{});
    if(listed.result?.tools?.map(x=>x.name).join(',')!=='read_note,write_note')
      throw Error('Gateway advertised an unexpected native tool interface.');
    if(modernMode&&(listed.result.resultType!=='complete'||
       listed.result._meta?.['io.modelcontextprotocol/serverInfo']?.name!=='agent-black-box-gateway'))
      throw Error('Modern list response omitted MCP server attribution.');
    console.log('PASS: '+(modernMode?'Modern':'Legacy')+' MCP gateway discovers only allowlisted native note tools.');

    const nonce=randomUUID().slice(0,8);
    const name='bbx-test-cancel-'+(duringMode?'during-':'after-')+nonce+'.txt';
    syntheticName=name;
    if(duringMode)syntheticMarker='bbx-test-cancel-running-'+nonce+'.txt';
    const contents=duringMode
      ?'Synthetic worker-cancel test: content must not be committed.'
      :'Synthetic cancelled MCP write committed before native host responded.';
    const issued=request('tools/call',{
      name:'write_note',arguments:{path:name,content:contents}
    });
    let unexpectedlyAnswered=false;
    issued.then(()=>{unexpectedlyAnswered=true;},()=>{}); // cleanup rejects pending cancellation.
    const approval=await pendingApproval(controller);
    if(approval.filename!==name||approval.content!==contents)
      throw Error('MCP cancellation approval was not for exact synthetic write.');
    await decide(port,approval.id,'approve');

    // Post-commit: native host emits its PID after service acknowledgement.
    // In-flight: host emits its PID before dispatch and the XPC worker
    // creates a separate private marker only after execution begins.
    const readySince=Date.now();
    let nativePid=0;
    while(Date.now()-readySince<7000){
      try{
        nativePid=Number(readFileSync(cancellationReady,'utf8').trim());
        if(Number.isSafeInteger(nativePid)&&nativePid>0 &&
           (!duringMode || (existsSync(join(nativeRoot,syntheticMarker)) &&
             readFileSync(join(nativeRoot,syntheticMarker),'utf8')==='worker-running\n')))
          break;
      }catch(error){if(error.code!=='ENOENT')throw error;}
      await new Promise(r=>setTimeout(r,40));
    }
    if(!Number.isSafeInteger(nativePid)||nativePid<=0)
      throw Error('Native cancellation host PID marker was not observed.');
    const aliveBefore=command('/bin/ps',['-o','stat=','-p',String(nativePid)],'Check native host before cancel');
    if(!aliveBefore.stdout.trim()||aliveBefore.stdout.trim().startsWith('Z'))
      throw Error('Native host already exited before cancellation.');
    if(duringMode) {
      if(!existsSync(join(nativeRoot,syntheticMarker)))
        throw Error('XPC service execution marker disappeared before cancellation.');
      if(existsSync(join(nativeRoot,name)))
        throw Error('In-flight worker already created note before cancellation.');
      console.log('PASS: Real XPC worker was executing before MCP cancellation; note not yet created.');
    }else{
      console.log('PASS: Native host remained alive after committed XPC write, before MCP cancellation.');
    }

    client.notify('notifications/cancelled',{requestId:issued.requestId,
      reason:duringMode?'Synthetic in-flight worker cancellation acceptance.':
        'Synthetic-only post-commit cancellation acceptance.'});

    // After cancellation, the gateway terminates its downstream adapter.
    // The adapter MUST terminate its independent native host process group.
    let disappeared=false;
    const waiting=Date.now();
    while(Date.now()-waiting<7000) {
      const stat=spawnSync('/bin/ps',['-o','stat=','-p',String(nativePid)],{
        encoding:'utf8',timeout:1000});
      const state=stat.stdout?.trim()??'';
      if(stat.status!==0||!state||state.startsWith('Z')){disappeared=true;break;}
      await new Promise(r=>setTimeout(r,50));
    }
    if(!disappeared)throw Error('Cancelled MCP request left a running native host process.');
    console.log('PASS: MCP cancellation terminated the outstanding native host process.');

    if(duringMode){
      // Invalidation is cooperative. The separate worker queue checks a
      // per-peer cancellation latch and removes its own execution marker.
      const started=Date.now();
      while(existsSync(join(nativeRoot,syntheticMarker))&&Date.now()-started<6500)
        await new Promise(r=>setTimeout(r,40));
      if(existsSync(join(nativeRoot,syntheticMarker)))
        throw Error('XPC worker never completed cooperative cancellation.');
      const absent=await nativeResult(host,frameBridgeRequest('READ',name));
      if(absent.ok||existsSync(join(nativeRoot,name)))
        throw Error('XPC worker committed a synthetic note after cancellation.');
      console.log('PASS: XPC worker observed lost peer, exited in-flight work and did not create note.');
    }else{
      // The native file committed *before* cancellation. Never imply rollback.
      const committed=await nativeResult(host,frameBridgeRequest('READ',name));
      if(!committed.ok||committed.content!==contents)
        throw Error('Committed XPC synthetic note absent after cancellation.');
      console.log('PASS: Post-cancellation inspection found the already committed synthetic note.');
    }

    const auditSince=Date.now();
    let uncertainEvents=[];
    while(Date.now()-auditSince<6500){
      controller.store.verify();
      const lines=readFileSync(auditFile,'utf8').trim().split('\n').filter(Boolean);
      const events=lines.map(line=>JSON.parse(line));
      uncertainEvents=events.filter(event=>event.ruleId==='MCP_OUTCOME_UNKNOWN'&&event.outcome==='error');
      if(uncertainEvents.length>0)break;
      await new Promise(r=>setTimeout(r,35));
    }
    controller.store.verify();
    if(uncertainEvents.length!==1||unexpectedlyAnswered)
      throw Error('Cancellation did not yield one UNKNOWN HMAC event without a false MCP answer.');
    const audit=readFileSync(auditFile,'utf8');
    if(audit.includes(contents)||audit.includes('MCP tool write_note executed'))
      throw Error('Cancelled write was recorded as success or note contents leaked.');
    console.log('PASS: Authenticated audit records cancelled write as UNKNOWN, not rolled back.');

    // Cancellation deliberately makes this downstream unavailable. No
    // automatic unsandboxed fallback or blind replay may occur.
    const afterCancel=await request('tools/call',{name:'read_note',arguments:{path:name}});
    if(afterCancel.result?.isError!==true)
      throw Error('Gateway used unexpected downstream after cancellation.');
    console.log('PASS: Gateway refuses new native requests after cancelling its downstream.');

    console.log('PASS: Experimental '+(duringMode?'in-flight XPC worker':'post-commit')+
      ' cancellation acceptance (synthetic-only).');
    if(!duringMode)
      console.log('NOTE: XPC work already completed before cancel; run --during for the in-flight experiment.');
    else
      console.log('NOTE: Cooperative cancellation is only demonstrated for this instrumented test worker, not production writes.');
  }finally{
    if(gateway)gateway.close();
    if(client)client.close();
    if(input)input.end();
    if(output)output.end();
    if(syntheticName&&nativeRoot){
      try{await nativeResult(host,frameBridgeRequest('REMOVE',syntheticName));}catch{}
    }
    if(syntheticMarker&&nativeRoot){
      try{await nativeResult(host,frameBridgeRequest('REMOVE',syntheticMarker));}catch{}
    }
    if(controller){
      controller.approvalQueue.close();
      await new Promise(r=>controller.server.close(r));
    }
    // Only an isolated throwaway HMAC audit store is removed here.
    rmSync(directory,{recursive:true,force:true});
  }
}
main().catch(e=>{console.error('EXPERIMENTAL MCP-XPC CANCELLATION FAILED: '+e.message);
  process.exitCode=1;});
