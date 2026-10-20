/**
 * v0.8 Phase 3D: XPC service abrupt-termination injection via real MCP→signed
 * native host→private XPC worker→audit acceptance using SYNTHETIC notes.
 *
 * This test is not MCP_SANDBOX=required and is not a production gateway
 * configuration. It creates an independent disposable HMAC audit history;
 * no real audit keys, credentials, user notes or old checkpoints are touched.
 */
import {PassThrough} from 'node:stream';
import {spawn,spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {copyFileSync,mkdirSync,mkdtempSync,readFileSync,rmSync} from 'node:fs';
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
if(args.some(arg=>arg!=='--modern')||args.filter(arg=>arg==='--modern').length>1)
  throw Error('Usage: npm run mcp:mac-xpc-mcp-acceptance [-- --modern]');
const modernMode=args.includes('--modern');
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
      return promise;
    },
    notify(method){sendJsonLine(input,{jsonrpc:'2.0',method});},
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
  if(process.platform!=='darwin')throw Error('Phase 3D requires real macOS.');
  if(process.env.MCP_SANDBOX==='required')
    throw Error('MCP_SANDBOX=required is NOT available on macOS; no fallback.');
  command('/usr/bin/xcrun',['--find','clang'],'Native Xcode compiler');
  const directory=mkdtempSync(join(tmpdir(),'bb-mcp-xpc-servicefault-'));
  const app=join(directory,'BlackBoxServiceFaultHost.app');
  const host=join(app,'Contents','MacOS','BlackBoxServiceFaultHost');
  const bundle=join(app,'Contents','XPCServices','BlackBoxServiceFaultWorker.xpc');
  const worker=join(bundle,'Contents','MacOS','BlackBoxServiceFaultWorker');
  let controller, gateway, client, input, output, syntheticName=null, nativeRoot=null;
  try{
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(sources,'ServiceFailureHost-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'ServiceFailureService-Info.plist'),join(bundle,'Contents','Info.plist'));
    command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',host,join(sources,'ServiceFailureBridgeHost.c')],'XPC service-failure test host build');
    command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',worker,join(sources,'ServiceFailureNotesService.m'),'-framework','Foundation'],'Native worker build');
    command('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-servicefault.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),bundle],
      'Private XPC worker signature');
    command('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-servicefault.host',app],'Native host signature');
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
    const childEnv={PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8',
      MCP_SANDBOX:'off',BLACKBOX_EXPERIMENTAL_XPC_HOST:host,
      BLACKBOX_WORKSPACE_ROOT:nativeRoot};
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

    // The XPC worker itself has a separate test-only _exit(86) branch,
    // which runs AFTER successful fsync of a synthetic new-file write but
    // BEFORE the XPC response. The normal AuthorityNotesService is unchanged.
    const pidBeforeReply=await nativeResult(host,Buffer.from('PID - 0\n','ascii'));
    const beforePid=Number(pidBeforeReply.content);
    if(!pidBeforeReply.ok||!Number.isSafeInteger(beforePid)||beforePid<=0)
      throw Error('Unable to identify the signed XPC service before injection.');
    console.log('PASS: Running XPC service PID obtained before worker termination.');

    const crash='bbx-test-xpc-crash-'+randomUUID().slice(0,8)+'.txt';
    syntheticName=crash;
    const content='Test-only service terminated after committing XPC note.';
    const called=request('tools/call',{
      name:'write_note',arguments:{path:crash,content}
    });
    const review=await pendingApproval(controller);
    if(review.filename!==crash||review.content!==content)
      throw Error('Wrong synthetic XPC service-failure approval request.');
    await decide(port,review.id,'approve');
    const result=await called;
    if(result.result?.isError!==true)
      throw Error('Post-commit service death incorrectly returned MCP success.');
    console.log('PASS: Abrupt XPC service termination returns a fail-closed MCP error.');

    // Filesystem effects may outlive the worker that performed them.
    const committed=await nativeResult(host,frameBridgeRequest('READ',crash));
    if(!committed.ok||committed.content!==content)
      throw Error('Test worker did not commit the exact note before exiting.');
    console.log('PASS: Test-only note survives after XPC service dies post-commit.');

    const pidAfterReply=await nativeResult(host,Buffer.from('PID - 0\n','ascii'));
    const afterPid=Number(pidAfterReply.content);
    if(!pidAfterReply.ok||!Number.isSafeInteger(afterPid)||afterPid<=0||
       afterPid===beforePid)
      throw Error('Distinct recovered XPC worker PID was not observed.');
    console.log('PASS: A different XPC service PID responds after terminated worker.');

    controller.store.verify();
    const records=readFileSync(auditFile,'utf8').trim().split('\n').map(x=>JSON.parse(x));
    const uncertain=records.filter(e=>
      e.ruleId==='MCP_OUTCOME_UNKNOWN'&&e.outcome==='error');
    if(uncertain.length!==1 || records.some(e=>e.ruleId==='MCP_OUTCOME_UNKNOWN'&&
       e.outcome==='success') || records.some(e=>e.summary?.includes('Tool completed')))
      throw Error('Post-commit XPC worker death was not recorded as UNKNOWN.');
    if(records.some(e=>JSON.stringify(e).includes(content)))
      throw Error('Synthetic note content was stored in the HMAC audit.');
    console.log('PASS: Authenticated audit records UNKNOWN after worker death, without note contents.');

    const viaMcp=await request('tools/call',{
      name:'read_note',arguments:{path:crash}
    });
    if(viaMcp.result?.isError || viaMcp.result?.content?.[0]?.text!==content)
      throw Error('Recovered XPC worker cannot serve a native-backed MCP read.');
    console.log('PASS: Real MCP reads recovered synthetic note from replacement XPC worker.');

    console.log('PASS: Experimental XPC SERVICE post-commit termination acceptance passed (synthetic-only).');
    console.log('NOTE: Simulated abrupt worker exit; not a malicious crash, production required-mode or signer attestation.');
  }finally{
    if(gateway)gateway.close();
    if(client)client.close();
    if(input)input.end();
    if(output)output.end();
    if(syntheticName&&nativeRoot){
      try{await nativeResult(host,frameBridgeRequest('REMOVE',syntheticName));}catch{}
    }
    if(controller){
      controller.approvalQueue.close();
      await new Promise(r=>controller.server.close(r));
    }
    // Only an isolated throwaway HMAC audit store is removed here.
    rmSync(directory,{recursive:true,force:true});
  }
}
main().catch(e=>{console.error('EXPERIMENTAL MCP-XPC SERVICE FAILURE ACCEPTANCE FAILED: '+e.message);
  process.exitCode=1;});
