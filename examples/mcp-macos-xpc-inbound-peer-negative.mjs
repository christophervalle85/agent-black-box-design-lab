/**
 * Real-macOS negative acceptance: an ad-hoc-signed host cannot call an XPC
 * notes worker that enforces Apple's same-team and host signing identifier
 * requirement on the *incoming* peer connection.
 *
 * Build and sign only a throwaway synthetic app + nested private worker.
 * Uses real native worker code; no Developer ID, required mode, or MCP
 * operations are enabled. Timeouts alone NEVER establish authentication.
 */
import {spawn,spawnSync} from 'node:child_process';
import {
  existsSync,mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync
} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseBridgeReply} from '../src/macos-xpc-bridge-wire.mjs';
import {validateMacWorkspaceBinding} from '../src/macos-workspace-binding.mjs';
import {inspectMinimalWorkerEntitlements} from '../src/macos-signer-trust.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const identities=Object.freeze({
  baseline:Object.freeze({
    host:'dev.agentblackbox.xpc-inbound-baseline.host',
    worker:'dev.agentblackbox.xpc-inbound-baseline.worker',
    clientFlag:'-DBBX_TEST_INBOUND_BASELINE_CLIENT=1'
  }),
  restricted:Object.freeze({
    host:'dev.agentblackbox.xpc-inbound-restricted.host',
    worker:'dev.agentblackbox.xpc-inbound-restricted.worker',
    clientFlag:'-DBBX_TEST_INBOUND_CLIENT=1'
  })
});
const armedName='bbx-test-inbound-armed.txt';
const deliveredName='bbx-test-inbound-delivered.txt';
function command(exe,args,label,{input,timeout=30000}={}){
  const result=spawnSync(exe,args,{
    encoding:'utf8',timeout,input,maxBuffer:128*1024,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8'}
  });
  if(result.error||result.signal||result.status!==0)
    throw Error(label+' failed (status '+result.status+'): '+
      (result.error?.message??result.stderr?.slice(0,500)??'no details'));
  return result;
}
function nativeHost(host){
  return command(host,[],'Unrestricted native ROOT baseline',
    {input:'ROOT - 0\n',timeout:12000});
}
function readNativeRoot(host){
  const text=nativeHost(host).stdout;
  const identity=parseBridgeReply(Buffer.from(text,'utf8'));
  if(!identity.ok)throw Error('Unrestricted baseline returned no native workspace.');
  validateMacWorkspaceBinding({
    configuredRoot:identity.content,reportedRoot:identity.content
  });
  return identity.content;
}
function workerProcess(pid) {
  if(!Number.isSafeInteger(pid)||pid<=0)
    return {alive:false,state:'invalid-pid',command:''};
  const r=spawnSync('/bin/ps',['-o','stat=','-o','comm=','-p',String(pid)],{
    encoding:'utf8',timeout:1500,maxBuffer:1200
  });
  const line=r.stdout?.trim()??'';
  const match=/^(\S+)\s+(.+)$/.exec(line);
  const command=match?.[2]??'';
  const state=match?.[1]??'not-present';
  const expected=command.split('/').at(-1)==='BlackBoxAuthorityWorker';
  return {alive:r.status===0 && expected && !state.startsWith('Z') &&
    !state.startsWith('X'),state,command};
}
function liveWorker(pid){return workerProcess(pid).alive;}
export function assessInboundPeerRejection({armedPid,workerAlive,deliverySeen,
  workerMarkerFresh,hostAttempted,hostStdout='',hostStderr='',
  hostExited=false,hostExitCode=null,hostExitSignal=null,
  hostError=null,hostOverflow=false}={}) {
  if(!workerMarkerFresh || !Number.isSafeInteger(armedPid)||armedPid<=0 ||
     workerAlive!==true)
    throw Error('Worker-side signing requirement was not proven installed on a live worker.');
  if(deliverySeen!==false)
    throw Error('Unauthorized request reached the restricted native worker handler.');
  if(hostAttempted!==true || hostError || hostOverflow || hostExitSignal)
    throw Error('Untrusted host did not attempt a clean native request.');
  if(hostStdout.startsWith('OK '))
    throw Error('Unauthorized host received a successful worker response.');
  // Apple may immediately return an XPC error to the initiating process.
  // Accept that *only* with native typed-XPC-error evidence, no successful
  // reply, and independently verified worker-side live gate + no delivery.
  if(hostExited) {
    if(hostExitCode!==0 || hostStdout!=='ERR 0\n' ||
       !hostStderr.includes('BBX_INBOUND_XPC_ERROR'))
      throw Error('Early native host exit had no verified XPC rejection evidence.');
  }else if(hostStdout!=='')
    throw Error('Native host emitted unexpected output while awaiting rejection.');
  return true;
}
function dispatch(host){
  const child=spawn(host,[],{
    shell:false,stdio:['pipe','pipe','pipe'],
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8'}
  });
  let stdout='',stderr='',error=null,exited=false,overflow=false;
  let code=null,signal=null;
  const completion=new Promise(resolve=>{
    child.on('close',(exitCode,exitSignal)=>{
      exited=true;code=exitCode;signal=exitSignal;
      resolve({code,signal});
    });
  });
  child.on('error',e=>{error=e.message;});
  child.stdout.on('data',chunk=>{
    stdout+=chunk.toString('utf8');
    if(stdout.length>3000){overflow=true;child.kill('SIGKILL');}
  });
  child.stderr.on('data',chunk=>{
    stderr+=chunk.toString('utf8');
    if(stderr.length>3000){overflow=true;child.kill('SIGKILL');}
  });
  child.stdin.on('error',()=>{});
  child.stdin.end('ROOT - 0\n');
  return {child,completion,observe:()=>({
    stdout,stderr,error,exited,overflow,code,signal
  })};
}
async function sleep(ms){await new Promise(resolve=>setTimeout(resolve,ms));}
async function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Synthetic XPC inbound-peer test requires explicit MCP_SANDBOX=off.');
  if(process.argv.slice(2).length!==0)throw Error('Unexpected fixture arguments.');
  command('/usr/bin/xcrun',['--find','clang'],'Native compiler');
  const dir=mkdtempSync(join(tmpdir(),'bb-inbound-peer-'));
  let trial,armedPath,deliveredPath,restrictedRoot;
  try {
    /*
     * NEVER recompile/re-sign a worker after starting it. launchd may keep
     * that signed XPC image alive or cached, and overwriting it can cause
     * premature invalidation unrelated to peer identity. Build two separate
     * app bundles, nested workers and unique service/signing identifiers.
     */
    const buildVariant=(which)=>{
      const ids=identities[which];
      const app=join(dir,which==='baseline'?'BaselineHost.app':'RestrictedHost.app');
      const host=join(app,'Contents','MacOS','BlackBoxAuthorityHost');
      const bundle=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
      const worker=join(bundle,'Contents','MacOS','BlackBoxAuthorityWorker');
      mkdirSync(dirname(host),{recursive:true});
      mkdirSync(dirname(worker),{recursive:true});
      const hostPlist=readFileSync(join(sources,'AuthorityHost-Info.plist'),'utf8')
        .replace('dev.agentblackbox.xpc-authority.host',ids.host);
      const workerPlist=readFileSync(join(sources,'AuthorityService-Info.plist'),'utf8')
        .replace('dev.agentblackbox.xpc-authority.worker',ids.worker);
      if(!hostPlist.includes(ids.host)||!workerPlist.includes(ids.worker))
        throw Error('Synthetic XPC identity was not installed in Info.plist.');
      writeFileSync(join(app,'Contents','Info.plist'),hostPlist);
      writeFileSync(join(bundle,'Contents','Info.plist'),workerPlist);
      command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2',
        '-Wall','-Wextra',ids.clientFlag,'-o',host,
        join(sources,'AuthorityBridgeHost.c')],'Native '+which+' host build');
      command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2',
        '-Wall','-Wextra',
        ...(which==='restricted'?['-DBBX_TEST_INBOUND_PEER_REQUIREMENT=1']:[]),
        '-o',worker,join(sources,'AuthorityNotesService.m'),
        '-framework','Foundation'],'Native '+which+' worker build');
      command('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
        '--identifier',ids.worker,
        '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
        bundle],'Ad-hoc '+which+' worker signature');
      command('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
        '--identifier',ids.host,app],'Ad-hoc '+which+' host signature');
      command('/usr/bin/codesign',['--verify','--strict','--deep',app],
        which+' nested app seal');
      const ent=command('/usr/bin/codesign',
        ['--display','--entitlements','-','--xml',bundle],
        'Worker App Sandbox entitlement');
      inspectMinimalWorkerEntitlements(ent.stdout+'\n'+ent.stderr);
      return {app,host,worker,bundle,ids};
    };
    const baseline=buildVariant('baseline');
    const restricted=buildVariant('restricted');
    const baselineRoot=readNativeRoot(baseline.host);
    console.log('PASS: Separate ad-hoc baseline host reached its private notes worker.');
    console.log('PASS: Distinct, nested restricted worker built and signed without replacing running XPC code.');

    /*
     * Obtain the restricted container location solely by substituting the
     * verified bundle identity in the baseline's canonical worker-reported
     * scratch path. Never treat an arbitrary host-supplied root as proof.
     * If macOS uses a different layout, stop rather than guess.
     */
    const baselineTail='/Library/Containers/'+identities.baseline.worker+
      '/Data/Documents/AgentBlackBoxScratchNotes';
    if(!baselineRoot.endsWith(baselineTail))
      throw Error('Baseline XPC container does not have expected worker bundle identity.');
    restrictedRoot=baselineRoot.slice(0,-baselineTail.length)+
      '/Library/Containers/'+identities.restricted.worker+
      '/Data/Documents/AgentBlackBoxScratchNotes';
    armedPath=join(restrictedRoot,armedName);
    deliveredPath=join(restrictedRoot,deliveredName);
    // Only clean exact markers in an already independently verified private
    // container. The actual worker must recreate the marker after setup.
    if(existsSync(restrictedRoot)){
      validateMacWorkspaceBinding({configuredRoot:restrictedRoot,
        reportedRoot:restrictedRoot});
      rmSync(armedPath,{force:true});
      rmSync(deliveredPath,{force:true});
    }

    trial=dispatch(restricted.host);
    let armedPid=0;
    const began=Date.now();
    while(Date.now()-began<7000){
      const current=trial.observe();
      if(current.error||current.overflow)
        throw Error('Untrusted native host failed to start cleanly.');
      if(existsSync(deliveredPath))
        throw Error('Restricted worker received an unauthorized message.');
      if(existsSync(armedPath)){
        validateMacWorkspaceBinding({configuredRoot:restrictedRoot,
          reportedRoot:restrictedRoot});
        const match=/^([1-9][0-9]{0,9})\n$/.exec(readFileSync(armedPath,'utf8'));
        if(!match)throw Error('Malformed worker-owned signing requirement marker.');
        armedPid=Number(match[1]);
        break;
      }
      // Deliberately do not abort merely because the host exited: Apple may
      // return a typed XPC error for an unauthorized incoming connection.
      await sleep(40);
    }
    if(!armedPid){
      const outcome=trial.observe();
      throw Error('No verified worker-side signing requirement marker; '+JSON.stringify({
        hostExited:outcome.exited,exitCode:outcome.code,exitSignal:outcome.signal,
        hostOutput:outcome.stdout.slice(0,100),
        hostError:outcome.stderr.slice(0,250),
        restrictedContainerExists:existsSync(restrictedRoot)
      }));
    }
    if(!liveWorker(armedPid)) {
      const outcome=trial.observe();
      throw Error('Worker not alive after incoming signing requirement setup; '+
        JSON.stringify({
          workerPid:armedPid,workerProcess:workerProcess(armedPid),
          hostExited:outcome.exited,hostExitCode:outcome.code,
          hostExitSignal:outcome.signal,
          hostOutput:outcome.stdout.slice(0,100),
          hostDiagnostics:outcome.stderr.slice(0,250),
          deliveredMarker:existsSync(deliveredPath)
        }));
    }
    console.log('PASS: Restricted native worker remains alive during bounded XPC diagnostic transaction.');
    await sleep(1100);
    const current=trial.observe();
    assessInboundPeerRejection({
      armedPid,workerMarkerFresh:existsSync(armedPath),
      workerAlive:liveWorker(armedPid),deliverySeen:existsSync(deliveredPath),
      hostAttempted:current.stderr.includes('BBX_INBOUND_REQUEST_ATTEMPTED'),
      hostStdout:current.stdout,hostStderr:current.stderr,
      hostExited:current.exited,hostExitCode:current.code,
      hostExitSignal:current.signal,hostError:current.error,
      hostOverflow:current.overflow
    });
    console.log('PASS: Unauthorized host request never reached the live worker handler.');
    console.log('PASS: Unauthorized host received no successful worker response.');
    console.log('PASS: Worker-side OS peer requirement negative acceptance (synthetic-only).');
    console.log('NOTE: Developer ID positive mutual trust and production signing remain pending.');
  } finally {
    if(trial){
      try{trial.child.kill('SIGKILL');}catch{}
      await trial.completion;
    }
    if(restrictedRoot && existsSync(restrictedRoot)){
      try{
        validateMacWorkspaceBinding({configuredRoot:restrictedRoot,
          reportedRoot:restrictedRoot});
        if(armedPath)rmSync(armedPath,{force:true});
        if(deliveredPath)rmSync(deliveredPath,{force:true});
      }catch(error){
        console.error('Marker cleanup not performed: '+error.message);
      }
    }
    rmSync(dir,{recursive:true,force:true});
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error('INBOUND XPC PEER IDENTITY NOT ACCEPTED: '+e.message);
    process.exitCode=1;});
