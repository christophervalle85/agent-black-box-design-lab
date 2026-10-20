/**
 * v0.8 phase-2A local-only experiment: fixed note operations through a
 * separately signed private XPC worker. Uses synthetic data in worker TMPDIR.
 * NOT a Node/MCP gateway and NOT suitable for persistent user documents.
 */
import {spawn,spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const call=(tool,args,label,timeout=60000)=>{
  const result=spawnSync(tool,args,{encoding:'utf8',timeout,maxBuffer:256*1024});
  if(result.error||result.status!==0)throw Error(label+': '+(result.error?.message??
    result.stderr?.trim()??'unknown failure')+' (exit '+result.status+')');
  return result;
};
function verifySandbox(service) {
  call('/usr/bin/codesign',['--verify','--strict',service],'Worker signature verification');
  const info=call('/usr/bin/codesign',['--display','--entitlements','-','--xml',service],
    'Worker entitlement inspection');
  const xml=info.stdout+'\n'+info.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Worker is missing App Sandbox entitlement.');
  if(/<key>com\.apple\.security\.network\.(?:client|server)<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Worker unexpectedly holds network entitlement.');
}
export function evaluateNativeNotes(reply) {
  if(!reply||typeof reply!=='object'||Array.isArray(reply))
    throw Error('Invalid native notes response.');
  for(const key of ['hostPID','workerPID'])
    if(!Number.isSafeInteger(reply[key]))throw Error('Invalid native process identity: '+key);
  for(const key of ['writeAllowed','readMatched','traversalRejected','cleanupAllowed'])
    if(typeof reply[key]!=='boolean')throw Error('Missing boolean evidence: '+key);
  const checks=[
    {label:'Native XPC worker is a separate process',ok:reply.hostPID>0&&reply.workerPID>0&&reply.hostPID!==reply.workerPID},
    {label:'New note created inside worker-owned temporary storage',ok:reply.writeAllowed},
    {label:'Native worker returned the exact note bytes',ok:reply.readMatched},
    {label:'Traversal rejected by native worker',ok:reply.traversalRejected},
    {label:'Synthetic test note removed',ok:reply.cleanupAllowed}
  ];
  return {ok:checks.every(c=>c.ok),checks};
}
function launch(host,timeout=15000) {
  return new Promise(resolve=>{
    let stdout='',stderr='',spawnError=null,timedOut=false,tooLarge=false;
    const child=spawn(host,[],{shell:false,stdio:['ignore','pipe','pipe'],
      env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8'}});
    child.stdout?.on('data',chunk=>{
      stdout+=chunk.toString();
      if(stdout.length>16000){tooLarge=true;child.kill('SIGKILL');}
    });
    child.stderr?.on('data',chunk=>{
      stderr+=chunk.toString();
      if(stderr.length>16000){tooLarge=true;child.kill('SIGKILL');}
    });
    child.on('error',e=>{spawnError=e.message;});
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeout);
    child.on('close',(status,signal)=>{
      clearTimeout(timer);
      resolve({status,signal,error:spawnError,timedOut,tooLarge,
        stdout:stdout.slice(0,500),stderr:stderr.slice(0,1200)});
    });
  });
}
async function main() {
  if(process.platform!=='darwin')throw Error('Real macOS and native XPC are required.');
  call('/usr/bin/xcrun',['--find','clang'],'Xcode Clang lookup');
  const directory=mkdtempSync(join(tmpdir(),'blackbox-xpc-notes-'));
  try{
    const app=join(directory,'BlackBoxNotesHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxNotesHost');
    const svc=join(app,'Contents','XPCServices','BlackBoxNotesWorker.xpc');
    const service=join(svc,'Contents','MacOS','BlackBoxNotesWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(service),{recursive:true});
    copyFileSync(join(sources,'NotesHost-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'NotesService-Info.plist'),join(svc,'Contents','Info.plist'));
    for(const [exe,source,label] of [
      [host,'NotesHost.c','Native XPC notes host'],
      [service,'NotesService.c','Native sandboxed notes worker']
    ]) {
      call('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
        '-o',exe,join(sources,source)],label+' compilation',120000);
    }
    call('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-notes.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),svc],
      'Native notes worker signing');
    call('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-notes.host',app],
      'Native notes host signing');
    call('/usr/bin/codesign',['--verify','--strict','--deep',app],
      'Signed host and nested service verification');
    verifySandbox(svc);
    console.log('PASS: Native notes XPC worker signed with independent App Sandbox.');
    const actual=await launch(host);
    if(actual.error||actual.signal||actual.status!==0||actual.timedOut||actual.tooLarge){
      console.error('Notes XPC process diagnostics:',JSON.stringify(actual,null,2));
      throw Error('Native notes host or worker could not finish; no native MCP tool claim.');
    }
    let result;
    try{result=JSON.parse(actual.stdout);}catch{throw Error('Malformed native XPC result: '+actual.stdout);}
    const proof=evaluateNativeNotes(result);
    for(const item of proof.checks)console.log((item.ok?'PASS: ':'FAIL: ')+item.label);
    if(!proof.ok)throw Error('Native XPC note boundary acceptance failed.');
    console.log('PASS: XPC note-operations feasibility complete (synthetic data only).');
    console.log('NOTE: Node MCP gateway is NOT connected to this worker; required mode remains fail-closed.');
  }finally {
    rmSync(directory,{recursive:true,force:true});
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error('XPC NOTES FEASIBILITY FAILED: '+e.message);process.exitCode=1;});
