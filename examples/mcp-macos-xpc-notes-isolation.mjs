/**
 * Synthetic-only OS isolation acceptance against the AuthorityNotesService
 * code, not a separate generic probe worker. Only this throwaway worker
 * build has BBX_TEST_NOTES_ISOLATION enabled.
 *
 * Does NOT enable macOS required mode or authenticate release signing.
 */
import {spawnSync,spawn} from 'node:child_process';
import {createServer,connect} from 'node:net';
import {copyFileSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessXpc} from './mcp-macos-xpc-probe.mjs';
import {selectLocalDevelopmentIdentity,parseSignedIdentity}
  from './mcp-macos-xpc-signed-peers.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const run=(exe,args,{timeout=90000,...opts}={})=>
  spawnSync(exe,args,{encoding:'utf8',timeout,maxBuffer:256*1024,...opts});
function check(exe,args,label,options={}){
  const r=run(exe,args,options);
  if(r.error||r.status!==0||r.signal)
    throw Error(label+' failed: '+(r.error?.message??r.stderr?.trim()??r.status));
  return r;
}
export function assessNotesWorkerIsolation(result){
  if(!result||result.valid!==true)
    throw Error('Native notes worker did not acknowledge a valid probe.');
  const examined=assessXpc(result);
  const labels=[
    'Final-source XPC notes worker runs in a separate process',
    'Notes worker OS denied a readable home-directory host marker',
    'Notes worker OS denied a live loopback TCP connection',
    'Notes worker fsynced and removed an exclusive file in its private Documents scratch root'
  ];
  return {ok:examined.ok,checks:examined.checks.map((c,i)=>({...c,label:labels[i]}))};
}
async function listen(){
  const server=createServer(socket=>socket.end());
  await new Promise((ok,no)=>{
    server.once('error',no);
    server.listen(0,'127.0.0.1',ok);
  });
  const port=server.address().port;
  try {
    await new Promise((ok,no)=>{
      const s=connect({host:'127.0.0.1',port});
      s.once('connect',()=>{s.destroy();ok();});
      s.once('error',no);
      s.setTimeout(3000,()=>{s.destroy();no(Error('Loopback baseline timeout'));});
    });
  }catch(e){server.close();throw e;}
  return {server,port};
}
function launch(host,marker,port){
  return new Promise(resolve=>{
    let stdout='',stderr='',error=null,timedOut=false,overflow=false;
    const child=spawn(host,[marker,String(port)],{
      shell:false,stdio:['ignore','pipe','pipe'],
      env:{HOME:homedir(),TMPDIR:tmpdir(),PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}
    });
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},12000);
    for(const [stream,which] of [[child.stdout,'stdout'],[child.stderr,'stderr']]){
      stream.on('data',chunk=>{
        if(which==='stdout')stdout+=chunk.toString('utf8');
        else stderr+=chunk.toString('utf8');
        if(stdout.length>8000||stderr.length>8000){
          overflow=true;child.kill('SIGKILL');
        }
      });
    }
    child.on('error',e=>{error=e.message;});
    child.on('close',(status,signal)=>{
      clearTimeout(timer);
      resolve({status,signal,error,timedOut,overflow,stdout,stderr:stderr.slice(0,500)});
    });
  });
}
async function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required for XPC OS-denial acceptance.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Synthetic notes-worker probe requires explicit MCP_SANDBOX=off.');
  const requiredSigned=process.argv.length===3&&process.argv[2]==='--required-signed';
  if(process.argv.length>2&&!requiredSigned)
    throw Error('Only --required-signed is supported for distinct native required-worker isolation probe.');
  check('/usr/bin/xcrun',['--find','clang'],'Native compiler');
  const signingIdentity=requiredSigned?selectLocalDevelopmentIdentity(
    check('/usr/bin/security',['find-identity','-v','-p','codesigning'],
      'Existing Apple Development signer').stdout):'-';
  const directory=mkdtempSync(join(tmpdir(),'bb-notes-isolation-'));
  const homeMarkerRoot=mkdtempSync(join(homedir(),'.bb-notes-isolation-host-'));
  let listener;
  try {
    const app=join(directory,'BlackBoxAuthorityHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxAuthorityHost');
    const service=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
    const worker=join(service,'Contents','MacOS','BlackBoxAuthorityWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(sources,'AuthorityHost-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'AuthorityService-Info.plist'),join(service,'Contents','Info.plist'));
    check('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-DBBX_TEST_NOTES_ISOLATION=1','-o',host,
      join(sources,'ProbeHost.c')],'Notes worker probe host build');
    check('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-DBBX_TEST_NOTES_ISOLATION=1',
      ...(requiredSigned?['-DBBX_NATIVE_REQUIRED_MCP=1']:[]),
      '-o',worker,
      join(sources,'AuthorityNotesService.m'),'-framework','Foundation'],
      'Actual notes-worker source with isolated diagnostic hook');
    check('/usr/bin/codesign',['--force','--sign',signingIdentity,'--options','runtime',
      '--identifier','dev.agentblackbox.xpc-authority.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
      service],'Ad-hoc App Sandbox notes-worker signing');
    check('/usr/bin/codesign',['--force','--sign',signingIdentity,'--options','runtime',
      '--identifier','dev.agentblackbox.xpc-authority.host',app],
      'Ad-hoc native host signing');
    check('/usr/bin/codesign',['--verify','--strict','--deep',app],
      'Nested app seal');
    if(requiredSigned){
      const team=target=>check('/usr/bin/codesign',['--display','--verbose=4',target],
        'Required worker identity').stderr;
      const first=parseSignedIdentity(team(app),
        'dev.agentblackbox.xpc-authority.host');
      const second=parseSignedIdentity(team(service),
        'dev.agentblackbox.xpc-authority.worker');
      if(first!==second)throw Error('Required signed host and worker Team IDs differ.');
    }
    const entitlements=check('/usr/bin/codesign',
      ['--display','--entitlements','-','--xml',service],
      'Notes-worker entitlements');
    const xml=entitlements.stdout+'\n'+entitlements.stderr;
    if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(xml)||
       /<key>com\.apple\.security\.network\.(?:client|server)<\/key>\s*<true\s*\/>/.test(xml))
      throw Error('Notes worker App Sandbox or network-entitlement boundary invalid.');
    console.log('PASS: Final notes-worker source built as independently sandboxed, ad-hoc-signed XPC test fixture.');
    const marker=join(homeMarkerRoot,'readable-host-marker.txt');
    writeFileSync(marker,'synthetic file; not a secret\n',{mode:0o600});
    if(!readFileSync(marker,'utf8').startsWith('synthetic file'))
      throw Error('Host-readable file baseline missing.');
    listener=await listen();
    console.log('PASS: Host marker and reachable loopback listener verified before launching worker.');
    const outcome=await launch(host,marker,listener.port);
    if(outcome.error||outcome.signal||outcome.status!==0||outcome.timedOut||outcome.overflow)
      throw Error('Real XPC worker probe failed or timed out: '+JSON.stringify(outcome));
    let message;
    try{message=JSON.parse(outcome.stdout);}catch{
      throw Error('Native notes-worker isolation output was not valid JSON.');
    }
    const verdict=assessNotesWorkerIsolation(message);
    for(const result of verdict.checks)
      console.log((result.ok?'PASS: ':'FAIL: ')+result.label);
    if(!verdict.ok) {
      console.error('OS errno diagnostics (no marker content):',JSON.stringify({
        hostFileErrno:message.hostFileErrno,
        networkErrorNumber:message.networkErrorNumber,
        temporaryWriteErrno:message.temporaryWriteErrno
      }));
      throw Error('Notes-worker isolation not accepted; do not enable required mode.');
    }
    console.log('PASS: '+(requiredSigned?
      'Apple Development-signed required-worker source installed an incoming OS peer gate and passed':
      'Notes-worker code passed')+
      ' real macOS file/network isolation in the separate diagnostic XPC build.');
    console.log('NOTE: Diagnostic method is compiled only for this disposable signed test, never into the installed required-mode worker.');
  }finally{
    if(listener)await new Promise(ok=>listener.server.close(ok));
    rmSync(directory,{recursive:true,force:true});
    rmSync(homeMarkerRoot,{recursive:true,force:true});
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error('NOTES WORKER OS ISOLATION NOT ACCEPTED: '+e.message);process.exitCode=1;});
