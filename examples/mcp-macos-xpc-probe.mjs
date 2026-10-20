/**
 * EXPERIMENTAL v0.8 macOS XPC boundary acceptance.
 * Builds ad-hoc signed app+embedded private XPC service, asks launchd to
 * service one narrow probe request, and verifies real OS-denied operations.
 * DOES NOT wire arbitrary MCP tools into XPC or enable MCP_SANDBOX=required.
 */
import {spawn,spawnSync} from 'node:child_process';
import {createServer,connect} from 'node:net';
import {copyFileSync,mkdirSync,mkdtempSync,readFileSync,realpathSync,rmSync,writeFileSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const run=(cmd,args,extra={})=>spawnSync(cmd,args,{encoding:'utf8',timeout:60000,maxBuffer:256*1024,...extra});
function check(cmd,args,label,timeout=60000){
  const result=run(cmd,args,{timeout});
  if(result.error||result.status!==0)
    throw Error(label+': '+(result.error?.message??result.stderr?.trim()??'unknown error')+' (exit '+result.status+')');
  return result;
}
function checkEntitlement(bundle){
  check('/usr/bin/codesign',['--verify','--strict',bundle],'XPC service signature');
  const result=check('/usr/bin/codesign',['--display','--entitlements','-','--xml',bundle],
    'XPC service entitlements');
  const xml=result.stdout+'\n'+result.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Embedded service lacks an enabled App Sandbox entitlement.');
  if(/<key>com\.apple\.security\.network\.(client|server)<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Embedded service unexpectedly has network entitlements.');
}
async function listen(){
  const server=createServer(socket=>socket.end());
  await new Promise((ok,no)=>{server.once('error',no);server.listen(0,'127.0.0.1',ok);});
  const port=server.address().port;
  try{
    await new Promise((ok,no)=>{
      const socket=connect({host:'127.0.0.1',port});
      socket.once('connect',()=>{socket.destroy();ok();});
      socket.once('error',no);
      socket.setTimeout(3000,()=>{socket.destroy();no(Error('Loopback baseline timed out.'));});
    });
  }catch(e){server.close();throw e;}
  return {server,port};
}
function launch(cmd,args,timeoutMs=12000){
  return new Promise(resolve=>{
    const start=Date.now();
    let stdout='',stderr='',error=null,timedOut=false;
    const child=spawn(cmd,args,{stdio:['ignore','pipe','pipe'],shell:false,
      env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C.UTF-8'}});
    child.stdout?.on('data',v=>{stdout+=v; if(stdout.length>128000)child.kill('SIGKILL');});
    child.stderr?.on('data',v=>{stderr+=v; if(stderr.length>128000)child.kill('SIGKILL');});
    child.on('error',e=>{error=e.message;});
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeoutMs);
    child.on('close',(status,signal)=>{
      clearTimeout(timer);
      resolve({status,signal,error,timedOut,elapsedMs:Date.now()-start,
        stdout:stdout.slice(0,1000),stderr:stderr.slice(0,1000)});
    });
  });
}
export function assessXpc(result) {
  if(!result || typeof result!=='object' || Array.isArray(result))
    throw Error('Invalid XPC probe result');
  for(const key of ['hostPID','workerPID','hostFileErrno','networkErrorNumber','temporaryWriteErrno']){
    if(!Number.isSafeInteger(result[key]))throw Error('Missing/incompatible XPC integer: '+key);
  }
  for(const key of ['hostFileDenied','networkDenied','temporaryWriteAllowed']){
    if(typeof result[key]!=='boolean')throw Error('Missing/incompatible XPC boolean: '+key);
  }
  const checks=[
    {label:'XPC worker runs in separate process',ok:result.hostPID>0&&result.workerPID>0&&result.hostPID!==result.workerPID},
    {label:'Worker denied user-owned host file by OS permissions',ok:result.hostFileDenied&&[1,13].includes(result.hostFileErrno)},
    {label:'Worker denied reachable loopback TCP by OS permissions',ok:result.networkDenied&&[1,13].includes(result.networkErrorNumber)},
    {label:'Worker can write and clean temporary file',ok:result.temporaryWriteAllowed&&result.temporaryWriteErrno===0}
  ];
  return {ok:checks.every(x=>x.ok),checks};
}
async function main(){
  if(process.platform!=='darwin')throw Error('XPC probe requires real macOS; cannot validate launchd on Linux CI.');
  check('/usr/bin/xcrun',['--find','clang'],'Xcode Clang compiler lookup');
  const directory=mkdtempSync(join(tmpdir(),'blackbox-xpc-probe-'));
  const secretDir=mkdtempSync(join(homedir(),'.blackbox-xpc-host-only-'));
  let listener;
  try{
    const app=join(directory,'BlackBoxXpcHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxXpcHost');
    const svc=join(app,'Contents','XPCServices','BlackBoxXpcProbe.xpc');
    const service=join(svc,'Contents','MacOS','BlackBoxXpcProbe');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(service),{recursive:true});
    copyFileSync(join(sources,'Host-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'Service-Info.plist'),join(svc,'Contents','Info.plist'));
    for(const [exe,src,label] of [
      [host,'ProbeHost.c','native XPC host'],
      [service,'ProbeService.c','sandboxed XPC service']
    ]) {
      check('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra','-o',exe,
        join(sources,src)],label+' compilation',120000);
    }
    check('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-probe.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),svc],
      'Embedded XPC service signing');
    check('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-probe.host',app],'Host app bundle signing');
    check('/usr/bin/codesign',['--verify','--deep','--strict',app],'Nested app signature validation');
    checkEntitlement(svc);
    console.log('PASS: Signed host .app contains an independently entitled private XPC service.');
    const marker=join(secretDir,'synthetic-host-marker.txt');
    writeFileSync(marker,'test-only marker, not a secret\n',{mode:0o600});
    if(readFileSync(marker,'utf8').length===0)throw Error('Host file baseline failed');
    listener=await listen();
    const observed=await launch(host,[realpathSync(marker),String(listener.port)],12000);
    if(observed.error||observed.signal||observed.status!==0||observed.timedOut) {
      console.error('XPC launch diagnostics:',JSON.stringify(observed,null,2));
      throw Error('XPC host/service did not finish successfully; actual isolation not yet proven.');
    }
    let raw;
    try{raw=JSON.parse(observed.stdout);}catch{throw Error('Malformed XPC output: '+observed.stdout.slice(0,250));}
    const verdict=assessXpc(raw);
    for(const check of verdict.checks)console.log((check.ok?'PASS: ':'FAIL: ')+check.label);
    if(!verdict.ok) {
      console.error('XPC diagnostic codes (no test marker content):',JSON.stringify({
        hostFileErrno:raw.hostFileErrno,networkErrorNumber:raw.networkErrorNumber,
        temporaryWriteErrno:raw.temporaryWriteErrno
      }));
      throw Error('XPC OS-isolation evidence insufficient; do not enable required mode.');
    }
    console.log('PASS: Independently sandboxed XPC feasibility proven on macOS.');
    console.log('NOTE: This does NOT implement read_note/write_note; Node MCP required mode remains fail-closed.');
  }finally{
    if(listener)await new Promise(ok=>listener.server.close(ok));
    rmSync(directory,{recursive:true,force:true});
    rmSync(secretDir,{recursive:true,force:true});
  }
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{console.error('XPC FEASIBILITY FAILED: '+error.message);process.exitCode=1;});
