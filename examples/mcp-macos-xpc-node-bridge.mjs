/**
 * Experimental Node->signed native host->XPC bridge smoke test.
 * This is not the MCP adapter and has NO operator approval or audit authority.
 */
import {spawn,spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {frameBridgeRequest,parseBridgeReplies} from '../src/macos-xpc-bridge-wire.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
function run(tool,args,label,timeout=90000) {
  const result=spawnSync(tool,args,{encoding:'utf8',timeout,maxBuffer:256*1024});
  if(result.error||result.status!==0)
    throw Error(label+' failed: '+(result.error?.message??result.stderr?.trim()??'unknown')+' (exit '+result.status+')');
  return result;
}
function checkWorkerSignature(service,app) {
  run('/usr/bin/codesign',['--verify','--strict','--deep',app],'Nested app signature');
  run('/usr/bin/codesign',['--verify','--strict',service],'Worker signature');
  const info=run('/usr/bin/codesign',['--display','--entitlements','-','--xml',service],
    'Worker entitlements');
  const data=info.stdout+'\n'+info.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(data))
    throw Error('Native note service lacks Apple App Sandbox.');
  if(/<key>com\.apple\.security\.network\.(?:client|server)<\/key>\s*<true\s*\/>/.test(data))
    throw Error('Native note worker unexpectedly has network entitlements.');
}
async function executeBatch(host,requests,{timeoutMs=12000}={}) {
  return new Promise(resolve=>{
    let stdout=Buffer.alloc(0),stderr='',error=null,timedOut=false,overflow=false;
    const child=spawn(host,[],{shell:false,stdio:['pipe','pipe','pipe'],
      env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',HOME:homedir(),TMPDIR:tmpdir()}});
    const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},timeoutMs);
    child.stdout.on('data',chunk=>{
      stdout=Buffer.concat([stdout,chunk]);
      if(stdout.length>16000){overflow=true;child.kill('SIGKILL');}
    });
    child.stderr.on('data',chunk=>{
      stderr+=(chunk.toString());
      if(stderr.length>1200){overflow=true;child.kill('SIGKILL');}
    });
    child.on('error',e=>{error=e.message;});
    child.stdin.on('error',()=>{});
    child.stdin.end(Buffer.concat(requests));
    child.on('close',(status,signal)=>{
      clearTimeout(timer);
      resolve({status,signal,error,timedOut,overflow,stdout,
        stderr:stderr.slice(0,400)});
    });
  });
}
async function main() {
  if(process.platform!=='darwin')throw Error('Real macOS and XPC are required.');
  run('/usr/bin/xcrun',['--find','clang'],'Xcode Clang availability');
  const workspace=mkdtempSync(join(tmpdir(),'agent-black-box-bridge-'));
  try {
    const app=join(workspace,'BlackBoxNotesHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxNotesHost');
    const bundle=join(app,'Contents','XPCServices','BlackBoxNotesWorker.xpc');
    const worker=join(bundle,'Contents','MacOS','BlackBoxNotesWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(sources,'NotesHost-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'NotesService-Info.plist'),join(bundle,'Contents','Info.plist'));
    run('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',host,join(sources,'NotesBridgeHost.c')],'Native bridge compilation',90000);
    run('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',worker,join(sources,'NotesService.c')],'XPC notes worker compilation',90000);
    run('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-notes.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),bundle],
      'Native XPC service signing');
    run('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-notes.host',app],'Native host signing');
    checkWorkerSignature(bundle,app);
    console.log('PASS: Signed private XPC worker retains App Sandbox with network disabled.');

    const filename='bbx-test-'+randomUUID().replaceAll('-','').slice(0,22)+'.txt';
    const content='Node to native host to XPC: synthetic security test only.';
    const requests=[
      frameBridgeRequest('WRITE',filename,content),
      frameBridgeRequest('READ',filename),
      frameBridgeRequest('WRITE',filename,'NOT an authorized overwrite'),
      Buffer.from('READ ../../.ssh/id_ed25519 0\n','ascii'),
      frameBridgeRequest('READ',filename),
      frameBridgeRequest('REMOVE',filename),
      frameBridgeRequest('READ',filename)
    ];
    const actual=await executeBatch(host,requests);
    if(actual.error||actual.signal||actual.status!==0||actual.timedOut||actual.overflow){
      console.error('Node/native bridge diagnostics:',JSON.stringify({
        status:actual.status,signal:actual.signal,error:actual.error,
        timedOut:actual.timedOut,overflow:actual.overflow,stderr:actual.stderr
      },null,2));
      throw Error('Native bridge failed or timed out; treat write outcome as UNKNOWN.');
    }
    const messages=parseBridgeReplies(actual.stdout,requests.length);
    const checks=[
      ['Node requested new synthetic note through private XPC worker',messages[0].ok],
      ['Exact note bytes returned through native bridge',messages[1].ok&&messages[1].content===content],
      ['Exclusive create prevents second write to same filename',!messages[2].ok],
      ['Traversal rejected by both host and worker boundaries',!messages[3].ok],
      ['Denied operations did not change original note',messages[4].ok&&messages[4].content===content],
      ['Synthetic note cleanup succeeded',messages[5].ok],
      ['Deleted synthetic note cannot be read',!messages[6].ok]
    ];
    for(const [label,ok] of checks)console.log((ok?'PASS: ':'FAIL: ')+label);
    if(!checks.every(x=>x[1]))throw Error('Node/native XPC isolation transport acceptance failed.');
    console.log('PASS: Experimental Node-to-XPC bridge accepted synthetic note operations.');
    console.log('NOTE: No live MCP gateway integration, human approvals or audit events; macOS required mode stays fail-closed.');
  }finally{rmSync(workspace,{recursive:true,force:true});}
}
main().catch(e=>{console.error('MAC NODE-XPC BRIDGE FAILED: '+e.message);process.exitCode=1;});
