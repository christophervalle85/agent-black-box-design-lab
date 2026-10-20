/**
 * Experimental Node->signed native host->XPC bridge smoke test.
 * This is not the MCP adapter and has NO operator approval or audit authority.
 */
import {spawn,spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync,realpathSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {frameBridgeRequest,parseBridgeReplies} from '../src/macos-xpc-bridge-wire.mjs';
import {validateMacWorkspaceBinding} from '../src/macos-workspace-binding.mjs';

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
function assertHealthyProcess(proc,label) {
  if(proc.error||proc.signal||proc.status!==0||proc.timedOut||proc.overflow){
    console.error('Durable XPC process diagnostics:',JSON.stringify({
      status:proc.status,signal:proc.signal,error:proc.error,
      timedOut:proc.timedOut,overflow:proc.overflow,stderr:proc.stderr
    },null,2));
    throw Error(label+' failed or timed out. Treat an in-flight write as outcome UNKNOWN.');
  }
}

async function main() {
  if(process.platform!=='darwin')throw Error('Real macOS and XPC are required.');
  run('/usr/bin/xcrun',['--find','clang'],'Xcode Clang availability');
  const workspace=mkdtempSync(join(tmpdir(),'agent-black-box-authority-'));
  try {
    const app=join(workspace,'BlackBoxAuthorityHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxAuthorityHost');
    const bundle=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
    const worker=join(bundle,'Contents','MacOS','BlackBoxAuthorityWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(sources,'AuthorityHost-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'AuthorityService-Info.plist'),join(bundle,'Contents','Info.plist'));
    run('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',host,join(sources,'AuthorityBridgeHost.c')],'Native bridge compilation',90000);
    run('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',worker,join(sources,'AuthorityNotesService.m'),
      '-framework','Foundation'],'XPC durable worker compilation',90000);
    run('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-authority.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),bundle],
      'Native XPC service signing');
    run('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-authority.host',app],'Native host signing');
    checkWorkerSignature(bundle,app);
    console.log('PASS: Signed private XPC worker retains App Sandbox with network disabled.');

    // Ask the signed private worker where it actually stores notes.
    // This is NOT cryptographic attestation or approval to route MCP tools.
    const identity=await executeBatch(host,[Buffer.from('ROOT - 0\n','ascii')]);
    assertHealthyProcess(identity,'workspace identity host');
    const reported=parseBridgeReplies(identity.stdout,1);
    if(reported.length!==1||!reported[0].ok)
      throw Error('Private XPC worker did not report its Documents workspace.');
    const nativeRoot=reported[0].content;
    const liveDemo=realpathSync(join(root,'demo-workspace'));
    let mismatchedDenied=false;
    try {
      validateMacWorkspaceBinding({configuredRoot:liveDemo,reportedRoot:nativeRoot});
    }catch{mismatchedDenied=true;}
    if(!mismatchedDenied)
      throw Error('Unexpectedly accepted an unrelated gateway demo-workspace.');
    console.log('PASS: Unrelated gateway demo-workspace is refused for native operations.');
    // Synthetic proof only: an explicitly matching policy root may be bound.
    // A production gateway must obtain this from a verified worker launch
    // and reject user-configured roots that do not match.
    const binding=validateMacWorkspaceBinding({
      configuredRoot:nativeRoot,reportedRoot:nativeRoot
    });
    if(!binding.matched)throw Error('Native workspace identity not bound.');
    console.log('PASS: Native Documents workspace identity is canonical, private and consistent.');

    const filename='bbx-test-'+randomUUID().replaceAll('-','').slice(0,22)+'.txt';
    const content='Durable sandbox XPC scratch note; synthetic data only.';
    const firstRequests=[
      frameBridgeRequest('WRITE',filename,content),
      frameBridgeRequest('READ',filename)
    ];
    const first=await executeBatch(host,firstRequests);
    assertHealthyProcess(first,'first host process');
    const original=parseBridgeReplies(first.stdout,firstRequests.length);
    if(!original[0].ok||!original[1].ok||original[1].content!==content)
      throw Error('First native host failed to write and read the durable synthetic note.');
    console.log('PASS: First signed native host created a sandbox-container note.');

    // A NEW native host process and XPC connection must read the same note.
    // This proves filesystem continuity across host invocations, NOT that
    // launchd necessarily killed/restarted the XPC service between calls.
    const laterRequests=[
      frameBridgeRequest('READ',filename),
      frameBridgeRequest('WRITE',filename,'unapproved overwrite'),
      Buffer.from('READ ../../.ssh/id_ed25519 0\n','ascii'),
      frameBridgeRequest('READ',filename),
      frameBridgeRequest('REMOVE',filename),
      frameBridgeRequest('READ',filename)
    ];
    const later=await executeBatch(host,laterRequests);
    assertHealthyProcess(later,'second host process');
    const observed=parseBridgeReplies(later.stdout,laterRequests.length);
    const checks=[
      ['Second native host reads the identical durable note',observed[0].ok&&observed[0].content===content],
      ['Durable notes remain exclusive-create only',!observed[1].ok],
      ['Traversal to unrelated host files is rejected',!observed[2].ok],
      ['Denied operations leave note bytes unchanged',observed[3].ok&&observed[3].content===content],
      ['Synthetic durable note removed after acceptance',observed[4].ok],
      ['Removed note is no longer readable',!observed[5].ok]
    ];
    for(const [label,ok] of checks)console.log((ok?'PASS: ':'FAIL: ')+label);
    if(!checks.every(([,ok])=>ok))
      throw Error('Durable worker acceptance incomplete; do not integrate with MCP.');
    console.log('PASS: Workspace authority and sandbox-container storage accepted in test-only native path.');
    console.log('NOTE: No signer attestation, native service restart, real MCP authorization or audit integration has been proven.');
  }finally{rmSync(workspace,{recursive:true,force:true});}
}
main().catch(e=>{console.error('MAC DURABLE-XPC CHECK FAILED: '+e.message);process.exitCode=1;});
