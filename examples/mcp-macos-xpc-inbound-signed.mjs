/**
 * Native signed INCOMING-host XPC denial, synthetic-only macOS experiment.
 *
 * The legitimate Apple Development-signed host maintains one worker session.
 * A second independently signed executable has the SAME Team ID but a
 * deliberately different signing identifier. Its request must never reach
 * the worker message handler, proven by same-PID before/after worker counts.
 *
 * NO user files, OS picker, Touch ID, MCP tooling or durable worker writes.
 * Never print/store the selected Keychain identity, Team ID or private key.
 */
import {spawnSync} from 'node:child_process';
import {
  copyFileSync,mkdirSync,mkdtempSync,rmSync
} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  selectLocalDevelopmentIdentity,parseSignedIdentity,describeCodesignFailure
} from './mcp-macos-xpc-signed-peers.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos','xpc');
const HOST_ID='dev.agentblackbox.xpc-snapshot-receipt.host';
const WRONG_HOST_ID='dev.agentblackbox.xpc-snapshot-receipt.wrong-host';
const WORKER_ID='dev.agentblackbox.xpc-snapshot-receipt.worker';
const EXPECTED='BBX_XPC_SIGNED_INBOUND_OS_REJECTED\n';

export function assessSignedInboundEvidence(result){
  if(!result || result.error || result.signal || result.status!==0 ||
     result.stdout!==EXPECTED || result.stderr!=='')
    throw Error('Native worker-side incoming peer rejection not established.');
  return true;
}
function command(tool,args,label,{timeout=30000,maxBuffer=12000}={}){
  const result=spawnSync(tool,args,{encoding:'utf8',timeout,maxBuffer,
    env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}});
  if(result.error || result.signal || result.status!==0){
    if(tool==='/usr/bin/codesign' && args.includes('--sign'))
      throw Error(label+' failed ('+describeCodesignFailure(result)+
        '); no incoming OS evidence was accepted.');
    throw Error(label+' failed; no incoming OS evidence was accepted.');
  }
  return result;
}
function inspectCode(path,identifier){
  const result=command('/usr/bin/codesign',[
    '--display','--verbose=4',path],'Signed executable identity inspection');
  return parseSignedIdentity(result.stdout+'\n'+result.stderr,identifier);
}
function requireWorkerSandbox(path){
  const result=command('/usr/bin/codesign',[
    '--display','--entitlements','-','--xml',path],
    'Worker sandbox entitlement inspection');
  const details=result.stdout+'\n'+result.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(details) ||
     /<key>com\.apple\.security\.network\.(?:client|server)<\/key>\s*<true\s*\/>/.test(details))
    throw Error('Verified sandboxed worker with no network entitlement required.');
}
async function main(){
  if(process.platform!=='darwin')
    throw Error('macOS required for signed inbound-peer acceptance.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required for signed test-only XPC peer fixture.');
  if(process.argv.length!==2)
    throw Error('This signed inbound-peer fixture takes no arguments.');
  const identity=selectLocalDevelopmentIdentity(command(
    '/usr/bin/security',['find-identity','-v','-p','codesigning'],
    'Apple Development Keychain identity selection').stdout);
  const temp=mkdtempSync(join(tmpdir(),'bbx-signed-inbound-'));
  try{
    const app=join(temp,'BlackBoxTransferReceiptHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxTransferReceiptHost');
    const wrong=join(app,'Contents','MacOS','BlackBoxTransferReceiptWrongHost');
    const service=join(app,'Contents','XPCServices',
      'BlackBoxTransferReceiptWorker.xpc');
    const worker=join(service,'Contents','MacOS','BlackBoxTransferReceiptWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(native,'TransferReceiptHost-Info.plist'),
      join(app,'Contents','Info.plist'));
    copyFileSync(join(native,'TransferReceiptService-Info.plist'),
      join(service,'Contents','Info.plist'));
    const flags=['-fblocks','-std=c11','-O2','-Wall','-Wextra',
      '-Werror=implicit-function-declaration',
      '-DBBX_TEST_SIGNED_PEER_REQUIREMENT=1'];
    command('/usr/bin/xcrun',['clang',...flags,'-o',host,
      join(native,'SignedInboundHost.c')],'Signed inbound trusted host build');
    // Identical bytes to the legitimate host, distinct executable
    // code-signing identity. Code is signed before the containing app.
    copyFileSync(host,wrong);
    command('/usr/bin/xcrun',['clang',...flags,
      '-DBBX_TEST_SIGNED_INBOUND_EVIDENCE=1','-o',worker,
      join(native,'TransferReceiptService.m'),'-framework','Foundation'],
      'Signed inbound worker build');
    command('/usr/bin/codesign',[
      '--force','--sign',identity,'--options','runtime',
      '--identifier',WORKER_ID,
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
      service],'Apple Development inbound worker signing');
    command('/usr/bin/codesign',[
      '--force','--sign',identity,'--options','runtime',
      '--identifier',WRONG_HOST_ID,wrong],
      'Apple Development wrong-host signing');
    command('/usr/bin/codesign',[
      '--force','--sign',identity,'--options','runtime',
      '--identifier',HOST_ID,app],
      'Apple Development legitimate app signing');
    command('/usr/bin/codesign',['--verify','--strict','--deep',app],
      'Signed nested app integrity check');
    command('/usr/bin/codesign',['--verify','--strict',service],
      'Signed worker integrity check');
    command('/usr/bin/codesign',['--verify','--strict',wrong],
      'Signed wrong-host integrity check');
    const teams=[
      inspectCode(app,HOST_ID),
      inspectCode(service,WORKER_ID),
      inspectCode(wrong,WRONG_HOST_ID)
    ];
    if(teams.some(t=>t!==teams[0]))
      throw Error('Signed host, worker and wrong-host helper lack identical Apple Team IDs.');
    requireWorkerSandbox(service);
    console.log('PASS: Legitimate host, wrong-identifier helper and sandboxed worker are Apple Development signed by the same Team ID.');
    console.log('ACTION: Real OS-enforced inbound-host identity check on one live sandboxed worker; no files or biometric prompts.');
    const observed=spawnSync(host,['orchestrate'],{
      encoding:'utf8',timeout:15000,maxBuffer:1024,
      env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
    });
    assessSignedInboundEvidence(observed);
    console.log('PASS: Worker accepted legitimate receipt, then rejected the differently signed incoming host before handler delivery.');
    console.log('PASS: Same worker process stayed live and its handler counter increased ONLY for authorized control probes.');
    console.log('NOTE: Signed synthetic-only identity test, not Touch ID approval, file transfer or production Developer ID acceptance.');
  }finally{
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{
    console.error('SIGNED INBOUND PEER NOT ACCEPTED: '+error.message);
    process.exitCode=1;
  });
