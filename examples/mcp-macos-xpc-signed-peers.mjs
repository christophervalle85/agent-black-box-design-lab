/**
 * v0.8: opt-in positive Apple Development signing XPC identity experiment.
 *
 * Uses exactly ONE valid Apple Development identity installed in the local
 * Keychain, never exports a private key, never passes a certificate name
 * to an MCP tool, never persists cert metadata or binary fixtures.
 *
 * A dedicated signed host/worker pair checks OS-enforced SAME TEAM and exact
 * signing identifier both inbound and outbound. Ad-hoc test and the normal
 * MCP server remain completely separate. User files are not accessed.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos','xpc');
const HOST_ID='dev.agentblackbox.xpc-snapshot-receipt.host';
const WORKER_ID='dev.agentblackbox.xpc-snapshot-receipt.worker';
const expected=Object.freeze({
  'signed-valid':'BBX_XPC_SIGNED_MUTUAL_ACCEPTED\n',
  'wrong-worker':'BBX_XPC_SIGNED_OUTBOUND_OS_REJECTED\n'
});

export function assessSignedPeerExperiment(mode,observed){
  if(!Object.hasOwn(expected,mode))
    throw Error('Unsupported positive-signature XPC mode.');
  if(!observed || observed.error || observed.signal ||
     observed.status!==0 || observed.stdout!==expected[mode] ||
     observed.stderr!=='')
    throw Error('Signed XPC OS peer-identity acceptance not established.');
  return true;
}
export function selectLocalDevelopmentIdentity(output){
  if(typeof output!=='string')throw Error('Invalid Keychain identity listing.');
  const choices=[...output.matchAll(
    /^\s*\d+\)\s+([A-Fa-f0-9]{40})\s+"Apple Development: [^"\r\n]+"\s*$/gm
  )];
  if(choices.length!==1 || !/^\s*1 valid identities found\s*$/m.test(output))
    throw Error('Exactly one valid Apple Development Keychain identity is required. Do not use ad-hoc signing.');
  return choices[0][1]; // Used only within codesign argv, NEVER printed.
}
/**
 * Deliberately classify only known codesign failures, never echo raw stderr,
 * executable paths, certificate names, Team IDs or Keychain metadata.
 * Unknown causes remain unknown rather than being mistaken for XPC denial.
 */
export function describeCodesignFailure(observed){
  const data=String(observed?.stderr??'')+'\n'+String(observed?.stdout??'');
  const cases=[
    [/errSecInternalComponent/i,'Keychain signing operation failed (errSecInternalComponent)'],
    [/user interaction is not allowed|errSecInteractionNotAllowed|CSSMERR_CSP_NO_USER_INTERACTION/i,
      'Keychain authorization or user interaction unavailable'],
    [/user canceled|user cancelled|errSecUserCanceled/i,'Keychain authorization was cancelled'],
    [/identity.*(?:not found|missing)|no identity found|specified item could not be found/i,
      'Signing identity or private key unavailable'],
    [/keychain.*locked|locked.*keychain/i,'Keychain is locked'],
    [/resource fork|Finder information|detritus not allowed/i,
      'Signing target contains unsupported metadata'],
    [/timed out/i,'Signing command timed out']
  ];
  const reason=observed?.error?.code==='ETIMEDOUT'?'Signing command timed out':
    cases.find(([pattern])=>pattern.test(data))?.[1]??'Unclassified signing failure';
  const exit=Number.isInteger(observed?.status)?observed.status:'unknown';
  return reason+'; exit status '+exit;
}
function command(exe,args,label,{maxBuffer=16384,timeout=30000}={}){
  const r=spawnSync(exe,args,{encoding:'utf8',timeout,maxBuffer,
    env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}});
  if(r.error || r.signal || r.status!==0){
    if(exe==='/usr/bin/codesign' && args.includes('--sign'))
      throw Error(label+' failed ('+describeCodesignFailure(r)+
        '); no signed XPC evidence was accepted.');
    throw Error(label+' failed; no signed XPC evidence was accepted.');
  }
  return r;
}
export function parseSignedIdentity(display,expectedIdentifier){
  if(typeof display!=='string' || typeof expectedIdentifier!=='string')
    throw Error('Invalid signed executable inspection.');
  const id=[...display.matchAll(/^Identifier=(.+)$/gm)].map(x=>x[1].trim());
  const team=[...display.matchAll(/^TeamIdentifier=([A-Z0-9]{10})$/gm)]
    .map(x=>x[1]);
  if(id.length!==1 || team.length!==1 || id[0]!==expectedIdentifier)
    throw Error('Executable signing identifier or Apple Team ID unavailable/mismatched.');
  return team[0]; // Never printed, only compared.
}
function signingDetail(path,id){
  const result=command('/usr/bin/codesign',
    ['--display','--verbose=4',path],'Signed identity inspection');
  return parseSignedIdentity(result.stdout+'\n'+result.stderr,id);
}
function assertWorkerSandbox(path){
  const result=command('/usr/bin/codesign',
    ['--display','--entitlements','-','--xml',path],
    'Sandbox entitlement verification');
  const text=result.stdout+'\n'+result.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(text) ||
     /<key>com\.apple\.security\.network\.(?:client|server)<\/key>\s*<true\s*\/>/.test(text))
    throw Error('Worker requires App Sandbox and no network entitlement.');
}
async function main(){
  if(process.platform!=='darwin')
    throw Error('Interactive macOS required for signed-peer experiment.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required for this disposable developer-signing test.');
  const mode=process.argv[2];
  if(process.argv.length!==3 || (!Object.hasOwn(expected,mode) && mode!=='both'))
    throw Error('Expected signed-valid, wrong-worker or both.');
  const signingIdentity=selectLocalDevelopmentIdentity(command(
    '/usr/bin/security',['find-identity','-v','-p','codesigning'],
    'Local Apple Development identity lookup').stdout);
  const temp=mkdtempSync(join(tmpdir(),'bbx-signed-xpc-peer-'));
  try{
    const app=join(temp,'BlackBoxTransferReceiptHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxTransferReceiptHost');
    const service=join(app,'Contents','XPCServices',
      'BlackBoxTransferReceiptWorker.xpc');
    const worker=join(service,'Contents','MacOS',
      'BlackBoxTransferReceiptWorker');
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
      join(native,'TransferReceiptHost.c')],'Native signed host compilation');
    command('/usr/bin/xcrun',['clang',...flags,'-o',worker,
      join(native,'TransferReceiptService.m'),
      '-framework','Foundation'],'Native signed worker compilation');
    // Nested code must be signed *first*. No --deep signing.
    command('/usr/bin/codesign',[
      '--force','--sign',signingIdentity,'--options','runtime',
      '--identifier',WORKER_ID,
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
      service],'Apple Development worker signing');
    command('/usr/bin/codesign',[
      '--force','--sign',signingIdentity,'--options','runtime',
      '--identifier',HOST_ID,app],'Apple Development host signing');
    command('/usr/bin/codesign',['--verify','--strict','--deep',app],
      'Host and nested worker signature verification');
    command('/usr/bin/codesign',['--verify','--strict',service],
      'Worker signature verification');
    const hostTeam=signingDetail(app,HOST_ID);
    const workerTeam=signingDetail(service,WORKER_ID);
    if(hostTeam!==workerTeam)
      throw Error('Host and worker Team IDs differ; trust gate denied.');
    assertWorkerSandbox(service);
    console.log('PASS: Apple Development-signed host and sandboxed worker have matching Team IDs and exact signing identifiers.');
    // Both checks share the SAME signed bundle, so a second, unrelated
    // codesign/Keychain operation cannot obscure OS rejection evidence.
    const checks=mode==='both'?['signed-valid','wrong-worker']:[mode];
    for(const check of checks){
      console.log('ACTION: Checking OS-enforced signed XPC peer identity ('+check+'); no documents or Touch ID prompts.');
      const observed=spawnSync(host,[check],{
        encoding:'utf8',timeout:15000,maxBuffer:1024,
        env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
      });
      assessSignedPeerExperiment(check,observed);
      if(check==='signed-valid')
        console.log('PASS: OS-gated same-Team signed host and worker exchanged one bounded synthetic digest receipt.');
      else
        console.log('PASS: OS returned the specific code-signing-requirement error for a wrong worker signing identifier.');
    }
    console.log('NOTE: This validates test-only signed-peer identity, not operator approval or a production document transfer.');
  }finally{
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{
    console.error('SIGNED XPC PEER NOT ACCEPTED: '+error.message);
    process.exitCode=1;
  });
