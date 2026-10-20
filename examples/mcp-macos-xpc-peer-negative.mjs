/**
 * Narrow on-Mac negative test: an ad-hoc-signed host must NOT be able to
 * establish an Apple-verified same-team XPC peer identity.
 *
 * Phase 4 precondition check only. It does not validate production signing.
 * No MCP tools, writes, approval controller or policy workspace are touched.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,mkdtempSync,mkdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseBridgeReply} from '../src/macos-xpc-bridge-wire.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const run=(exe,args,{input,timeout=30000}={})=>spawnSync(exe,args,{
  input,encoding:'utf8',timeout,maxBuffer:65536,
  env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',TMPDIR:tmpdir(),HOME:process.env.HOME??''}
});
function command(exe,args,label,opts={}) {
  const r=run(exe,args,opts);
  if(r.error||r.status!==0||r.signal)
    throw Error(label+' failed: '+(r.error?.message??r.stderr?.trim()??r.status));
  return r;
}
export function assessAdhocPeerRejection(baseline,negative) {
  if(!baseline || baseline.status!==0 || baseline.signal ||
     !baseline.stdout?.startsWith('OK '))
    throw Error('Unrestricted baseline XPC connection did not succeed.');
  if(!negative || negative.error || negative.signal || negative.status!==86 ||
     !negative.stderr?.includes('BBX_PEER_REQUIREMENT_OS_REJECTED'))
    throw Error('Apple peer identity requirement did not demonstrably reject the ad-hoc worker.');
  if(negative.stdout?.includes('OK '))
    throw Error('Restricted XPC client unexpectedly received worker data.');
  return true;
}
function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required.');
  if(process.env.MCP_SANDBOX==='required')
    throw Error('Cannot run experimental peer negative fixture under required mode.');
  if(process.argv.slice(2).length!==0)throw Error('This fixture takes no arguments.');
  command('/usr/bin/xcrun',['--find','clang'],'Clang availability');
  const dir=mkdtempSync(join(tmpdir(),'bb-peer-negative-'));
  try {
    const app=join(dir,'BlackBoxAuthorityHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxAuthorityHost');
    const service=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
    const worker=join(service,'Contents','MacOS','BlackBoxAuthorityWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(sources,'AuthorityHost-Info.plist'),join(app,'Contents','Info.plist'));
    copyFileSync(join(sources,'AuthorityService-Info.plist'),join(service,'Contents','Info.plist'));
    const compileHost=extra=>command('/usr/bin/xcrun',
      ['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',...extra,
       '-o',host,join(sources,'AuthorityBridgeHost.c')],'Native host compilation');
    const sign=()=>command('/usr/bin/codesign',
      ['--force','--sign','-','--options','runtime',
       '--identifier','dev.agentblackbox.xpc-authority.host',app],
      'Ad-hoc test host bundle signing');
    compileHost([]);
    command('/usr/bin/xcrun',['clang','-std=c11','-fblocks','-O2','-Wall','-Wextra',
      '-o',worker,join(sources,'AuthorityNotesService.m'),'-framework','Foundation'],
      'Native XPC worker compilation');
    command('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-authority.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),service],
      'Ad-hoc worker signing');
    sign();
    command('/usr/bin/codesign',['--verify','--deep','--strict',app],'Nested signature');
    const baseline=run(host,[],{input:'ROOT - 0\n'});
    if(baseline.status!==0||baseline.signal||!baseline.stdout?.startsWith('OK '))
      throw Error('Baseline native peer could not reach the worker; cannot test identity rejection.');
    const parsed=parseBridgeReply(Buffer.from(baseline.stdout,'utf8'));
    if(!parsed.ok||!parsed.content.includes('/Library/Containers/'))
      throw Error('Baseline did not reach actual sandboxed native workspace.');
    console.log('PASS: Baseline ad-hoc host connected to real private XPC notes worker.');
    // Rebuild the SAME host bundle with Apple's peer requirement installed
    // before resume(), then re-sign the test app's modified code seal.
    compileHost(['-DBBX_TEST_PEER_REQUIREMENT=1']);
    sign();
    command('/usr/bin/codesign',['--verify','--deep','--strict',app],'Nested signed negative app');
    const negative=run(host,[],{input:'ROOT - 0\n'});
    if(!assessAdhocPeerRejection(baseline,negative))
      throw Error('Unreachable native peer negative gate.');
    console.log('PASS: Apple runtime same-team peer requirement rejected ad-hoc XPC worker.');
    console.log('PASS: No unauthenticated worker response was forwarded by restricted native host.');
    console.log('NOTE: Developer ID positive peer acceptance and worker-side host authentication remain blocked.');
  }finally{rmSync(dir,{recursive:true,force:true});}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  try{main();}catch(error){console.error('XPC PEER IDENTITY NEGATIVE NOT ACCEPTED: '+error.message);process.exitCode=1;}
