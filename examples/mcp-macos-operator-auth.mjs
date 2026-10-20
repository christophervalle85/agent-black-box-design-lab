/**
 * Native macOS LocalAuthentication acceptance — independent OS evidence.
 *
 * This does NOT wire LocalAuthentication into the Phase 5 controller or
 * authorize file transfers. A real Mac with an interactive GUI session is
 * required. Positive acceptance needs real device-owner authentication;
 * negative acceptance needs an actual OS user-cancel outcome, not any error.
 */
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir,homedir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const source=join(root,'native','macos','LocalOperatorAuthentication.m');
const markerFor=Object.freeze({
  probe:{status:0,marker:'BBX_LOCAL_AUTH_AVAILABLE\n'},
  approve:{status:0,marker:'BBX_LOCAL_AUTH_SUCCEEDED\n'},
  cancel:{status:83,marker:'BBX_LOCAL_AUTH_USER_CANCELLED\n'},
  'touchid-probe':{status:0,marker:'BBX_LOCAL_AUTH_TOUCHID_AVAILABLE\n'},
  'touchid-approve':{status:0,marker:'BBX_LOCAL_AUTH_TOUCHID_SUCCEEDED\n'},
  'touchid-cancel':{status:83,marker:'BBX_LOCAL_AUTH_TOUCHID_USER_CANCELLED\n'}
});
export function assessMacOperatorAuth(mode,{
  status,stdout='',stderr='',error=null,signal=null
}={}) {
  if(!Object.hasOwn(markerFor,mode))
    throw Error('Unsupported macOS operator test mode.');
  const expected=markerFor[mode];
  if(error || signal || status!==expected.status ||
     stdout!==expected.marker || stderr!=='')
    throw Error('macOS OS-authentication evidence did not match '+mode+
      ' acceptance; status='+String(status)+', marker='+
      stdout.trim().slice(0,120)+', error='+
      String(error?.message??signal??'none').slice(0,120));
  return true;
}
function run(exe,args,{timeout=30000}={}){
  const r=spawnSync(exe,args,{
    encoding:'utf8',timeout,maxBuffer:4096,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
  });
  if(r.error || r.signal)throw Error('Native command failed: '+
    String(r.error?.message??r.signal));
  return r;
}
async function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required for this disposable native test.');
  const mode=process.argv[2];
  if(process.argv.length!==3 || !Object.hasOwn(markerFor,mode))
    throw Error('Expected probe, approve, cancel, touchid-probe, touchid-approve or touchid-cancel.');
  const temp=mkdtempSync(join(tmpdir(),'bb-local-auth-'));
  try{
    const executable=join(temp,'BlackBoxLocalAuthFixture');
    const compile=run('/usr/bin/xcrun',[
      'clang','-fobjc-arc','-std=c11','-Wall','-Wextra',
      '-O2','-o',executable,source,
      '-framework','Foundation','-framework','LocalAuthentication'
    ]);
    if(compile.status!==0)
      throw Error('Native LocalAuthentication compilation failed: '+
        compile.stderr.slice(0,800));
    const signature=run('/usr/bin/codesign',[
      '--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.mac-local-auth-fixture',
      executable
    ]);
    if(signature.status!==0)
      throw Error('Disposable native auth helper signing failed.');
    const check=run('/usr/bin/codesign',['--verify','--strict',executable]);
    if(check.status!==0)throw Error('Disposable helper signature did not verify.');
    console.log('PASS: Disposable LocalAuthentication helper compiled and ad-hoc signature verified.');
    if(mode==='approve')
      console.log('ACTION: Authenticate using macOS Touch ID, Watch, or password as configured.');
    if(mode==='cancel')
      console.log('ACTION: Click Cancel in the macOS prompt; avoid Touch ID / Apple Watch confirmation.');
    if(mode==='touchid-approve')
      console.log('ACTION: Use your enrolled Touch ID finger to authenticate; this mode excludes Watch/password fallback.');
    if(mode==='touchid-cancel')
      console.log('ACTION: Click Cancel on the Touch ID prompt WITHOUT touching the sensor; Watch/password fallback is excluded.');
    const output=run(executable,[mode],{timeout:90000});
    assessMacOperatorAuth(mode,output);
    if(mode==='probe')
      console.log('PASS: macOS LocalAuthentication device-owner policy is available.');
    if(mode==='approve')
      console.log('PASS: Real macOS device-owner authentication succeeded; synthetic-only.');
    if(mode==='cancel')
      console.log('PASS: Real macOS device-owner policy returned an explicit user-cancel result; synthetic-only.');
    if(mode==='touchid-probe')
      console.log('PASS: macOS biometric-only authentication is available (Touch ID enrolled).');
    if(mode==='touchid-approve')
      console.log('PASS: Real macOS biometric-only authentication succeeded; synthetic-only.');
    if(mode==='touchid-cancel')
      console.log('PASS: Real macOS biometric-only user cancellation was rejected; synthetic-only.');
    console.log('NOTE: OS identity is not bound to any controller approval, picker or XPC transfer.');
  } finally {
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error('MAC OPERATOR AUTH NOT ACCEPTED: '+e.message);
    process.exitCode=1;});
