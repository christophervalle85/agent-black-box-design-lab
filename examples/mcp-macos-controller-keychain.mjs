/**
 * Separate, explicitly invoked macOS Keychain enrollment for a TEST RSA
 * controller credential. Private key never leaves the macOS Keychain through
 * this program. Compiled and Apple Development-signed helper is distinct
 * from the Touch ID/XPC reviewed-host binary.
 *
 * Signing also requires fresh in-helper Touch ID consent; the Keychain
 * credential remains a software test key, not an ACL-bound independent
 * authorization service or production-trusted controller.
 */
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir,homedir} from 'node:os';
import {join,dirname,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {selectLocalDevelopmentIdentity} from './mcp-macos-xpc-signed-peers.mjs';
import {
  parseMacKeychainPublicRecord,encodeMacKeychainUnsignedReview,
  validateMacKeychainSignedReview
} from '../src/macos-controller-keychain.mjs';
import {
  enrollMacControllerPublicPin,assertMacControllerEnrolledPin
} from '../src/macos-controller-pin.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const source=join(root,'native','macos','xpc','KeychainControllerSigner.m');
const env=()=>({PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'});
function invoke(tool,args,{input=null,timeout=30000}={}){
  const process=spawnSync(tool,args,{
    encoding:null,input,env:env(),timeout,maxBuffer:4096
  });
  return process;
}
function mustRun(tool,args,label){
  const result=invoke(tool,args);
  if(result.error||result.signal||result.status!==0)
    throw Error(label+' failed; Keychain controller identity not accepted.');
  return result;
}
export function buildSignedMacKeychainControllerHelper(temp,identity){
  if(process.platform!=='darwin'||typeof identity!=='string'||!identity)
    throw Error('A real Mac and Apple Development signing identity are required.');
  const helper=join(temp,'BBXTestControllerKeychain');
  mustRun('/usr/bin/xcrun',['clang','-std=c11','-fno-objc-arc','-O2',
    '-Wall','-Wextra','-Werror=implicit-function-declaration','-o',helper,
    source,'-framework','Foundation','-framework','Security',
    '-framework','LocalAuthentication'],
  'Keychain test helper compile');
  mustRun('/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',
    '--identifier','dev.agentblackbox.test.controller-keychain',helper],
  'Keychain test helper signature');
  mustRun('/usr/bin/codesign',['--verify','--strict',helper],
  'Keychain test helper integrity');
  return helper;
}
export function readMacKeychainControllerIdentity(helper){
  const result=mustRun(helper,['public'],'Persistent test controller public-key retrieval');
  return parseMacKeychainPublicRecord(result.stdout.toString('ascii'));
}
export function signMacKeychainReviewedTransaction(helper,tx,{
  publicKey,reservationMac,auditDirectory,now=Date.now()
}={}){
  if(typeof auditDirectory!=='string'||!auditDirectory.startsWith('/')||
     auditDirectory.includes('\0'))
    throw Error('Native HMAC audit directory required.');
  const unsigned=encodeMacKeychainUnsignedReview(tx,{reservationMac,now});
  const result=invoke(helper,['sign',auditDirectory],
    {input:unsigned,timeout:50000});
  if(result.error||result.signal||result.status!==0)
    throw Error('Persistent controller did not obtain Touch ID consent or refused the signed review.');
  return validateMacKeychainSignedReview(result.stdout,{
    publicKey,transaction:tx,reservationMac,now
  });
}
/**
 * Negative-only diagnostic. A fresh helper process must return exactly 88
 * (the native signing marker exists for this reviewed transaction).
 * Other failures, including Keychain errors, are NOT evidence of replay.
 * No signature material or Touch ID prompt may be emitted on this path.
 */
export function assertMacKeychainSignerReplayDenied(helper,tx,{
  reservationMac,auditDirectory,now=Date.now()
}={}){
  if(typeof auditDirectory!=='string'||!auditDirectory.startsWith('/')||
     auditDirectory.includes('\0'))
    throw Error('Native HMAC audit directory required.');
  const unsigned=encodeMacKeychainUnsignedReview(tx,{reservationMac,now});
  const outcome=invoke(helper,['sign',auditDirectory],
    {input:unsigned,timeout:2500});
  if(outcome.error||outcome.signal||outcome.status!==88||
     outcome.stdout.length!==0||outcome.stderr.length!==0)
    throw Error('Exact native Keychain signer replay denial not proven.');
  return true;
}
async function main(){
  if(process.platform!=='darwin')
    throw Error('Explicit controller Keychain enrollment requires a real Mac.');
  const mode=process.argv[2];
  if(process.argv.length!==3||!['provision','inspect'].includes(mode))
    throw Error('Use "provision" once or "inspect" to verify enrolled public key.');
  const found=mustRun('/usr/bin/security',
    ['find-identity','-v','-p','codesigning'],'Apple Development identity discovery');
  const identity=selectLocalDevelopmentIdentity(found.stdout.toString('utf8'));
  const temp=mkdtempSync(join(tmpdir(),'bbx-controller-keychain-'));
  try{
    const helper=buildSignedMacKeychainControllerHelper(temp,identity);
    if(mode==='provision'){
      const result=invoke(helper,['provision']);
      if(result.error||result.signal||result.status!==0 ||
         result.stdout.toString('ascii')!=='BBX_KEYCHAIN_CONTROLLER_PROVISIONED\n' ||
         result.stderr.length!==0)
        throw Error('Provisioning denied: existing key, unavailable Keychain or insecure key attributes. No automatic replacement.');
      console.log('PASS: Separate test controller RSA key enrolled in the macOS Keychain without emitting private bytes.');
    }
    const publicRecord=readMacKeychainControllerIdentity(helper);
    if(mode==='provision')
      enrollMacControllerPublicPin(publicRecord.sha256);
    else assertMacControllerEnrolledPin(publicRecord.sha256);
    console.log('PASS: Persistent enrolled RSA-2048 public key matches its separate local trust pin.');
    console.log('PUBLIC SHA256 (PKCS1 DER): '+publicRecord.sha256);
    console.log('NOTE: Software macOS Keychain and test helper, not Secure Enclave, a remote controller or production approval authority.');
  }finally{rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{
    console.error('CONTROLLER KEYCHAIN TEST DENIED: '+e.message);
    process.exitCode=1;
  });
