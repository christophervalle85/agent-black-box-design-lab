/**
 * v0.8 Phase 6: real macOS, synthetic-only user-selected fd snapshot proof.
 *
 * A disposable AppKit helper opens only a generated test file after native
 * selection, hashes a bounded fd read, and returns size/digest only.
 * NO user documents, MCP/XPC import/export, production signing or grants.
 */
import {spawnSync} from 'node:child_process';
import {createHash,timingSafeEqual} from 'node:crypto';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const source=join(root,'native','macos','SelectedFileSnapshot.m');
const BASE=Buffer.from('BBX synthetic fd snapshot test\n','utf8');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const sha=/^[a-f0-9]{64}$/;
function sameDigest(a,b){
  if(!sha.test(a)||!sha.test(b))return false;
  return timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
}
export function assessNativeMacSnapshot(mode,result,{expectedDigest,stagedDigest,byteLength}={}){
  if(!['select','altered'].includes(mode))throw Error('Unknown native snapshot acceptance mode.');
  if(!result || result.error || result.signal || result.status!==0 ||
     result.stderr!=='' || typeof result.stdout!=='string' ||
     !Number.isSafeInteger(byteLength) || byteLength<1 || byteLength>2000 ||
     !sha.test(expectedDigest??'') || !sha.test(stagedDigest??''))
    throw Error('Unacceptable native file snapshot outcome.');
  const exact='BBX_SNAPSHOT_READ '+byteLength+' '+stagedDigest+'\n';
  if(result.stdout!==exact)
    throw Error('Native snapshot differs from staged test fixture or output contract.');
  const matched=sameDigest(stagedDigest,expectedDigest);
  if(mode==='select' && !matched)
    throw Error('Selected synthetic content digest changed; import denied.');
  if(mode==='altered' && matched)
    throw Error('Altered fixture unexpectedly matched the reviewed content.');
  return mode==='select'?'exact synthetic snapshot':'modified synthetic snapshot rejected';
}
function cmd(exe,args,label){
  const r=spawnSync(exe,args,{
    encoding:'utf8',timeout:30000,maxBuffer:8192,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
  });
  if(r.error||r.signal||r.status!==0)
    throw Error(label+' failed: '+String(r.error?.message??r.stderr??r.stdout??r.signal).slice(0,320));
}
async function main(){
  if(process.platform!=='darwin')
    throw Error('Real interactive macOS session is required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required for this ad-hoc experiment.');
  const mode=process.argv[2];
  if(process.argv.length!==3 || !['select','altered'].includes(mode))
    throw Error('Expected exactly one mode: select or altered.');
  const temp=mkdtempSync(join(tmpdir(),'bb-native-snapshot-'));
  try{
    const file=join(temp,'bbx-test-snapshot.txt');
    const expected=Buffer.from(BASE);
    const staged=Buffer.from(BASE);
    if(mode==='altered')staged[0]^=1; // deterministic same-length content change
    writeFileSync(file,staged,{mode:0o600,flag:'wx'});
    const executable=join(temp,'BlackBoxSelectedFileSnapshot');
    cmd('/usr/bin/xcrun',[
      'clang','-fobjc-arc','-std=c11','-Wall','-Wextra',
      '-Werror=implicit-function-declaration','-O2',
      '-o',executable,source,'-framework','AppKit','-framework','Foundation'
    ],'Native snapshot build');
    cmd('/usr/bin/codesign',[
      '--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.native-fd-snapshot-test',executable
    ],'Disposable signing');
    cmd('/usr/bin/codesign',['--verify','--strict',executable],
      'Native binary signature verification');
    console.log('PASS: Native selected-fd snapshot helper compiled and ad-hoc signature verified.');
    if(mode==='select')
      console.log('ACTION: Select ONLY bbx-test-snapshot.txt and click Select Synthetic File.');
    else
      console.log('ACTION: NEGATIVE CONTENT TEST — select ONLY bbx-test-snapshot.txt. This synthetic fixture has a deliberately altered byte and MUST be rejected.');
    const result=spawnSync(executable,[file],{
      encoding:'utf8',timeout:90000,maxBuffer:4096,
      env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
    });
    const outcome=assessNativeMacSnapshot(mode,result,{
      byteLength:expected.length,expectedDigest:hash(expected),
      stagedDigest:hash(staged)
    });
    if(mode==='select')
      console.log('PASS: '+outcome+' matched exact expected SHA-256 and byte count.');
    else
      console.log('PASS: '+outcome+'; altered bytes cannot satisfy the reviewed digest.');
    console.log('PASS: Native helper exposed only a digest and byte count, never selected path or file contents.');
    console.log('NOTE: Synthetic user-selected read only; no XPC transfer, MCP import, or required sandbox authorization.');
  }finally{
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{
    console.error('NATIVE FD SNAPSHOT NOT ACCEPTED: '+error.message);
    process.exitCode=1;
  });
