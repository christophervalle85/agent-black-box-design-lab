/**
 * Real macOS NSOpenPanel diagnostic: select/cancel a single generated fixture.
 *
 * No imported contents, no arbitrary file paths, no MCP calls, and no user
 * documents touched. The on-device result is not a transfer capability.
 */
import {spawnSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir,homedir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const base=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const nativeSource=join(base,'native','macos','SyntheticOpenPanel.m');
const markers=Object.freeze({
  select:Object.freeze({status:0,stdout:'BBX_MAC_PICKER_EXACT_FIXTURE_SELECTED\n'}),
  cancel:Object.freeze({status:83,stdout:'BBX_MAC_PICKER_USER_CANCELLED\n'}),
  'reject-other':Object.freeze({status:87,stdout:'BBX_MAC_PICKER_OTHER_FIXTURE_REJECTED\n'})
});
export function assessMacSyntheticPicker(mode,observed={}){
  if(!Object.hasOwn(markers,mode))throw Error('Invalid picker test mode.');
  const expected=markers[mode];
  if(observed.error || observed.signal || observed.status!==expected.status ||
     observed.stdout!==expected.stdout || observed.stderr!=='')
    throw Error('macOS Open Panel returned no accepted '+mode+
      ' evidence: status='+String(observed.status)+
      ' marker='+String(observed.stdout??'').trim().slice(0,80));
  return true;
}
function command(exe,args,label,{timeout=30000}={}){
  const r=spawnSync(exe,args,{
    encoding:'utf8',timeout,maxBuffer:4096,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
  });
  if(r.error||r.signal||r.status!==0)
    throw Error(label+' failed: '+
      String(r.error?.message??r.stderr??r.signal??r.stdout).slice(0,300));
}
async function main(){
  if(process.platform!=='darwin')throw Error('Interactive macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required for ad-hoc fixture.');
  const mode=process.argv[2];
  if(process.argv.length!==3 || !Object.hasOwn(markers,mode))
    throw Error('Expected exactly one mode: select, cancel, or reject-other.');
  const temp=mkdtempSync(join(tmpdir(),'bb-mac-panel-fixture-'));
  try{
    const file=join(temp,'bbx-test-panel.txt');
    writeFileSync(file,'BBX synthetic picker fixture',{mode:0o600,flag:'wx'});
    const other=join(temp,'bbx-test-other.txt');
    if(mode==='reject-other')
      writeFileSync(other,'BBX synthetic picker fixture',{mode:0o600,flag:'wx'});
    const executable=join(temp,'BlackBoxSyntheticOpenPanel');
    command('/usr/bin/xcrun',[
      'clang','-fobjc-arc','-std=c11','-Wall','-Wextra',
      '-O2','-o',executable,nativeSource,
      '-framework','AppKit','-framework','Foundation'
    ],'Native Open Panel compilation');
    command('/usr/bin/codesign',[
      '--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.synthetic-open-panel',
      executable
    ],'Test fixture ad-hoc signing');
    command('/usr/bin/codesign',['--verify','--strict',executable],
      'Native fixture signature verification');
    console.log('PASS: Disposable AppKit Open Panel helper compiled and ad-hoc signature verified.');
    if(mode==='select')
      console.log('ACTION: Choose ONLY bbx-test-panel.txt in the macOS file-selection window, then click Select Test File.');
    else if(mode==='cancel')
      console.log('ACTION: Click Cancel in the macOS file-selection window. DO NOT select a file.');
    else
      console.log('ACTION: NEGATIVE TEST — select ONLY bbx-test-other.txt, then click Select Test File. The helper must reject this wrong fixture. Do not select personal files.');
    const args=mode==='reject-other'?[mode,file,other]:[mode,file];
    const r=spawnSync(executable,args,{
      encoding:'utf8',timeout:90000,maxBuffer:4096,
      env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
    });
    assessMacSyntheticPicker(mode,r);
    if(mode==='select')
      console.log('PASS: Native file selection matched ONLY the disposable synthetic fixture.');
    else if(mode==='cancel')
      console.log('PASS: Native file panel returned an explicit user-cancellation result.');
    else
      console.log('PASS: Native file panel rejected the independently verified alternate synthetic fixture.');
    console.log('PASS: The fixture never returned file paths or contents to the caller.');
    console.log('NOTE: No imported data, sandboxed file capability or native MCP transfer.');
  }finally{
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{
    console.error('MAC FILE PICKER NOT ACCEPTED: '+e.message);
    process.exitCode=1;
  });
