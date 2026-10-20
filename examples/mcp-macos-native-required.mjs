/**
 * Opt-in local installer for the v0.8 Mac required-mode MCP native host.
 * Only an explicit CLI action writes this separate Apple Development-signed
 * app. Never touches/re-enrolls the previously pinned Keychain RSA identity.
 * No GitHub Actions, sudo, Developer ID, notarization or MCP tool activation.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,existsSync,lstatSync,mkdirSync,mkdtempSync,
  readFileSync,renameSync,rmSync,writeFileSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  MAC_NATIVE_REQUIRED_DIR,MAC_NATIVE_REQUIRED_APP,
  assertMacRequiredPin,verifyMacRequiredInstallation,
  probeMacRequiredWorkspace
} from '../src/macos-required-mcp.mjs';
import {selectLocalDevelopmentIdentity,parseSignedIdentity,
  describeCodesignFailure} from './mcp-macos-xpc-signed-peers.mjs';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sources=join(root,'native','macos','xpc');
const hostId='dev.agentblackbox.xpc-authority.host';
const workerId='dev.agentblackbox.xpc-authority.worker';

function command(exe,args,label,timeout=90000){
  const a=spawnSync(exe,args,{encoding:'utf8',timeout,maxBuffer:8192,
    env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}});
  if(a.error||a.signal||a.status!==0){
    const reason=exe==='/usr/bin/codesign'&&args.includes('--sign')?
      ' ('+describeCodesignFailure(a)+')':'';
    throw Error(label+' failed closed'+reason);
  }
  return a.stdout+'\n'+a.stderr;
}
function build(stage,identity){
  const app=join(stage,MAC_NATIVE_REQUIRED_APP);
  const host=join(app,'Contents','MacOS','BlackBoxAuthorityHost');
  const bundle=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
  const worker=join(bundle,'Contents','MacOS','BlackBoxAuthorityWorker');
  mkdirSync(dirname(host),{recursive:true});
  mkdirSync(dirname(worker),{recursive:true});
  copyFileSync(join(sources,'AuthorityHost-Info.plist'),join(app,'Contents','Info.plist'));
  copyFileSync(join(sources,'AuthorityService-Info.plist'),join(bundle,'Contents','Info.plist'));
  const flags=['-std=c11','-fblocks','-O2','-Wall','-Wextra',
    '-Werror=implicit-function-declaration','-DBBX_NATIVE_REQUIRED_MCP=1'];
  command('/usr/bin/xcrun',['clang',...flags,'-o',host,
    join(sources,'AuthorityBridgeHost.c')],'Required signed MCP native host build');
  command('/usr/bin/xcrun',['clang',...flags,'-o',worker,
    join(sources,'AuthorityNotesService.m'),'-framework','Foundation'],
    'Required signed MCP XPC worker build');
  command('/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',
    '--identifier',workerId,'--entitlements',
    join(root,'native','macos','SandboxProbe.entitlements'),bundle],
    'Required native worker signing');
  command('/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',
    '--identifier',hostId,app],'Required MCP host signing');
  command('/usr/bin/codesign',['--verify','--strict','--deep',app],
    'Required native nested signature');
  command('/usr/bin/codesign',['--verify','--strict',bundle],
    'Required native worker signature');
  const teams=[hostId,workerId].map((id,i)=>{
    const target=i===0?app:bundle;
    return parseSignedIdentity(command('/usr/bin/codesign',
      ['--display','--verbose=4',target],'Required identity inspection'),id);
  });
  if(teams[0]!==teams[1])
    throw Error('Required native host/worker Team IDs differ.');
  return {app,host,team:teams[0]};
}
function ensureDir(){
  mkdirSync(MAC_NATIVE_REQUIRED_DIR,{recursive:true,mode:0o700});
  const st=lstatSync(MAC_NATIVE_REQUIRED_DIR);
  if(st.isSymbolicLink()||!st.isDirectory()||st.uid!==process.getuid()||
     (st.mode&0o077)!==0)
    throw Error('Required native installer directory is unsafe.');
}
async function main(){
  if(process.platform!=='darwin')throw Error('Real macOS required for signed native MCP installation.');
  const mode=process.argv[2];
  if(process.argv.length!==3||!['install','install-replace','verify'].includes(mode))
    throw Error('Use install, install-replace (explicit replacement), or verify.');
  if(mode==='verify'){
    const item=verifyMacRequiredInstallation();
    const path=probeMacRequiredWorkspace(item.host);
    console.log('PASS: Native host, XPC worker, pinned Team ID and worker-owned workspace verified.');
    console.log('MCP_WORKSPACE_ROOT='+JSON.stringify(path));
    return;
  }
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required for local native installer.');
  ensureDir();
  const pinPath=join(MAC_NATIVE_REQUIRED_DIR,'trust-pin.json');
  const dest=join(MAC_NATIVE_REQUIRED_DIR,MAC_NATIVE_REQUIRED_APP);
  const replacing=mode==='install-replace';
  if(replacing&&!existsSync(dest))
    throw Error('No existing signed native MCP app to replace.');
  if(!replacing&&existsSync(dest))
    throw Error('Native MCP app already installed; no implicit replacement.');
  const trust=existsSync(pinPath)?assertMacRequiredPin(
    JSON.parse(readFileSync(pinPath,'utf8'))):null;
  if(replacing){
    const verified=verifyMacRequiredInstallation();
    if(verified.teamId!==trust)throw Error('Existing signing identity not pinned.');
  }
  const identity=selectLocalDevelopmentIdentity(command('/usr/bin/security',
    ['find-identity','-v','-p','codesigning'],'Local Apple Development certificate'));
  const stage=mkdtempSync(join(MAC_NATIVE_REQUIRED_DIR,'.build-'));
  let backup=null;
  try{
    const built=build(stage,identity);
    if(trust!==null&&trust!==built.team)
      throw Error('Existing independent Team pin differs; refusing native identity replacement.');
    const workspace=probeMacRequiredWorkspace(built.host);
    if(replacing){
      backup=join(MAC_NATIVE_REQUIRED_DIR,
        '.replaced-backup-'+process.pid);
      if(existsSync(backup))throw Error('Native backup path already exists.');
      renameSync(dest,backup);
    }
    try{renameSync(built.app,dest);}
    catch(e){if(backup)renameSync(backup,dest);backup=null;throw e;}
    if(trust===null){
      writeFileSync(pinPath,JSON.stringify({version:1,teamId:built.team})+'\n',
        {mode:0o600,flag:'wx'});
    }
    const verified=verifyMacRequiredInstallation();
    if(verified.teamId!==built.team)
      throw Error('Post-install trusted identity mismatch.');
    if(backup){rmSync(backup,{recursive:true,force:true});backup=null;}
    console.log('PASS: Signed native MCP app installed with OS peer requirements in BOTH directions; private Team pin verified.');
    console.log('MCP_WORKSPACE_ROOT='+JSON.stringify(workspace));
    console.log('NOTE: This local Apple Development prototype is not notarized, independently protected from same-user compromise, or approved for external distribution.');
  }finally{
    rmSync(stage,{recursive:true,force:true});
    if(backup)console.error('NOTE: Previous native app preserved at a private backup path; reconcile manually.');
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(e=>{console.error('REQUIRED MAC NATIVE MCP NOT ACCEPTED: '+e.message);
    process.exitCode=1;});
