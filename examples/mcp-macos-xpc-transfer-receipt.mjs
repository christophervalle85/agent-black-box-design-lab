/**
 * Phase 6 — actual synthetic-only Node -> native host -> sandboxed XPC worker.
 * This is a CONTENT/DIGEST/REPLAY transport diagnostic, NOT a permission
 * authority. Ad-hoc identities do not establish production XPC peer trust.
 * No user files, no NSOpenPanel, no MCP calls, no worker filesystem writes.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos','xpc');
const accepted=Object.freeze({
  valid:'BBX_XPC_RECEIPT_VALID_ACCEPTED\n',
  replay:'BBX_XPC_RECEIPT_REPLAY_BLOCKED\n',
  tamper:'BBX_XPC_RECEIPT_TAMPER_BLOCKED\n'
});

export function assessSyntheticXpcReceipt(mode,result){
  if(!Object.hasOwn(accepted,mode))
    throw Error('Unsupported synthetic XPC receipt mode.');
  if(!result || result.error || result.signal || result.status!==0 ||
     result.stderr!=='' || result.stdout!==accepted[mode])
    throw Error('Native sandboxed XPC receipt result was not accepted.');
  return true;
}
function run(tool,args,label,timeout=90000){
  const r=spawnSync(tool,args,{encoding:'utf8',timeout,maxBuffer:8192,
    env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}});
  if(r.error || r.signal || r.status!==0)
    throw Error(label+' failed: '+String(
      r.error?.message??r.stderr?.trim()??r.stdout?.trim()??r.signal).slice(0,240));
  return r;
}
async function main(){
  if(process.platform!=='darwin')
    throw Error('Real macOS and XPC required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Ad-hoc synthetic XPC acceptance requires MCP_SANDBOX=off.');
  const mode=process.argv[2];
  if(process.argv.length!==3 || !Object.hasOwn(accepted,mode))
    throw Error('Expected exactly one mode: valid, tamper or replay.');
  const temp=mkdtempSync(join(tmpdir(),'bb-native-xpc-receipt-'));
  try{
    const app=join(temp,'BlackBoxTransferReceiptHost.app');
    const host=join(app,'Contents','MacOS','BlackBoxTransferReceiptHost');
    const service=join(app,'Contents','XPCServices','BlackBoxTransferReceiptWorker.xpc');
    const worker=join(service,'Contents','MacOS','BlackBoxTransferReceiptWorker');
    mkdirSync(dirname(host),{recursive:true});
    mkdirSync(dirname(worker),{recursive:true});
    copyFileSync(join(native,'TransferReceiptHost-Info.plist'),
      join(app,'Contents','Info.plist'));
    copyFileSync(join(native,'TransferReceiptService-Info.plist'),
      join(service,'Contents','Info.plist'));
    const flags=['-fblocks','-std=c11','-O2','-Wall','-Wextra',
      '-Werror=implicit-function-declaration'];
    run('/usr/bin/xcrun',['clang',...flags,'-o',host,
      join(native,'TransferReceiptHost.c')],'Synthetic XPC host build');
    run('/usr/bin/xcrun',['clang',...flags,'-o',worker,
      join(native,'TransferReceiptService.m'),'-framework','Foundation'],
      'Synthetic XPC worker build');
    run('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-snapshot-receipt.worker',
      '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
      service],'Synthetic worker ad-hoc signing');
    run('/usr/bin/codesign',['--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.xpc-snapshot-receipt.host',
      app],'Synthetic host ad-hoc signing');
    run('/usr/bin/codesign',['--verify','--strict','--deep',app],
      'Nested XPC app signature verification');
    run('/usr/bin/codesign',['--verify','--strict',service],
      'Nested XPC worker signature verification');
    const entitlements=run('/usr/bin/codesign',[
      '--display','--entitlements','-','--xml',service
    ],'Worker sandbox entitlement inspection');
    const info=entitlements.stdout+entitlements.stderr;
    if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(info) ||
       /<key>com\.apple\.security\.network\.(client|server)<\/key>\s*<true\s*\/>/.test(info))
      throw Error('No verified sandbox entitlement or unexpected network permission.');
    console.log('PASS: Disposable native XPC host and sandboxed worker built, signed and verified.');
    console.log('ACTION: Executing synthetic-only '+mode+' XPC receipt check; no file picker or user documents.');
    const outcome=spawnSync(host,[mode],{
      encoding:'utf8',timeout:15000,maxBuffer:1024,
      env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
    });
    assessSyntheticXpcReceipt(mode,outcome);
    if(mode==='valid')
      console.log('PASS: Sandboxed XPC worker accepted a bounded matching synthetic payload digest.');
    else if(mode==='tamper')
      console.log('PASS: Sandboxed XPC worker denied altered bytes and still accepted the subsequently correct bytes for that nonce.');
    else
      console.log('PASS: Sandboxed XPC worker rejected a repeated nonce in the same worker process.');
    console.log('NOTE: No files transferred; ad-hoc XPC peers are not production-authenticated.');
  }finally{
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{
    console.error('NATIVE XPC RECEIPT NOT ACCEPTED: '+error.message);
    process.exitCode=1;
  });
