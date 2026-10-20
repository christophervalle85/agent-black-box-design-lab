/**
 * On-device synthetic Phase 5 review-binding acceptance.
 * Real Touch ID, immutable review metadata, one-use HMAC audit:
 * NO native file I/O, picker, MCP tool or production auth.
 */
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir,homedir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {AuditStore} from '../src/audit.mjs';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';
import {createAuditedMacTransferController} from '../src/macos-transfer-controller.mjs';
import {evaluateNativeMacTransferTouchId} from '../src/macos-native-transfer-verifier.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const nativeSource=join(root,'native','macos','TransferReviewAuthenticator.m');
function command(exe,args,label){
  const result=spawnSync(exe,args,{
    encoding:'utf8',timeout:30000,maxBuffer:8192,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
  });
  if(result.error||result.signal||result.status!==0)
    throw Error(label+' failed: '+
      String(result.error?.message??result.stderr??result.signal).slice(0,280));
}
async function main(){
  if(process.platform!=='darwin')throw Error('A real interactive Mac is required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Ad-hoc experiment requires explicit MCP_SANDBOX=off.');
  const mode=process.argv[2];
  if(process.argv.length!==3 || !['approve','cancel'].includes(mode))
    throw Error('Expected one mode: approve or cancel.');
  const temp=mkdtempSync(join(tmpdir(),'bb-transfer-touchid-'));
  let gate;
  try{
    const exe=join(temp,'BlackBoxSyntheticTransferTouchId');
    command('/usr/bin/xcrun',[
      'clang','-fobjc-arc','-fblocks','-std=c11',
      '-Wall','-Wextra','-O2','-o',exe,nativeSource,
      '-framework','Foundation','-framework','LocalAuthentication'
    ],'Native Touch ID verifier build');
    command('/usr/bin/codesign',[
      '--force','--sign','-','--options','runtime',
      '--identifier','dev.agentblackbox.transfer-review-touchid-fixture',exe
    ],'Ad-hoc verifier signing');
    command('/usr/bin/codesign',['--verify','--strict',exe],
      'Synthetic verifier code signature');
    console.log('PASS: Review-binding native verifier built and ad-hoc signature checked.');
    const store=new AuditStore(join(temp,'audit.jsonl'),{externalReceiptFile:null});
    gate=createAuditedMacTransferController({store});
    const bytes=Buffer.from('Synthetic review, no documents are accessed.\n','utf8');
    const intent=createMacTransferIntent({
      operation:'import',noteName:'bbx-test-review-auth.txt',bytes
    });
    const review=gate.host.request(intent);
    const context=Object.freeze({
      reviewId:review.reviewId,intent:review.intent,decision:'approve'
    });
    console.log('PASS: Fresh path-free exact-byte transfer intent reviewed and HMAC audited.');
    if(mode==='approve')
      console.log('ACTION: Touch your enrolled Touch ID finger when the macOS review prompt appears.');
    else
      console.log('ACTION: Click Cancel WITHOUT touching Touch ID. No approval is allowed.');
    const outcome=await evaluateNativeMacTransferTouchId(context,{
      executable:exe,timeoutMs:30000
    });
    if(mode==='approve'){
      if(outcome!=='authenticated')
        throw Error('Native biometric authentication was not accepted.');
      console.log('PASS: OS Touch ID authenticated the specific review ID, nonce and digest.');
      if(!gate.controller.decide(review.reviewId,'approve'))
        throw Error('Verified review could not be approved.');
      if(gate.host.consume({reviewId:review.reviewId,intent,bytes})!==true)
        throw Error('One-time verified review could not be consumed.');
      console.log('PASS: Exact immutable synthetic review approved and consumed once.');
    }else{
      if(outcome!=='cancelled')
        throw Error('Cancellation mode received unexpected successful OS authentication.');
      if(!gate.controller.decide(review.reviewId,'deny'))
        throw Error('Cancelled review could not be denied.');
      let blocked=false;
      try{gate.host.consume({reviewId:review.reviewId,intent,bytes});}
      catch{blocked=true;}
      if(!blocked)throw Error('Cancelled review was unexpectedly consumable.');
      console.log('PASS: Real OS Touch ID user cancellation denied the review.');
      console.log('PASS: Cancelled synthetic review cannot be consumed.');
    }
    const events=store.list({limit:20});
    if(!store.verify().ok ||
       events.some(e=>e.ruleId==='MAC_TRANSFER_CONSUMED') !== (mode==='approve') ||
       events.some(e=>e.ruleId==='MAC_TRANSFER_APPROVED') !== (mode==='approve') ||
       events.some(e=>e.ruleId==='MAC_TRANSFER_DENIED') !== (mode==='cancel'))
      throw Error('HMAC-audited one-use review outcome did not match OS outcome.');
    console.log('PASS: HMAC audit and approval outcome are consistent; no OS file transfer.');
    console.log('NOTE: Ad-hoc test-only signing; user-prompt consent and production trust gates remain.');
  }finally{
    gate?.controller.close();
    rmSync(temp,{recursive:true,force:true});
  }
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{console.error('TOUCH ID TRANSFER REVIEW NOT ACCEPTED: '+error.message);
    process.exitCode=1;});
