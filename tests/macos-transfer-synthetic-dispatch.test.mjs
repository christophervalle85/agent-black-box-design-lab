import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {AuditStore} from '../src/audit.mjs';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';
import {createAuditedMacTransferController} from '../src/macos-transfer-controller.mjs';
import {assertCanonicalMacReviewedTransaction} from '../src/macos-reviewed-transaction.mjs';

const NOW=1_790_000_000_000;
const bytes=()=>Buffer.from('BBX audited synthetic dispatch bytes.\n');
async function fixture({transport=null,timeout=5000,overrideStore=null}={},fn){
  const dir=mkdtempSync(join(tmpdir(),'bbx-synthetic-dispatch-'));
  try{
    const real=new AuditStore(join(dir,'events.jsonl'),{externalReceiptFile:null});
    const store=overrideStore?overrideStore(real):real;
    const controller=createAuditedMacTransferController({
      store,clock:()=>NOW,syntheticTransport:transport,
      syntheticTimeoutMs:timeout
    });
    const intent=createMacTransferIntent({
      operation:'import',noteName:'bbx-test-dispatch.txt',
      bytes:bytes(),now:NOW
    });
    const review=controller.host.request(intent);
    assert.equal(controller.controller.decide(review.reviewId,'approve'),true);
    await fn({dir,real,store,controller,intent,review});
  }finally{
    rmSync(dir,{recursive:true,force:true});
  }
}
const request=({review,intent,payload=bytes()})=>({
  reviewId:review.reviewId,intent,bytes:payload
});
const ids=store=>store.list({limit:50}).reverse().map(e=>e.ruleId);
test('ordinary audited controller has NO synthetic dispatch capability',()=>{
  const dir=mkdtempSync(join(tmpdir(),'bbx-synthetic-disabled-'));
  try{
    const store=new AuditStore(join(dir,'events.jsonl'),{externalReceiptFile:null});
    const pair=createAuditedMacTransferController({store,clock:()=>NOW});
    assert.equal(Object.hasOwn(pair.host,'dispatchSynthetic'),false);
    assert.equal(Object.hasOwn(pair.controller,'dispatchSynthetic'),false);
    for(const bad of [false,true,{},'fake',Promise.resolve(true)]){
      assert.throws(()=>createAuditedMacTransferController({
        store,clock:()=>NOW,syntheticTransport:bad
      }),/Invalid opt-in/);
    }
    assert.throws(()=>createAuditedMacTransferController({
      store,syntheticTransport:()=>{},syntheticTimeoutMs:0
    }),/Invalid opt-in/);
  }finally{rmSync(dir,{recursive:true,force:true});}
});
test('HMAC durable reserve, one-use synthetic callback, verified final receipt',()=>fixture({
  transport:context=>{
    assert.equal(Object.isFrozen(context),true);
    assert.equal(Object.isFrozen(context.intent),true);
    assert.equal(context.bytes.equals(bytes()),true);
    assert.equal(context.reviewId.length,36);
    assert.equal(Object.isFrozen(context.transaction),true);
    assert.equal(context.transaction.reviewId,context.reviewId);
    assert.equal(context.transaction.nonce,context.intent.nonce);
    assert.equal(context.transaction.sha256,context.intent.sha256);
    assert.equal(context.transaction.noteName,context.intent.noteName);
    assert.deepEqual(assertCanonicalMacReviewedTransaction(
      context.transaction,{now:NOW}),context.transaction);
    return 'SYNTHETIC_ACCEPTED';
  }
},async({real,controller,review,intent})=>{
  assert.equal(await controller.host.dispatchSynthetic(request({review,intent})),true);
  assert.deepEqual(ids(real),[
    'MAC_TRANSFER_REVIEW','MAC_TRANSFER_DECISION_REQUEST',
    'MAC_TRANSFER_APPROVED','MAC_TRANSFER_DISPATCH_ATTEMPT',
    'MAC_TRANSFER_DISPATCH_RESERVED','MAC_TRANSFER_DISPATCH_SIMULATED'
  ]);
  assert.equal(real.verify().ok,true);
  const events=real.list({limit:50});
  assert.equal(events.every(e=>e.approvalId===review.reviewId),true);
  assert.equal(events[0].outcome,'simulated');
  assert.equal(events[0].decision,'allow');
  assert.doesNotMatch(readFileSync(real.filename,'utf8'),
    /BBX audited synthetic dispatch bytes|sha256|nonce|bearer|sourcePath/);
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /No unconsumed/);
  assert.throws(()=>controller.host.request(intent),/already been reviewed/);
}));
test('modified bytes and changed metadata burn approved review before transport',()=>fixture({
  transport:()=>{throw Error('Transport must never run');}
},async({real,controller,review,intent})=>{
  const modified=bytes();modified[0]^=1;
  await assert.rejects(controller.host.dispatchSynthetic(
    request({review,intent,payload:modified})),/validation denied/);
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /No unconsumed/);
  assert.deepEqual(ids(real).slice(-2),[
    'MAC_TRANSFER_DISPATCH_ATTEMPT','MAC_TRANSFER_DISPATCH_VALIDATION_DENIED'
  ]);
}));
test('changed reviewed metadata burns once and cannot retry',()=>fixture({
  transport:()=>{throw Error('Must not dispatch');}
},async({real,controller,review,intent})=>{
  await assert.rejects(controller.host.dispatchSynthetic(
    request({review,intent:{...intent,noteName:'bbx-test-forged.txt'}})),
    /validation denied/);
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /No unconsumed/);
  assert.ok(ids(real).includes('MAC_TRANSFER_DISPATCH_VALIDATION_DENIED'));
}));
test('explicitly denied synthetic transport records blocked outcome without retry',()=>fixture({
  transport:()=> 'SYNTHETIC_DENIED'
},async({real,controller,review,intent})=>{
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /dispatch denied/);
  assert.equal(ids(real).at(-1),'MAC_TRANSFER_DISPATCH_DENIED');
  assert.equal(real.list({limit:1})[0].outcome,'blocked');
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /No unconsumed/);
}));
for(const [label,transport,timeout] of [
  ['throwing callback',()=>{throw Error('untrusted /Users/path secret');},500],
  ['malformed callback',()=>({status:'accepted',signed:true}),500],
  ['silent undefined',()=>undefined,500],
  ['stalled callback',()=>new Promise(()=>{}),15]
]){
  test(label+' is audited UNCERTAIN and permanently burns review',()=>fixture({
    transport,timeout
  },async({real,controller,review,intent})=>{
    await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
      /uncertain/);
    assert.equal(ids(real).at(-1),'MAC_TRANSFER_DISPATCH_UNCERTAIN');
    assert.equal(real.verify().ok,true);
    assert.doesNotMatch(readFileSync(real.filename,'utf8'),
      /untrusted|Users|secret|accepted":true/);
    await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
      /No unconsumed/);
  }));
}
test('audit reservation failure occurs AFTER burn but BEFORE synthetic callback',()=>fixture({
  transport:()=>{throw Error('callback must not run');},
  overrideStore:real=>({
    verify:()=>real.verify(),
    add:event=>{
      if(event.ruleId==='MAC_TRANSFER_DISPATCH_RESERVED')
        throw Error('simulated reservation fsync failure');
      return real.add(event);
    }
  })
},async({controller,review,intent,real})=>{
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /reservation audit failed/);
  assert.equal(ids(real).at(-1),'MAC_TRANSFER_DISPATCH_ATTEMPT');
  assert.equal(ids(real).includes('MAC_TRANSFER_DISPATCH_SIMULATED'),false);
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /No unconsumed/);
}));
test('integrity tampering prevents callback, including before review burn',()=>fixture({
  transport:()=>{throw Error('Callback must not execute');}
},async({controller,review,intent,real})=>{
  const original=readFileSync(real.filename,'utf8');
  writeFileSync(real.filename,original.replace('MAC_TRANSFER_APPROVED',
    'MAC_TRANSFER_FABRICATED'));
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /integrity failure/i);
}));
test('terminal audit failure cannot be mistaken for successful dispatch',()=>fixture({
  transport:()=> 'SYNTHETIC_ACCEPTED',
  overrideStore:real=>({
    verify:()=>real.verify(),
    add:event=>{
      if(event.ruleId==='MAC_TRANSFER_DISPATCH_SIMULATED')
        throw Error('simulated terminal fsync failure');
      return real.add(event);
    }
  })
},async({controller,review,intent,real})=>{
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /terminal fsync failure/);
  assert.equal(ids(real).at(-1),'MAC_TRANSFER_DISPATCH_RESERVED');
  await assert.rejects(controller.host.dispatchSynthetic(request({review,intent})),
    /No unconsumed/);
}));
test('concurrent synthetic attempts cannot dispatch twice',()=>fixture({
  transport:()=>new Promise(resolve=>setTimeout(()=>resolve('SYNTHETIC_ACCEPTED'),20))
},async({real,controller,review,intent})=>{
  const first=controller.host.dispatchSynthetic(request({review,intent}));
  const second=controller.host.dispatchSynthetic(request({review,intent}));
  await assert.rejects(second,/No unconsumed/);
  assert.equal(await first,true);
  assert.equal(ids(real).filter(id=>id==='MAC_TRANSFER_DISPATCH_RESERVED').length,1);
}));
