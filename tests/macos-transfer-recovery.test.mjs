import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {AuditStore} from '../src/audit.mjs';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';
import {createAuditedMacTransferController} from '../src/macos-transfer-controller.mjs';
import {
  inspectMacSyntheticDispatchRecovery,classifyMacSyntheticUncertainReceipt
} from '../src/macos-transfer-recovery.mjs';

const NOW=1_790_000_000_000;
const BYTES=Buffer.from('BBX recovery synthetic bytes.\n');
async function fixture(transport,execute){
  const dir=mkdtempSync(join(tmpdir(),'bbx-review-recovery-'));
  const path=join(dir,'audit.jsonl');
  try{
    const store=new AuditStore(path,{externalReceiptFile:null});
    const controller=createAuditedMacTransferController({
      store,clock:()=>NOW,syntheticTransport:transport
    });
    const intent=createMacTransferIntent({
      operation:'import',noteName:'bbx-test-recovery.txt',
      bytes:BYTES,now:NOW
    });
    const review=controller.host.request(intent);
    assert.equal(controller.controller.decide(review.reviewId,'approve'),true);
    await execute({
      store,controller,review,intent,path,
      request:()=>({reviewId:review.reviewId,intent,bytes:BYTES}),
      restart:()=>new AuditStore(path,{externalReceiptFile:null})
    });
  }finally{rmSync(dir,{recursive:true,force:true});}
}
const entry=(store,id)=>{
  const report=inspectMacSyntheticDispatchRecovery(store);
  assert.equal(report.inspectedRecords,store.verify().records);
  const result=report.dispatches.find(x=>x.reviewId===id);
  assert.ok(result);
  assert.equal(result.canRetry,false);
  return {report,result};
};
test('HMAC audit restart never turns synthetic callback success into OS proof',()=>
  fixture(()=> 'SYNTHETIC_ACCEPTED',async ctx=>{
    assert.equal(await ctx.controller.host.dispatchSynthetic(ctx.request()),true);
    const {report,result}=entry(ctx.restart(),ctx.review.reviewId);
    assert.equal(result.status,'simulated-only');
    assert.equal(report.hasUncertainDispatch,false);
    assert.match(result.description,/no native success/i);
    // Starting a new controller does not reconstruct an approved grant.
    const restored=createAuditedMacTransferController({
      store:ctx.restart(),clock:()=>NOW,
      syntheticTransport:()=>{throw Error('MUST NOT REPLAY');}
    });
    await assert.rejects(restored.host.dispatchSynthetic(ctx.request()),/No unconsumed/);
  })
);
test('unknown transport after durable reservation is still uncertain after restart',()=>
  fixture(()=>{throw Error('native host crashed after possible commit');},
    async ctx=>{
      await assert.rejects(ctx.controller.host.dispatchSynthetic(ctx.request()),
        /uncertain/);
      const {report,result}=entry(ctx.restart(),ctx.review.reviewId);
      assert.equal(report.hasUncertainDispatch,true);
      assert.equal(result.status,'unknown');
    })
);
test('crash before terminal audit is UNKNOWN rather than a recoverable approval',()=>
  fixture(()=> 'SYNTHETIC_ACCEPTED',async ctx=>{
    const original=ctx.store.add.bind(ctx.store);
    ctx.store.add=event=>{
      if(event.ruleId==='MAC_TRANSFER_DISPATCH_SIMULATED')
        throw Error('simulated lost terminal fsync');
      return original(event);
    };
    await assert.rejects(ctx.controller.host.dispatchSynthetic(ctx.request()),
      /lost terminal fsync/);
    const recovered=ctx.restart();
    const {result,report}=entry(recovered,ctx.review.reviewId);
    assert.equal(result.status,'unknown');
    assert.equal(report.hasUncertainDispatch,true);
  })
);
test('explicit negative transport remains DENIED across restart',()=>
  fixture(()=> 'SYNTHETIC_DENIED',async ctx=>{
    await assert.rejects(ctx.controller.host.dispatchSynthetic(ctx.request()),
      /dispatch denied/);
    assert.equal(entry(ctx.restart(),ctx.review.reviewId).result.status,'denied');
  })
);
test('invalid bytes burn approval before any reservation and cannot become committed',()=>
  fixture(()=>{throw Error('transport must not run');},async ctx=>{
    const modified=Buffer.from(BYTES);modified[0]^=1;
    await assert.rejects(ctx.controller.host.dispatchSynthetic({
      ...ctx.request(),bytes:modified
    }),/validation denied/);
    const {result}=entry(ctx.restart(),ctx.review.reviewId);
    assert.equal(result.status,'validation-denied');
  })
);
test('failed reservation audit is classified as pre-dispatch and never retryable',()=>
  fixture(()=>{throw Error('transport must not run');},async ctx=>{
    const original=ctx.store.add.bind(ctx.store);
    ctx.store.add=event=>{
      if(event.ruleId==='MAC_TRANSFER_DISPATCH_RESERVED')
        throw Error('cannot journal reservation');
      return original(event);
    };
    await assert.rejects(ctx.controller.host.dispatchSynthetic(ctx.request()),
      /reservation audit failed/);
    assert.equal(entry(ctx.restart(),ctx.review.reviewId).result.status,
      'pre-dispatch');
  })
);
test('audit tampering fails closed before lifecycle classification',()=>
  fixture(()=> 'SYNTHETIC_ACCEPTED',async ctx=>{
    await ctx.controller.host.dispatchSynthetic(ctx.request());
    const text=readFileSync(ctx.path,'utf8');
    writeFileSync(ctx.path,text.replace(
      'MAC_TRANSFER_DISPATCH_SIMULATED','MAC_TRANSFER_DISPATCH_FORGED'));
    const report=()=>inspectMacSyntheticDispatchRecovery(ctx.store);
    assert.throws(report,/integrity failure/i);
    assert.throws(ctx.restart,/integrity failure/i);
  })
);
test('authenticated duplicate or contradictory outcomes are treated as corruption',()=>
  fixture(()=> 'SYNTHETIC_ACCEPTED',async ctx=>{
    await ctx.controller.host.dispatchSynthetic(ctx.request());
    const event=ctx.store.list({limit:1})[0];
    // Even if a privileged writer with the audit key appended a contradictory
    // event, the lifecycle inspector refuses to infer success from it.
    ctx.store.add({...event,id:'11111111-1111-4111-8111-111111111111',
      ruleId:'MAC_TRANSFER_DISPATCH_DENIED'});
    assert.throws(()=>inspectMacSyntheticDispatchRecovery(ctx.restart()),
      /RECOVERY REQUIRED/);
  })
);
test('truncated audit inspection windows are denied, not silently accepted',()=>{
  const store={
    verify:()=>({ok:true,records:1001}),
    list:()=>{throw Error('must not use partial audit history');}
  };
  assert.throws(()=>inspectMacSyntheticDispatchRecovery(store),
    /RECOVERY REQUIRED/);
});

test('native receipt observations never turn HMAC-uncertain reservations into success or retry',()=>fixture(
  ()=>{throw Error('synthetic transport lost native ACK');},
  async ctx=>{
    await assert.rejects(ctx.controller.host.dispatchSynthetic(ctx.request()),
      /uncertain/);
    const report=inspectMacSyntheticDispatchRecovery(ctx.restart());
    for(const observation of ['matching-marker','no-marker','unverifiable']){
      const verdict=classifyMacSyntheticUncertainReceipt(report,{
        reviewId:ctx.review.reviewId,observation
      });
      assert.equal(verdict.status,'unknown');
      assert.equal(verdict.observation,observation);
      assert.equal(verdict.canRetry,false);
      assert.equal(verdict.canClaimSuccess,false);
      assert.equal(Object.isFrozen(verdict),true);
    }
    const missing='123e4567-e89b-42d3-a456-426614174001';
    for(const invalid of [
      {reviewId:missing,observation:'matching-marker'},
      {reviewId:ctx.review.reviewId,observation:'committed'},
      {reviewId:ctx.review.reviewId,observation:true},
      {reviewId:'not-a-review',observation:'no-marker'},
      {reviewId:ctx.review.reviewId,observation:null}
    ])assert.throws(()=>classifyMacSyntheticUncertainReceipt(report,invalid));
    assert.equal(ctx.restart().list({limit:1})[0].ruleId,
      'MAC_TRANSFER_DISPATCH_UNCERTAIN');
  }
));
test('terminal simulated result cannot be reinterpreted as uncertain native evidence',()=>fixture(
  ()=> 'SYNTHETIC_ACCEPTED',async ctx=>{
    assert.equal(await ctx.controller.host.dispatchSynthetic(ctx.request()),true);
    const report=inspectMacSyntheticDispatchRecovery(ctx.restart());
    assert.throws(()=>classifyMacSyntheticUncertainReceipt(report,{
      reviewId:ctx.review.reviewId,observation:'matching-marker'
    }),/no unique uncertain reserved review/);
  }
));
