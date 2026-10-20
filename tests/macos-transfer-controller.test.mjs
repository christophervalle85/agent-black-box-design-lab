import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {once} from 'node:events';
import {createBlackBoxServer} from '../src/server.mjs';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';

const payload=()=>Buffer.from('synthetic-only\n','utf8');
function createIntent(operation='import'){
  return createMacTransferIntent({
    operation,noteName:'bbx-test-controller.txt',bytes:payload()
  });
}
async function fixture(options,fn){
  const dir=mkdtempSync(join(tmpdir(),'bb-transfer-controller-'));
  const workspaceRoot=join(dir,'workspace');
  mkdirSync(workspaceRoot);
  const app=createBlackBoxServer({
    dataFile:join(dir,'audit.jsonl'),workspaceRoot,
    agentClient:{model:'mock',status:async()=>({ready:false})},
    ...options
  });
  app.server.listen(0,'127.0.0.1');
  await once(app.server,'listening');
  const base='http://127.0.0.1:'+app.server.address().port;
  try{await fn({...app,base,dir});}
  finally{
    await new Promise(resolve=>app.server.close(resolve));
    rmSync(dir,{recursive:true,force:true});
  }
}
async function decide(base,id,decision,options={}){
  return fetch(base+'/api/mac/transfers/'+id+'/decision',{
    method:'POST',
    headers:{'content-type':'application/json',...(options.headers??{})},
    body:options.body??JSON.stringify({decision})
  });
}
test('new transfer controller endpoints remain disabled in the ordinary server',()=>fixture({},async ctx=>{
  assert.equal(ctx.macTransferHost,null);
  assert.equal((await fetch(ctx.base+'/api/mac/transfers/pending')).status,404);
  assert.equal((await decide(ctx.base,'12345678-1234-4abc-8abc-123456789abc','approve',
    {headers:{Origin:ctx.base}})).status,404);
}));
test('only in-process host can create; same-origin local decision is required; HMAC records omit bytes',()=>fixture(
  {experimentalMacTransferReviews:true, experimentalMacTransferOperatorVerify: async ()=>true},async ctx=>{
    const {macTransferHost:host,base,store}=ctx;
    assert.ok(host);
    const intent=createIntent();
    const review=host.request(intent);
    assert.ok(review.reviewId);
    assert.deepEqual((await (await fetch(base+'/api/mac/transfers/pending')).json()).pending,[review]);
    assert.equal((await fetch(base+'/api/mac/transfers',{method:'POST',
      headers:{Origin:base,'content-type':'application/json'},
      body:JSON.stringify(intent)})).status,404);
    assert.equal((await decide(base,review.reviewId,'approve')).status,403);
    assert.equal((await decide(base,review.reviewId,'approve',
      {headers:{Origin:'http://evil.example'}})).status,403);
    assert.equal((await decide(base,review.reviewId,'approve',
      {headers:{Origin:base},body:JSON.stringify({decision:'approve',approved:true})})).status,400);
    assert.equal((await decide(base,review.reviewId,'approve',
      {headers:{Origin:base}})).status,200);
    assert.equal((await decide(base,review.reviewId,'approve',
      {headers:{Origin:base}})).status,409);
    assert.equal(host.consume({reviewId:review.reviewId,intent,bytes:payload()}),true);
    assert.throws(()=>host.consume({reviewId:review.reviewId,intent,bytes:payload()}));
    assert.throws(()=>host.request(intent),/already been reviewed/);
    assert.deepEqual((await (await fetch(base+'/api/mac/transfers/pending')).json()).pending,[]);
    assert.equal(store.verify().ok,true);
    const records=store.list({limit:20}).reverse();
    assert.deepEqual(records.map(x=>x.ruleId),[
      'MAC_TRANSFER_REVIEW','MAC_TRANSFER_DECISION_REQUEST',
      'MAC_TRANSFER_APPROVED','MAC_TRANSFER_CONSUMPTION_ATTEMPT',
      'MAC_TRANSFER_CONSUMED'
    ]);
    assert.equal(records.at(-1).outcome,'simulated');
    assert.equal(records.every(x=>x.approvalId===review.reviewId),true);
    assert.doesNotMatch(readFileSync(store.filename,'utf8'),/synthetic-only|content digest|sha256|sourcePath|bearer/i);
  }
));
test('denial, cancel and expiry deny synthetic request without creating OS files',()=>fixture(
  {experimentalMacTransferReviews:true, experimentalMacTransferOperatorVerify: async ()=>true},async ctx=>{
    const {macTransferHost:host,base,store,dir}=ctx;
    const denied=createIntent('export');
    const review=host.request(denied);
    assert.equal((await decide(base,review.reviewId,'deny',
      {headers:{Origin:base}})).status,200);
    assert.throws(()=>host.consume({reviewId:review.reviewId,intent:denied,bytes:payload()}));
    const cancelled=createIntent();
    const cancelledReview=host.request(cancelled);
    assert.equal(host.cancel(cancelledReview.reviewId),true);
    assert.equal((await decide(base,cancelledReview.reviewId,'approve',
      {headers:{Origin:base}})).status,409);
    assert.ok(store.list({limit:30}).some(e=>e.ruleId==='MAC_TRANSFER_DENIED'));
    assert.ok(store.list({limit:30}).some(e=>e.ruleId==='MAC_TRANSFER_CANCELLED'));
    assert.equal(readFileSync(join(dir,'audit.jsonl'),'utf8').includes('synthetic-only'),false);
  }
));
test('tampered HMAC audit blocks creation, decision and consumption',()=>fixture(
  {experimentalMacTransferReviews:true, experimentalMacTransferOperatorVerify: async ()=>true},async ctx=>{
    const {macTransferHost:host,base,store}=ctx;
    const first=createIntent(),r=host.request(first);
    const log=readFileSync(store.filename,'utf8');
    writeFileSync(store.filename,log.replace('MAC_TRANSFER_REVIEW','MAC_TRANSFER_TAMPERED'));
    assert.throws(()=>host.request(createIntent()),/integrity failure/i);
    assert.equal((await decide(base,r.reviewId,'approve',
      {headers:{Origin:base}})).status,503);
    assert.throws(()=>host.consume({reviewId:r.reviewId,intent:first,bytes:payload()}),
      /integrity failure/i);
    assert.equal((await fetch(base+'/api/mac/transfers/pending')).status,503);
  }
));
test('changed payload burns approval before another attempt; no transfer is performed',()=>fixture(
  {experimentalMacTransferReviews:true, experimentalMacTransferOperatorVerify: async ()=>true},async ctx=>{
    const {macTransferHost:host,base}=ctx;
    const intent=createIntent('export'),review=host.request(intent);
    assert.equal((await decide(base,review.reviewId,'approve',
      {headers:{Origin:base}})).status,200);
    const changed=payload();changed[0]^=1;
    assert.throws(()=>host.consume({
      reviewId:review.reviewId,intent,bytes:changed
    }),/digest/);
    assert.throws(()=>host.consume({reviewId:review.reviewId,intent,bytes:payload()}),
      /No unconsumed/);
    const events=ctx.store.list({limit:20});
    assert.equal(events.some(e=>e.ruleId==='MAC_TRANSFER_CONSUMPTION_DENIED' &&
      e.decision==='block' && e.outcome==='blocked'),true);
    assert.equal(events.some(e=>e.ruleId==='MAC_TRANSFER_CONSUMED'),false);
  }
));


test('enabling experimental transfer reviews alone cannot approve a synthetic transfer',()=>fixture(
  {experimentalMacTransferReviews:true},async ctx=>{
    const review=ctx.macTransferHost.request(createIntent());
    const response=await decide(ctx.base,review.reviewId,'approve',
      {headers:{Origin:ctx.base}});
    assert.equal(response.status,403);
    assert.equal(ctx.macTransferHost.consume instanceof Function,true);
    assert.throws(()=>ctx.macTransferHost.consume({
      reviewId:review.reviewId,intent:review.intent,bytes:payload()
    }),/did not approve/);
    assert.equal(ctx.store.list({limit:10})
      .some(e=>e.ruleId==='MAC_TRANSFER_APPROVED'),false);
  }
));
test('trusted verifier must be explicitly injected, never inferred from a local Origin',()=>{
  assert.throws(()=>createBlackBoxServer({
    experimentalMacTransferOperatorVerify:async()=>true
  }),/requires explicit experimental mode/);
  assert.throws(()=>createBlackBoxServer({
    experimentalMacTransferReviews:true,
    experimentalMacTransferOperatorVerify:true
  }),/trusted function/);
  return fixture({
    experimentalMacTransferReviews:true,
    experimentalMacTransferOperatorVerify: async()=>false
  },async ctx=>{
    const intent=createIntent(),review=ctx.macTransferHost.request(intent);
    assert.equal((await decide(ctx.base,review.reviewId,'approve',
      {headers:{Origin:ctx.base}})).status,403);
    assert.equal(ctx.store.list({limit:10})
      .some(e=>e.ruleId==='MAC_TRANSFER_APPROVED'),false);
    assert.throws(()=>ctx.macTransferHost.consume({
      reviewId:review.reviewId,intent,bytes:payload()
    }),/did not approve/);
  });
});
test('the trusted verifier sees the exact immutable reviewed operation and never bytes or host paths',()=>fixture({
  experimentalMacTransferReviews:true,
  experimentalMacTransferOperatorVerify: async context=>{
    assert.equal(Object.isFrozen(context),true);
    assert.equal(Object.isFrozen(context.intent),true);
    assert.equal(context.intent.operation,'export');
    assert.equal(context.intent.noteName,'bbx-test-controller.txt');
    assert.equal(context.decision,'approve');
    assert.equal(JSON.stringify(context).includes('synthetic-only'),false);
    assert.equal(Object.hasOwn(context,'bytes'),false);
    assert.equal(Object.hasOwn(context,'path'),false);
    return true;
  }
},async ctx=>{
  const intent=createIntent('export'),review=ctx.macTransferHost.request(intent);
  assert.equal((await decide(ctx.base,review.reviewId,'approve',
    {headers:{Origin:ctx.base}})).status,200);
  assert.equal(ctx.macTransferHost.consume({
    reviewId:review.reviewId,intent,bytes:payload()
  }),true);
}));
test('only one verification can be in flight and late approval cannot revive cancellation',async()=>{
  let release,entered;
  const enteredPromise=new Promise(resolve=>{entered=resolve;});
  await fixture({
    experimentalMacTransferReviews:true,
    experimentalMacTransferOperatorVerify: async()=>{
      entered();
      return new Promise(resolve=>{release=resolve;});
    }
  },async ctx=>{
    const intent=createIntent(),review=ctx.macTransferHost.request(intent);
    const first=decide(ctx.base,review.reviewId,'approve',
      {headers:{Origin:ctx.base}});
    await enteredPromise;
    assert.equal((await decide(ctx.base,review.reviewId,'approve',
      {headers:{Origin:ctx.base}})).status,409);
    assert.equal(ctx.macTransferHost.cancel(review.reviewId),true);
    release(true);
    assert.equal((await first).status,409);
    assert.equal(ctx.store.list({limit:20})
      .some(e=>e.ruleId==='MAC_TRANSFER_APPROVED'),false);
  });
});
