import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';
import {createMacTransferReviewPair} from '../src/macos-transfer-review.mjs';

const start=1_790_000_000_000;
const bytes=()=>Buffer.from('approved synthetic note\n');
function fixture(options={}) {
  let now=start;
  const pair=createMacTransferReviewPair({clock:()=>now,...options});
  const intent=(operation='import')=>createMacTransferIntent({
    operation,noteName:'bbx-test-reviewed.txt',bytes:bytes(),now
  });
  return {pair,intent,advance:ms=>{now+=ms;},get now(){return now;}};
}
test('Phase 5 preview cannot authorize: operator controller must separately approve once',()=>{
  const {pair,intent}=fixture();
  const issued=intent();
  const request=pair.host.request(issued);
  assert.equal('decide' in pair.host,false);
  assert.equal('consume' in pair.controller,false);
  assert.equal(JSON.stringify(request).includes('approved synthetic note'),false);
  assert.equal(Object.isFrozen(request),true);
  assert.equal(Object.isFrozen(request.intent),true);
  assert.deepEqual(pair.controller.pending(),[request]);
  assert.throws(()=>pair.host.consume({
    reviewId:request.reviewId,intent:issued,bytes:bytes()
  }),/did not approve/);
  assert.equal(pair.controller.decide(request.reviewId,'approve'),false);
});
test('approved import consumes exactly once; replay and duplicate intent never work',()=>{
  const {pair,intent}=fixture();
  const issued=intent();
  const request=pair.host.request(issued);
  assert.equal(pair.controller.decide(request.reviewId,'approve'),true);
  assert.equal(pair.controller.decide(request.reviewId,'approve'),false);
  assert.deepEqual(pair.controller.pending(),[]);
  assert.equal(pair.host.consume({
    reviewId:request.reviewId,intent:issued,bytes:bytes()
  }),true);
  assert.throws(()=>pair.host.consume({
    reviewId:request.reviewId,intent:issued,bytes:bytes()
  }),/No unconsumed/);
  assert.throws(()=>pair.host.request(issued),/already been reviewed/);
});
test('approved export still rejects changed operation, name, digest, nonce and bytes',()=>{
  for(const change of [
    {operation:'import'},{noteName:'bbx-test-other.txt'},
    {sha256:'f'.repeat(64)},{nonce:'12345678-1234-4abc-8abc-123456789abc'},
    {byteLength:1}
  ]) {
    const {pair,intent}=fixture();
    const issued=intent('export');
    const request=pair.host.request(issued);
    pair.controller.decide(request.reviewId,'approve');
    assert.throws(()=>pair.host.consume({
      reviewId:request.reviewId,intent:{...issued,...change},bytes:bytes()
    }));
    assert.throws(()=>pair.host.consume({
      reviewId:request.reviewId,intent:issued,bytes:bytes()
    }),/No unconsumed/);
  }
  const {pair,intent}=fixture();
  const issued=intent('export'),review=pair.host.request(issued);
  pair.controller.decide(review.reviewId,'approve');
  const modified=bytes();modified[0]=0x58;
  assert.throws(()=>pair.host.consume({reviewId:review.reviewId,intent:issued,
    bytes:modified}),/digest/);
  assert.throws(()=>pair.host.consume({reviewId:review.reviewId,intent:issued,
    bytes:bytes()}),/No unconsumed/);
});
test('deny, cancellation, expiry and shutdown are irrevocable',()=>{
  const f=fixture();
  const deny=f.pair.host.request(f.intent());
  assert.equal(f.pair.controller.decide(deny.reviewId,'deny'),true);
  assert.equal(f.pair.controller.decide(deny.reviewId,'approve'),false);
  const cancelled=f.pair.host.request(f.intent());
  assert.equal(f.pair.controller.decide(cancelled.reviewId,'approve'),true);
  assert.equal(f.pair.host.cancel(cancelled.reviewId),true);
  assert.throws(()=>f.pair.host.consume({
    reviewId:cancelled.reviewId,intent:cancelled.intent,bytes:bytes()
  }),/No unconsumed/);
  const expired=f.pair.host.request(f.intent());
  f.advance(60_000);
  assert.equal(f.pair.controller.decide(expired.reviewId,'approve'),false);
  assert.throws(()=>f.pair.host.consume({
    reviewId:expired.reviewId,intent:expired.intent,bytes:bytes()
  }),/No unconsumed|expired/);
  const open=f.pair.host.request(f.intent());
  f.pair.controller.close();
  assert.deepEqual(f.pair.controller.pending(),[]);
  assert.throws(()=>f.pair.host.consume({
    reviewId:open.reviewId,intent:open.intent,bytes:bytes()
  }),/Invalid/);
  assert.throws(()=>f.pair.host.request(f.intent()),/closed/);
});
test('review capacity and unapproved decision attempts fail closed',()=>{
  const f=fixture({maxRequests:2});
  const first=f.pair.host.request(f.intent());
  assert.equal(f.pair.controller.decide('not-an-id','approve'),false);
  assert.equal(f.pair.controller.decide(first.reviewId,'anything'),false);
  assert.equal(f.pair.controller.decide(first.reviewId,'approve'),true);
  assert.equal(f.pair.controller.decide(first.reviewId,'deny'),false);
  const second=f.pair.host.request(f.intent());
  assert.throws(()=>f.pair.host.request(f.intent()),/capacity/);
  assert.equal(f.pair.host.cancel(second.reviewId),true);
  assert.throws(()=>f.pair.host.request(f.intent()),/capacity/);
  assert.throws(()=>createMacTransferReviewPair({maxRequests:0}));
  assert.throws(()=>createMacTransferReviewPair({clock:()=>NaN}).host.request(f.intent()));
});
test('immutable review snapshot is independent of the caller and contains no authority',()=>{
  const f=fixture();
  const raw=f.intent();
  const review=f.pair.host.request(raw);
  const clone={...raw};
  clone.noteName='bbx-test-attacker.txt';
  assert.equal(review.intent.noteName,raw.noteName);
  assert.equal(f.pair.controller.pending()[0].intent.noteName,raw.noteName);
  assert.throws(()=>f.pair.host.consume({
    reviewId:review.reviewId,intent:clone,bytes:bytes()
  }),/did not approve/);
});
