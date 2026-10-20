/**
 * Phase 5: isolated, IN-MEMORY review/approval-consumption state machine.
 *
 * Not connected to the operator's authenticated HTTP controller, MCP, native
 * picker, XPC, OS filesystem, or audit. Only trusted application code must
 * hold the controller facet; possession of that facet is NOT authentication.
 * No grant is returned to, or verified from, a model-supplied token.
 * A process restart drops ALL approvals (fail closed).
 */
import {randomUUID} from 'node:crypto';
import {
  validateMacTransferIntent,assertMacTransferReviewMatches,assertMacTransferBytes
} from './macos-transfer-intent.mjs';

function boundedClock(clock) {
  const now=clock();
  if(!Number.isSafeInteger(now)||now<0)
    throw Error('Transfer approval clock invalid.');
  return now;
}
function reviewId(id) {
  return typeof id==='string' && /^[a-f0-9-]{36}$/i.test(id);
}
export function createMacTransferReviewPair({clock=Date.now,maxRequests=64}={}) {
  if(typeof clock!=='function' ||
     !Number.isSafeInteger(maxRequests)||maxRequests<1||maxRequests>1024)
    throw Error('Invalid transfer review capacity or clock.');
  const pending=new Map();
  // Never forget a nonce during this process lifetime: denying a replay is
  // safer than recycling an apparently cancelled or expired review.
  const usedNonces=new Set();
  let closed=false;
  function cleanExpired(now) {
    for(const [id,record] of pending)
      if(now>=record.intent.expiresAt)pending.delete(id);
  }
  function request(intent) {
    if(closed)throw Error('Transfer review service closed.');
    const now=boundedClock(clock);
    const validated=validateMacTransferIntent(intent,{now});
    cleanExpired(now);
    if(usedNonces.has(validated.nonce))
      throw Error('Transfer intent nonce has already been reviewed.');
    if(usedNonces.size>=maxRequests || pending.size>=maxRequests)
      throw Error('Transfer review capacity exhausted; refusing new approval.');
    const id=randomUUID();
    const record={intent:validated,state:'pending'};
    pending.set(id,record);
    usedNonces.add(validated.nonce);
    return Object.freeze({reviewId:id,intent:validated});
  }
  function pendingReviews() {
    const now=boundedClock(clock);
    cleanExpired(now);
    if(closed)return Object.freeze([]);
    return Object.freeze([...pending].filter(([,r])=>r.state==='pending')
      .map(([id,record])=>Object.freeze({reviewId:id,intent:record.intent})));
  }
  // Trusted controller only. Includes approved-but-unconsumed records so
  // the audit adapter can tie a later consume/cancel to the original grant.
  function lookup(id) {
    if(closed||!reviewId(id))return null;
    cleanExpired(boundedClock(clock));
    const record=pending.get(id);
    return record?Object.freeze({reviewId:id,intent:record.intent}):null;
  }
  function decide(id,decision) {
    if(closed||!reviewId(id) || (decision!=='approve'&&decision!=='deny'))
      return false;
    const now=boundedClock(clock);
    cleanExpired(now);
    const record=pending.get(id);
    if(!record||record.state!=='pending')return false;
    // The trusted controller calls this after authenticating a local human
    // decision. This module alone has NO operator authentication.
    if(decision==='deny')pending.delete(id);
    else record.state='approved';
    return true;
  }
  function cancel(id) {
    if(!reviewId(id))return false;
    return pending.delete(id); // Cancels even an approved, unconsumed review.
  }
  function consume({reviewId:id,intent,bytes}={}) {
    if(closed||!reviewId(id))throw Error('Invalid transfer review consumption.');
    const now=boundedClock(clock);
    const record=pending.get(id);
    if(!record)throw Error('No unconsumed transfer review exists.');
    // Consume BEFORE inspecting potentially attacker-modified bytes/metadata;
    // a failed attempt burns the approval and cannot be used for another file.
    pending.delete(id);
    if(record.state!=='approved')
      throw Error('Operator did not approve the transfer.');
    assertMacTransferReviewMatches(intent,record.intent,{now});
    assertMacTransferBytes(record.intent,bytes,{now});
    return true; // Validation only; never an OS permission or bearer token.
  }
  function close() {
    if(closed)return;
    closed=true;
    pending.clear();
  }
  return Object.freeze({
    // Trusted host/adapter keeps this facet OUTSIDE model-controlled code.
    host:Object.freeze({request,consume,cancel}),
    // Only the authenticated controller should ever receive this facet.
    controller:Object.freeze({pending:pendingReviews,lookup,decide,close})
  });
}
