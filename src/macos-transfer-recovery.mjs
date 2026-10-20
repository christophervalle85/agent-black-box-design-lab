/**
 * Read-only, fail-closed recovery inspection for synthetic macOS reviews.
 *
 * Operates on an independently verified HMAC audit chain, never on process
 * memory or an unverified controller success flag. No audit entries are
 * synthesized during recovery: reservation without a terminal result is
 * UNKNOWN, even after an OS-host crash or transport timeout. This does NOT
 * query actual native XPC commit state or grant permission to retry.
 *
 * AuditStore.list is intentionally bounded to 1,000 records. When the full
 * chain is larger, refuse an incomplete lifecycle analysis rather than
 * incorrectly accepting a truncated history.
 */
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const FINAL=new Map([
  ['MAC_TRANSFER_DISPATCH_SIMULATED','simulated-only'],
  ['MAC_TRANSFER_DISPATCH_DENIED','denied'],
  ['MAC_TRANSFER_DISPATCH_UNCERTAIN','unknown']
]);
const RELEVANT=new Set([
  'MAC_TRANSFER_REVIEW','MAC_TRANSFER_APPROVED',
  'MAC_TRANSFER_DISPATCH_ATTEMPT',
  'MAC_TRANSFER_DISPATCH_VALIDATION_DENIED',
  'MAC_TRANSFER_DISPATCH_RESERVED',...FINAL.keys()
]);
const STATES=Object.freeze({
  'simulated-only':'A synthetic callback claimed success; no native success proven.',
  denied:'Injected transport explicitly denied; approval burned.',
  unknown:'Reserved operation could have committed; never retry automatically.',
  'validation-denied':'Validation denied before transport; approval burned.',
  'pre-dispatch':'No durable transport reservation found; old approval expired on restart.'
});
function fail(){throw Error('RECOVERY REQUIRED: inconsistent synthetic transfer audit lifecycle.');}
export function inspectMacSyntheticDispatchRecovery(store){
  if(!store || typeof store.verify!=='function' ||
     typeof store.list!=='function')throw Error('Verified HMAC audit store required.');
  const checkpoint=store.verify();
  if(checkpoint?.ok!==true ||
     !Number.isSafeInteger(checkpoint.records) ||
     checkpoint.records<0)throw Error('Verified HMAC audit checkpoint required.');
  if(checkpoint.records>1000)
    throw Error('RECOVERY REQUIRED: synthetic transfer audit exceeds complete inspection window.');
  const records=store.list({limit:1000});
  if(!Array.isArray(records) || records.length!==checkpoint.records)
    throw Error('RECOVERY REQUIRED: audit changed during recovery inspection.');
  const states=new Map();
  // Iterate in chronological order, so ordering is part of the evidence.
  for(const event of [...records].reverse()){
    if(!event || typeof event!=='object' ||
       !RELEVANT.has(event.ruleId))continue;
    if(event.source!=='mac-transfer-synthetic' ||
       !UUID.test(event.approvalId))fail();
    const id=event.approvalId;
    if(!states.has(id))
      states.set(id,{review:false,approved:false,attempt:false,
                     validationDenied:false,reserved:false,terminal:null});
    const state=states.get(id);
    switch(event.ruleId){
      case 'MAC_TRANSFER_REVIEW':
        if(state.review)fail();
        state.review=true;
        break;
      case 'MAC_TRANSFER_APPROVED':
        if(!state.review||state.approved||state.attempt)fail();
        state.approved=true;
        break;
      case 'MAC_TRANSFER_DISPATCH_ATTEMPT':
        if(!state.review||!state.approved||state.attempt||
           state.reserved||state.terminal||state.validationDenied)fail();
        state.attempt=true;
        break;
      case 'MAC_TRANSFER_DISPATCH_VALIDATION_DENIED':
        if(!state.attempt||state.validationDenied||state.reserved||
           state.terminal)fail();
        state.validationDenied=true;
        break;
      case 'MAC_TRANSFER_DISPATCH_RESERVED':
        if(!state.attempt||state.reserved||state.validationDenied||
           state.terminal)fail();
        state.reserved=true;
        break;
      default:
        if(!FINAL.has(event.ruleId)||!state.reserved||state.terminal)fail();
        state.terminal=FINAL.get(event.ruleId);
        break;
    }
  }
  const results=[];
  for(const [reviewId,state] of states){
    if(!state.attempt)continue;
    let status;
    if(state.validationDenied)status='validation-denied';
    else if(!state.reserved)status='pre-dispatch';
    else status=state.terminal??'unknown';
    results.push(Object.freeze({
      reviewId,status,canRetry:false,description:STATES[status]
    }));
  }
  return Object.freeze({
    inspectedRecords:checkpoint.records,
    hasUncertainDispatch:results.some(x=>x.status==='unknown'),
    dispatches:Object.freeze(results)
  });
}

/*
 * Correlate an explicitly observed native TEST-WORKER marker with a verified
 * HMAC-audit UNCERTAIN reservation. The observation is data supplied by the
 * caller, not a signed claim; only the test harness may source it from the
 * actual OS-signed worker's exact evidence response. Never produce a grant,
 * a success verdict, a retry instruction or a persisted audit modification.
 */
export function classifyMacSyntheticUncertainReceipt(report,{
  reviewId,observation
}={}){
  if(!report || !Array.isArray(report.dispatches) ||
     !UUID.test(reviewId))throw Error('Verified synthetic recovery report required.');
  const target=report.dispatches.filter(
    item=>item?.reviewId===reviewId&&item.status==='unknown'&&
          item.canRetry===false
  );
  if(target.length!==1)
    throw Error('RECOVERY REQUIRED: no unique uncertain reserved review.');
  const meaning=Object.freeze({
    'matching-marker':'Native synthetic nonce marker matches the transaction, but no controller acknowledgment exists.',
    'no-marker':'No nonce marker observed in the worker container snapshot; execution absence is NOT proven.',
    unverifiable:'Native receipt evidence is invalid or unavailable; outcome remains unknown.'
  });
  if(!Object.hasOwn(meaning,observation))
    throw Error('Unsupported native synthetic recovery evidence.');
  return Object.freeze({
    reviewId,observation,status:'unknown',
    canRetry:false,canClaimSuccess:false,
    description:meaning[observation]
  });
}
