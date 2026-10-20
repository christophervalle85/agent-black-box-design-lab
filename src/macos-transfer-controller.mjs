/**
 * v0.8 Phase 5: OPT-IN synthetic transfer review controller adapter.
 * Not a native file transfer, OS entitlement or proof of operator identity.
 * Only in-process trusted host code can create or consume a review. A
 * separate, same-origin UI can decide; a remote model cannot issue requests.
 */
import {randomUUID} from 'node:crypto';
import {createMacTransferReviewPair} from './macos-transfer-review.mjs';
import {createCanonicalMacReviewedTransaction} from './macos-reviewed-transaction.mjs';

export function createAuditedMacTransferController({
  store,clock=Date.now,syntheticTransport=null,syntheticTimeoutMs=5000
}={}) {
  if(!store || typeof store.verify!=='function' || typeof store.add!=='function')
    throw Error('Verified HMAC audit store is required.');
  if((syntheticTransport!==null && typeof syntheticTransport!=='function') ||
     !Number.isSafeInteger(syntheticTimeoutMs) || syntheticTimeoutMs<1 ||
     syntheticTimeoutMs>30000)
    throw Error('Invalid opt-in synthetic dispatch configuration.');
  const queue=createMacTransferReviewPair({clock});
  const audit=(review,ruleId,decision,outcome,summary,transfer=null)=>{
    const intent=review.intent;
    const event={
      id:randomUUID(),timestamp:new Date(clock()).toISOString(),
      runId:'mac-transfer-v0.8',agentId:'trusted-local-host',
      source:'mac-transfer-synthetic',tool:'mac.transfer.'+intent.operation,
      input:'Synthetic '+intent.operation+' '+intent.noteName+'; bytes omitted',
      decision,risk:'high',riskScore:75,ruleId,
      reason:summary,outcome,summary,durationMs:0,
      approvalId:review.reviewId,
      ...(transfer===null?{}:{
        transferTransactionId:transfer.transactionId,
        transferNonce:transfer.nonce,
        transferSHA256:transfer.sha256,
        transferBytes:transfer.byteLength,
        transferExpiresAt:transfer.expiresAt
      })
    };
    return store.add(event);
  };
  /**
   * ATTEMPT -> single-use burn -> durable RESERVATION -> synthetic callback
   * -> terminal audit. This is an isolated, injected test transport, NOT an
   * authenticated macOS XPC peer or a substitute for native Touch ID.
   *
   * Audit failures before the callback prohibit dispatch; an unexpected,
   * thrown or timed-out callback burns the grant and records uncertainty.
   * NEVER retry an uncertain external operation automatically.
   */
  async function dispatchSynthetic({reviewId,intent,bytes}={}) {
    store.verify();
    const review=queue.controller.lookup(reviewId);
    if(!review)throw Error('No unconsumed synthetic dispatch approval.');
    audit(review,'MAC_TRANSFER_DISPATCH_ATTEMPT','review','pending',
      'Synthetic dispatch staging requested; no native file operation.');
    // This call burns the approval even when bytes or metadata are wrong.
    let snapshot,transaction;
    try {
      queue.host.consume({reviewId,intent,bytes});
      // The data identity is derived from the ORIGINAL trusted review,
      // not attacker-supplied transaction fields or a new nonce.
      transaction=createCanonicalMacReviewedTransaction(review,{
        now:clock()
      });
      snapshot=Buffer.from(bytes);
    } catch {
      audit(review,'MAC_TRANSFER_DISPATCH_VALIDATION_DENIED','block','blocked',
        'Single-use synthetic dispatch validation failed; review was burned.');
      throw Error('Synthetic dispatch validation denied; approval consumed.');
    }
    try{
      // Must be HMAC-durable BEFORE the injected callback can run.
      audit(review,'MAC_TRANSFER_DISPATCH_RESERVED','review','pending',
        'Synthetic dispatch reservation durable; one-use review consumed.',
        transaction);
      store.verify();
    }catch{
      snapshot.fill(0);
      // The grant is burned, and the transport has NOT been called.
      throw Error('Synthetic dispatch reservation audit failed; no dispatch.');
    }
    const context=Object.freeze({
      reviewId:review.reviewId,intent:review.intent,transaction,bytes:snapshot
    });
    let outcome;
    let expired=false;
    let timer;
    try{
      outcome=await Promise.race([
        Promise.resolve().then(()=>syntheticTransport(context)),
        new Promise(resolve=>{
          timer=setTimeout(()=>{expired=true;resolve(null);},syntheticTimeoutMs);
        })
      ]);
    }catch{
      outcome=null;
    }finally{
      clearTimeout(timer);
      // Clearing our copy also limits post-resolution secret retention.
      // It CANNOT cancel a transport which is still running after timeout.
      snapshot.fill(0);
    }
    if(!expired && outcome==='SYNTHETIC_ACCEPTED'){
      // A successful synthetic receipt is not real OS transport authority.
      store.verify();
      audit(review,'MAC_TRANSFER_DISPATCH_SIMULATED','allow','simulated',
        'Injected synthetic transport reported success; no OS transfer.');
      return true;
    }
    store.verify();
    if(!expired && outcome==='SYNTHETIC_DENIED'){
      audit(review,'MAC_TRANSFER_DISPATCH_DENIED','block','blocked',
        'Injected synthetic transport explicitly denied; no automatic retry.');
      throw Error('Synthetic dispatch denied; approval cannot be reused.');
    }
    audit(review,'MAC_TRANSFER_DISPATCH_UNCERTAIN','block','error',
      'Synthetic transport outcome unknown or timed out; review burned; no retry.');
    throw Error('Synthetic dispatch uncertain; manual reconciliation required.');
  }
  const host=Object.freeze({
    request(intent){
      store.verify();
      const review=queue.host.request(intent);
      try{
        audit(review,'MAC_TRANSFER_REVIEW','review','pending',
          'Synthetic transfer review opened; no file operation permitted.');
      }catch(error){
        queue.host.cancel(review.reviewId);
        throw error;
      }
      return review;
    },
    consume({reviewId,intent,bytes}={}){
      store.verify();
      const review=queue.controller.lookup(reviewId);
      if(!review)throw Error('No unconsumed transfer approval.');
      audit(review,'MAC_TRANSFER_CONSUMPTION_ATTEMPT','review','pending',
        'Staged transfer validation requested; no native file access.');
      let result;
      try {
        result=queue.host.consume({reviewId,intent,bytes});
      } catch(error) {
        // The review has already been burned. Record a definitive denial,
        // never leave a forged/altered attempt looking like success.
        audit(review,'MAC_TRANSFER_CONSUMPTION_DENIED','block','blocked',
          'Synthetic approval or payload validation denied; no OS transfer.');
        throw error;
      }
      audit(review,'MAC_TRANSFER_CONSUMED','allow','simulated',
        'One-time synthetic grant validated; no OS transfer occurred.');
      return result;
    },
    cancel(id){
      store.verify();
      const review=queue.controller.lookup(id);
      if(!review)return false;
      audit(review,'MAC_TRANSFER_CANCEL_REQUEST','review','pending',
        'Synthetic transfer cancellation requested.');
      const result=queue.host.cancel(id);
      if(result) audit(review,'MAC_TRANSFER_CANCELLED','block','blocked',
        'Synthetic transfer cancelled; no file operation occurred.');
      return result;
    },
    // NEVER install synthetic dispatch on the ordinary MCP/server facade.
    ...(syntheticTransport===null?{}:{dispatchSynthetic})
  });
  const controller=Object.freeze({
    pending(){
      store.verify();
      return queue.controller.pending();
    },
    decide(id,decision){
      store.verify();
      if(decision!=='approve'&&decision!=='deny')return false;
      const review=queue.controller.lookup(id);
      if(!review || !queue.controller.pending().some(x=>x.reviewId===id))return false;
      audit(review,'MAC_TRANSFER_DECISION_REQUEST','review','pending',
        'Local UI requested a synthetic review decision.');
      if(!queue.controller.decide(id,decision))return false;
      try{
        audit(review,decision==='approve'?'MAC_TRANSFER_APPROVED':'MAC_TRANSFER_DENIED',
          decision==='approve'?'allow':'block',
          decision==='approve'?'pending':'blocked',
          decision==='approve'
            ?'Operator approved one-time staging; no native file access.'
            :'Operator denied synthetic transfer; no native file access.');
      }catch(error){
        queue.host.cancel(id);
        throw error;
      }
      return true;
    },
    close(){queue.controller.close();}
  });
  return Object.freeze({host,controller});
}
