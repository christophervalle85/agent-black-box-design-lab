/**
 * Test-only detached MAC format for a preissued reviewed transaction.
 *
 * A MAC proves possession of an independently trusted key and binds the
 * reservation checkpoint to the exact ASCII wire bytes. This helper DOES
 * NOT establish the signer's identity, reserve an approval, protect the key,
 * authenticate a human decision, or prevent replay. Never accept a key
 * chosen/provided by an untrusted envelope or by the model.
 *
 * Current deterministic vector uses a PUBLIC fixture key. Its output is
 * NEVER controller authority and must not enable real transfer operations.
 */
import {createHmac} from 'node:crypto';
import {encodeCanonicalMacReviewedHandoff} from './macos-reviewed-transaction.mjs';

export const MAC_REVIEWED_AUTHORITY_DOMAIN='bbx-audited-handoff-auth-v1\n';
const lowerHex=/^[a-f0-9]{64}$/;

export function encodeMacReviewedAuthorityEnvelope(transaction,{
  key,reservationMac,now=Date.now()
}={}){
  if(!Buffer.isBuffer(key) || key.length!==32)
    throw Error('Detached handoff MAC requires an external 32-byte key.');
  if(typeof reservationMac!=='string' || !lowerHex.test(reservationMac))
    throw Error('Detached handoff requires a canonical audit reservation MAC.');
  const wire=encodeCanonicalMacReviewedHandoff(transaction,{now});
  const reservation=Buffer.from('reservationMac='+reservationMac+'\n','ascii');
  const tag=createHmac('sha256',key)
    .update(MAC_REVIEWED_AUTHORITY_DOMAIN,'ascii')
    .update(wire).update(reservation).digest('hex');
  return Buffer.concat([wire,reservation,
    Buffer.from('authorityMac='+tag+'\n','ascii')]);
}
