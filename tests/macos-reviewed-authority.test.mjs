import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHmac} from 'node:crypto';
import {
  encodeMacReviewedAuthorityEnvelope,MAC_REVIEWED_AUTHORITY_DOMAIN
} from '../src/macos-reviewed-authority.mjs';
import {encodeCanonicalMacReviewedHandoff} from '../src/macos-reviewed-transaction.mjs';
import {
  fixedMacReviewedVector,fixedMacAuthorityEnvelope,
  FIXED_AUTH_KEY,FIXED_RESERVATION_MAC,FIXED_ISSUED
} from '../examples/mcp-macos-reviewed-contract-vector.mjs';

test('detached v1 MAC binds every canonical byte and audit reservation metadata',()=>{
  const tx=fixedMacReviewedVector();
  const base=encodeCanonicalMacReviewedHandoff(tx,{now:FIXED_ISSUED});
  const reservation=Buffer.from('reservationMac='+FIXED_RESERVATION_MAC+'\n');
  const mac=createHmac('sha256',FIXED_AUTH_KEY)
    .update(MAC_REVIEWED_AUTHORITY_DOMAIN,'ascii')
    .update(base).update(reservation).digest('hex');
  const expected=Buffer.concat([base,reservation,
    Buffer.from('authorityMac='+mac+'\n')]);
  assert.equal(fixedMacAuthorityEnvelope().equals(expected),true);
  assert.equal(mac.length,64);
  assert.equal(expected.toString('ascii').includes(FIXED_AUTH_KEY.toString('hex')),false);
  assert.equal(expected.toString('ascii').includes('approved='),false);
});
test('detached MAC encoding rejects attacker key/metadata shape and expired reviews',()=>{
  const tx=fixedMacReviewedVector();
  const good={key:FIXED_AUTH_KEY,reservationMac:FIXED_RESERVATION_MAC,
    now:FIXED_ISSUED};
  for(const key of [undefined,null,Buffer.alloc(31),Buffer.alloc(33),
                    FIXED_AUTH_KEY.toString('hex')]){
    assert.throws(()=>encodeMacReviewedAuthorityEnvelope(tx,{...good,key}));
  }
  for(const reservationMac of [undefined,null,'F'.repeat(64),
                               'c'.repeat(63),'x'.repeat(64)]){
    assert.throws(()=>encodeMacReviewedAuthorityEnvelope(tx,{
      ...good,reservationMac
    }));
  }
  assert.throws(()=>encodeMacReviewedAuthorityEnvelope(tx,{
    ...good,now:FIXED_ISSUED+60000
  }),/expired|invalid/i);
  assert.throws(()=>encodeMacReviewedAuthorityEnvelope({...tx,approved:true},
    good));
});
