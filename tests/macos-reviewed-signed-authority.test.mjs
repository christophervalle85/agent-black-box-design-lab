import {test} from 'node:test';
import assert from 'node:assert/strict';
import {constants,verify} from 'node:crypto';
import {
  createEphemeralMacControllerSigner,encodeMacReviewedRsaHandoff,
  verifyMacReviewedRsaHandoff,formatPinnedMacRsaPublicHeader,
  MAC_REVIEWED_RSA_DOMAIN
} from '../src/macos-reviewed-signed-authority.mjs';
import {encodeCanonicalMacReviewedHandoff} from '../src/macos-reviewed-transaction.mjs';
import {fixedMacReviewedVector,FIXED_ISSUED}
  from '../examples/mcp-macos-reviewed-contract-vector.mjs';

const reservationMac='b'.repeat(64);
test('ephemeral RSA signature authenticates exact canonical review and audit checkpoint',()=>{
  const {privateKey,publicKey}=createEphemeralMacControllerSigner();
  const tx=fixedMacReviewedVector();
  const wire=encodeMacReviewedRsaHandoff(tx,{
    privateKey,reservationMac,now:FIXED_ISSUED
  });
  assert.ok(wire.length<1536);
  assert.ok(wire.toString('ascii').startsWith(
    encodeCanonicalMacReviewedHandoff(tx,{now:FIXED_ISSUED}).toString('ascii')
  ));
  assert.equal(wire.includes(Buffer.from('PRIVATE KEY')),false);
  assert.equal(wire.toString('ascii').includes('approved='),false);
  const options={publicKey,transaction:tx,reservationMac,now:FIXED_ISSUED};
  assert.equal(verifyMacReviewedRsaHandoff(wire,options),true);
  const message=Buffer.concat([
    Buffer.from(MAC_REVIEWED_RSA_DOMAIN),
    encodeCanonicalMacReviewedHandoff(tx,{now:FIXED_ISSUED}),
    Buffer.from('reservationMac='+reservationMac+'\n')
  ]);
  const sig=Buffer.from(/controllerSig=([0-9a-f]{512})\n$/.exec(
    wire.toString('ascii'))[1],'hex');
  assert.equal(verify('sha256',message,{
    key:publicKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  },sig),true);
});
test('a pinned key rejects other signers, forged review and corrupted signatures',()=>{
  const first=createEphemeralMacControllerSigner();
  const other=createEphemeralMacControllerSigner();
  const tx=fixedMacReviewedVector();
  const issued=encodeMacReviewedRsaHandoff(tx,{
    privateKey:first.privateKey,reservationMac,now:FIXED_ISSUED
  });
  const options={publicKey:first.publicKey,transaction:tx,reservationMac,
    now:FIXED_ISSUED};
  const flip=(input,prefix)=>{
    const b=Buffer.from(input),start=b.indexOf(prefix);
    assert.ok(start>=0);
    const at=start+prefix.length;
    b[at]=b[at]===0x66?0x65:0x66;
    return b;
  };
  for(const invalid of [
    flip(issued,'controllerSig='),
    flip(issued,'reservationMac='),
    flip(issued,'reviewId='),
    issued.subarray(0,-1),
    Buffer.concat([issued,Buffer.from('approved=true\n')]),
    encodeMacReviewedRsaHandoff(tx,{
      privateKey:other.privateKey,reservationMac,now:FIXED_ISSUED
    })
  ])assert.equal(verifyMacReviewedRsaHandoff(invalid,options),false);
  assert.equal(verifyMacReviewedRsaHandoff(issued,{
    ...options,reservationMac:'c'.repeat(64)
  }),false);
  assert.equal(verifyMacReviewedRsaHandoff(issued,{
    ...options,publicKey:other.publicKey
  }),false);
});
test('signed review encoder fails closed on invalid keys and canonical fields',()=>{
  const keys=createEphemeralMacControllerSigner(),tx=fixedMacReviewedVector();
  for(const bad of [null,undefined,keys.publicKey,Buffer.alloc(32)])
    assert.throws(()=>encodeMacReviewedRsaHandoff(tx,{
      privateKey:bad,reservationMac,now:FIXED_ISSUED
    }));
  for(const bad of ['x'.repeat(64),'B'.repeat(64),'b'.repeat(63),''])
    assert.throws(()=>encodeMacReviewedRsaHandoff(tx,{
      privateKey:keys.privateKey,reservationMac:bad,now:FIXED_ISSUED
    }));
  assert.throws(()=>encodeMacReviewedRsaHandoff(tx,{
    privateKey:keys.privateKey,reservationMac,now:FIXED_ISSUED+60000
  }));
  const header=formatPinnedMacRsaPublicHeader(keys.publicKey);
  assert.match(header,/bbx_test_pinned_rsa_der/);
  assert.doesNotMatch(header,/PRIVATE KEY|controllerSig|reservationMac=/);
});
