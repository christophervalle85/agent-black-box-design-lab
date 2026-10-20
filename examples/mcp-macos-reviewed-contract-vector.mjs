/**
 * Fixed-public-data cross-language contract vector (Node vs native C).
 * This checksum is NOT an operator approval, key, or transferable grant.
 */
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  createCanonicalMacReviewedTransaction,encodeCanonicalMacReviewedHandoff
} from '../src/macos-reviewed-transaction.mjs';
import {encodeMacReviewedAuthorityEnvelope} from '../src/macos-reviewed-authority.mjs';

export const FIXED_BYTES=Buffer.from('BBX synthetic Touch ID reviewed bytes.\n');
export const FIXED_REVIEW_ID='123e4567-e89b-42d3-a456-426614174000';
export const FIXED_NONCE='abcdef12-3456-4789-8abc-123456789abc';
export const FIXED_ISSUED=1790000000000;
export function fixedMacReviewedVector(){
  return createCanonicalMacReviewedTransaction({
    reviewId:FIXED_REVIEW_ID,
    intent:{
      version:1,operation:'import',noteName:'bbx-test-reviewed.txt',
      byteLength:FIXED_BYTES.length,
      sha256:createHash('sha256').update(FIXED_BYTES).digest('hex'),
      nonce:FIXED_NONCE,
      issuedAt:FIXED_ISSUED,expiresAt:FIXED_ISSUED+60000
    }
  },{now:FIXED_ISSUED});
}
// PUBLIC deterministic fixture only: no runtime authority, never a secret.
export const FIXED_AUTH_KEY=Buffer.from(
  '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f','hex');
export const FIXED_RESERVATION_MAC='c'.repeat(64);
export function fixedMacAuthorityEnvelope(){
  return encodeMacReviewedAuthorityEnvelope(fixedMacReviewedVector(),{
    key:FIXED_AUTH_KEY,reservationMac:FIXED_RESERVATION_MAC,now:FIXED_ISSUED
  });
}
function flipHexLine(record,prefix){
  const wire=Buffer.from(record);
  const index=wire.indexOf(prefix);
  if(index<0)throw Error('Expected MAC test field missing.');
  const point=index+prefix.length;
  wire[point]=wire[point]===0x66?0x65:0x66;
  return wire;
}
function forgedCoherentReview(){
  const original=fixedMacReviewedVector();
  const {reviewId,transactionId,...intent}=original;
  const forged=createCanonicalMacReviewedTransaction({
    reviewId:'123e4567-e89b-42d3-a456-426614174001',intent
  },{now:FIXED_ISSUED});
  // Attacker recomputes the PUBLIC transaction digest but cannot refresh MAC.
  const text=fixedMacAuthorityEnvelope().toString('ascii')
    .replace('reviewId='+reviewId,'reviewId='+forged.reviewId)
    .replace('transactionId='+transactionId,
      'transactionId='+forged.transactionId);
  return Buffer.from(text,'ascii');
}
if(process.argv[1] && resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const mode=process.argv[2];
  if(process.argv.length===2)
    console.log(fixedMacReviewedVector().transactionId);
  else if(process.argv.length!==3)process.exitCode=90;
  else if(mode==='--handoff')
    process.stdout.write(encodeCanonicalMacReviewedHandoff(
      fixedMacReviewedVector(),{now:FIXED_ISSUED}
    ));
  else if(mode==='--auth')process.stdout.write(fixedMacAuthorityEnvelope());
  else if(mode==='--auth-bad-mac')process.stdout.write(
    flipHexLine(fixedMacAuthorityEnvelope(),'authorityMac='));
  else if(mode==='--auth-bad-reservation')process.stdout.write(
    flipHexLine(fixedMacAuthorityEnvelope(),'reservationMac='));
  else if(mode==='--auth-forged-review')process.stdout.write(forgedCoherentReview());
  else process.exitCode=90;
}
