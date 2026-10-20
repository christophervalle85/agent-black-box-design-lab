/**
 * Build public-key-pinned RSA-PSS fixtures for Apple CI. Only PUBLIC bytes
 * are written to a generated C header; private keys remain in this process.
 */
import {writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createCanonicalMacReviewedTransaction} from '../src/macos-reviewed-transaction.mjs';
import {
  createEphemeralMacControllerSigner,encodeMacReviewedRsaHandoff,
  formatPinnedMacRsaPublicHeader
} from '../src/macos-reviewed-signed-authority.mjs';
import {fixedMacReviewedVector,FIXED_ISSUED}
  from './mcp-macos-reviewed-contract-vector.mjs';

export function buildPinnedMacRsaFixture(dir){
  const {publicKey,privateKey}=createEphemeralMacControllerSigner();
  const transaction=fixedMacReviewedVector();
  const reservationMac='b'.repeat(64); // PUBLIC deterministic audit placeholder
  const valid=encodeMacReviewedRsaHandoff(transaction,{
    privateKey,reservationMac,now:FIXED_ISSUED
  });
  const flip=(input,prefix)=>{
    const buf=Buffer.from(input);
    const offset=buf.indexOf(prefix);
    if(offset<0)throw Error('Missing signed-vector field.');
    const index=offset+prefix.length;
    buf[index]=buf[index]===0x66?0x65:0x66;
    return buf;
  };
  const {reviewId,transactionId,...intent}=transaction;
  const replacement=createCanonicalMacReviewedTransaction({
    reviewId:'123e4567-e89b-42d3-a456-426614174001',intent
  },{now:FIXED_ISSUED});
  // A canonical ID is not a signature: attacker can recompute this digest.
  const forged=Buffer.from(valid.toString('ascii')
    .replace('reviewId='+reviewId,'reviewId='+replacement.reviewId)
    .replace('transactionId='+transactionId,
             'transactionId='+replacement.transactionId),'ascii');
  const foreign=createEphemeralMacControllerSigner();
  const unpinned=encodeMacReviewedRsaHandoff(transaction,{
    privateKey:foreign.privateKey,reservationMac,now:FIXED_ISSUED
  });
  const fixtures={
    'rsa-valid.txt':valid,
    'rsa-bad-signature.txt':flip(valid,'controllerSig='),
    'rsa-bad-reservation.txt':flip(valid,'reservationMac='),
    'rsa-forged-review.txt':forged,
    'rsa-other-controller.txt':unpinned,
    'rsa-truncated.txt':valid.subarray(0,-1),
    'rsa-extra-field.txt':Buffer.concat([valid,Buffer.from('approved=true\n')])
  };
  writeFileSync(join(dir,'BBXTestPinnedControllerKey.h'),
    formatPinnedMacRsaPublicHeader(publicKey),{mode:0o600,flag:'wx'});
  for(const [name,data] of Object.entries(fixtures))
    writeFileSync(join(dir,name),data,{mode:0o600,flag:'wx'});
  return true;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length!==3)process.exitCode=90;
  else buildPinnedMacRsaFixture(resolve(process.argv[2]));
}
