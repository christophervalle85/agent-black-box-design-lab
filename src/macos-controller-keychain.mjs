/**
 * Test-only controller identity pinned from a persistent macOS Keychain RSA
 * key. Node gets ONLY the public key and a signed canonical synthetic review.
 * It must never provision a new key in the reviewed-transfer harness.
 *
 * This is NOT a production trust service: the Keychain software key is
 * available to an authorized same-user diagnostic helper. No hardware
 * isolation, independent deployment pin or trusted human consent proven.
 */
import {createPublicKey,createHash} from 'node:crypto';
import {encodeCanonicalMacReviewedHandoff} from './macos-reviewed-transaction.mjs';
import {verifyMacReviewedRsaHandoff} from './macos-reviewed-signed-authority.mjs';

const PUBLIC_LINE=/^BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=([A-Za-z0-9+/]+={0,2})\n$/;
const RESERVATION=/^[0-9a-f]{64}$/;
export function parseMacKeychainPublicRecord(output){
  if(typeof output!=='string')throw Error('Exact Keychain public-key response required.');
  const match=PUBLIC_LINE.exec(output);
  if(!match)throw Error('Malformed Keychain public-key response.');
  const der=Buffer.from(match[1],'base64');
  if(der.length<200||der.length>512||der.toString('base64')!==match[1])
    throw Error('Non-canonical Keychain RSA public key.');
  let publicKey;
  try{publicKey=createPublicKey({key:der,format:'der',type:'pkcs1'});}
  catch{throw Error('Invalid Keychain RSA public key DER.');}
  if(publicKey.type!=='public'||publicKey.asymmetricKeyType!=='rsa'||
     publicKey.asymmetricKeyDetails?.modulusLength!==2048||
     publicKey.asymmetricKeyDetails?.publicExponent!==65537n)
    throw Error('Expected an RSA-2048 e=65537 Keychain public key.');
  return Object.freeze({
    publicKey,
    sha256:createHash('sha256').update(der).digest('hex')
  });
}
export function encodeMacKeychainUnsignedReview(tx,{
  reservationMac,now=Date.now()
}={}){
  if(typeof reservationMac!=='string'||!RESERVATION.test(reservationMac))
    throw Error('Verified HMAC reservation checkpoint required.');
  return Buffer.concat([encodeCanonicalMacReviewedHandoff(tx,{now}),
    Buffer.from('reservationMac='+reservationMac+'\n','ascii')]);
}
export function validateMacKeychainSignedReview(wire,{
  publicKey,transaction,reservationMac,now=Date.now()
}={}){
  if(!Buffer.isBuffer(wire)||wire.length>1536||
     !verifyMacReviewedRsaHandoff(wire,{
       publicKey,transaction,reservationMac,now
     }))
    throw Error('Keychain signing response did not match the pinned controller identity and exact reservation.');
  return wire;
}
