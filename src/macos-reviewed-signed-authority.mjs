/**
 * Experimental v0.8 signed controller-review DATA transcript.
 * RSA-PSS/SHA256 binds a canonical review and audit-reservation checkpoint.
 * The native verifier must independently pin the corresponding PUBLIC key.
 * This does NOT prove the operator identity, audit durability or replay safety.
 */
import {constants,generateKeyPairSync,sign,verify,KeyObject} from 'node:crypto';
import {encodeCanonicalMacReviewedHandoff} from './macos-reviewed-transaction.mjs';

export const MAC_REVIEWED_RSA_DOMAIN='bbx-reviewed-controller-rsa-pss-v1\n';
const HASH=/^[0-9a-f]{64}$/;
const domain=Buffer.from(MAC_REVIEWED_RSA_DOMAIN,'ascii');

export function createEphemeralMacControllerSigner(){
  return Object.freeze(generateKeyPairSync('rsa',{
    modulusLength:2048,publicExponent:65537
  }));
}
function checkKey(key,type){
  if(!(key instanceof KeyObject)||key.type!==type||
     key.asymmetricKeyType!=='rsa'||
     key.asymmetricKeyDetails?.modulusLength!==2048)
    throw Error('Expected an RSA-2048 '+type+' KeyObject.');
}
function signedBytes(tx,reservationMac,now){
  if(typeof reservationMac!=='string'||!HASH.test(reservationMac))
    throw Error('Canonical HMAC audit reservation checkpoint required.');
  return Buffer.concat([
    domain,encodeCanonicalMacReviewedHandoff(tx,{now}),
    Buffer.from('reservationMac='+reservationMac+'\n','ascii')
  ]);
}
export function encodeMacReviewedRsaHandoff(tx,{
  privateKey,reservationMac,now=Date.now()
}={}){
  checkKey(privateKey,'private');
  const signed=signedBytes(tx,reservationMac,now);
  const signature=sign('sha256',signed,{
    key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  });
  if(signature.length!==256)throw Error('Unexpected RSA signature length.');
  return Buffer.concat([signed.subarray(domain.length),
    Buffer.from('controllerSig='+signature.toString('hex')+'\n','ascii')]);
}
/** An offline test oracle: the verifier key must never come from the wire. */
export function verifyMacReviewedRsaHandoff(wire,{
  publicKey,transaction,reservationMac,now=Date.now()
}={}){
  checkKey(publicKey,'public');
  if(!Buffer.isBuffer(wire))return false;
  let signed;
  try{signed=signedBytes(transaction,reservationMac,now);}
  catch{return false;}
  const match=/\ncontrollerSig=([0-9a-f]{512})\n$/.exec(wire.toString('ascii'));
  if(!match)return false;
  const expected=Buffer.concat([signed.subarray(domain.length),
    Buffer.from('controllerSig='+match[1]+'\n','ascii')]);
  if(!wire.equals(expected))return false;
  return verify('sha256',signed,{
    key:publicKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32
  },Buffer.from(match[1],'hex'));
}
/** Build-time pin for disposable native test code; never store the private key. */
export function formatPinnedMacRsaPublicHeader(publicKey){
  checkKey(publicKey,'public');
  const der=publicKey.export({type:'pkcs1',format:'der'});
  if(der.length<200||der.length>512)throw Error('Unexpected public-key DER.');
  const rows=[];
  for(let i=0;i<der.length;i+=12)
    rows.push('  '+[...der.subarray(i,i+12)]
      .map(v=>'0x'+v.toString(16).padStart(2,'0')).join(', '));
  return ['#ifndef BBX_TEST_PINNED_RSA_PUBLIC_H',
    '#define BBX_TEST_PINNED_RSA_PUBLIC_H',
    '/* Ephemeral TEST pin: not a production controller trust anchor. */',
    'static const unsigned char bbx_test_pinned_rsa_der[]={',
    rows.join(',\n'),'};','#endif',''].join('\n');
}
