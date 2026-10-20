/**
 * v0.8 Phase 6: canonical DATA identity for a reviewed synthetic transaction.
 *
 * Identity is SHA-256 over strict, domain-separated ASCII encoding.
 * A matching hash proves field equality, NOT provenance, authentication,
 * Touch ID success, HMAC audit approval or permission to dispatch. The
 * signed native host is not yet connected to this Node review issuer.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {validateMacTransferIntent} from './macos-transfer-intent.mjs';

export const MAC_REVIEWED_TRANSACTION_VERSION=1;
export const MAC_REVIEWED_TRANSACTION_DOMAIN='bbx-reviewed-transaction-v1';
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const hex=/^[a-f0-9]{64}$/;
const fields=Object.freeze([
  'version','reviewId','operation','noteName','byteLength',
  'sha256','nonce','issuedAt','expiresAt'
]);
const keys=Object.freeze([...fields,'transactionId'].sort());
function exactRecord(value,wanted){
  if(!value || typeof value!=='object' || Array.isArray(value) ||
     ![Object.prototype,null].includes(Object.getPrototypeOf(value)))
    throw Error('Canonical transaction requires a plain record.');
  const descriptions=Object.getOwnPropertyDescriptors(value);
  const names=Object.keys(descriptions).sort();
  if(names.length!==wanted.length ||
     names.some((name,i)=>name!==wanted[i]) ||
     names.some(name=>!('value' in descriptions[name])) ||
     Reflect.ownKeys(value).length!==wanted.length)
    throw Error('Canonical transaction fields must be exact data properties.');
}
function clock(now){
  if(!Number.isSafeInteger(now)||now<0)
    throw Error('Invalid canonical transaction clock.');
  return now;
}
function normalize(reviewId,intent,{now}){
  if(typeof reviewId!=='string'||!uuid.test(reviewId))
    throw Error('Canonical review ID requires lowercase UUIDv4.');
  const check=validateMacTransferIntent(intent,{now:clock(now)});
  if(!uuid.test(check.nonce))
    throw Error('Canonical nonce requires lowercase UUIDv4.');
  return Object.freeze({
    version:MAC_REVIEWED_TRANSACTION_VERSION,
    reviewId,operation:check.operation,noteName:check.noteName,
    byteLength:check.byteLength,sha256:check.sha256,nonce:check.nonce,
    issuedAt:check.issuedAt,expiresAt:check.expiresAt
  });
}
/**
 * No JSON/string-key-order ambiguities. All fields are ASCII by schema;
 * none can contain an LF, equal sign or delimiter injection. Numeric fields
 * are canonical base-10 nonnegative safe integers, with no leading zeroes.
 * The trailing LF is mandatory; native and Node must hash identical bytes.
 */
function encodeCanonicalMacReviewedTransaction(value){
  exactRecord(value,[...fields].sort());
  const parts=[
    MAC_REVIEWED_TRANSACTION_DOMAIN,
    ...fields.map(key=>key+'='+String(value[key]))
  ];
  return Buffer.from(parts.join('\n')+'\n','ascii');
}
function createId(value){
  return createHash('sha256')
    .update(encodeCanonicalMacReviewedTransaction(value)).digest('hex');
}
export function createCanonicalMacReviewedTransaction({reviewId,intent},{now=Date.now()}={}){
  const base=normalize(reviewId,intent,{now});
  return Object.freeze({...base,transactionId:createId(base)});
}
/** Re-derive and verify a claimed ID; a digest is never approval evidence. */
export function assertCanonicalMacReviewedTransaction(candidate,{now=Date.now()}={}){
  exactRecord(candidate,keys);
  if(candidate.version!==MAC_REVIEWED_TRANSACTION_VERSION ||
     typeof candidate.transactionId!=='string' ||
     !hex.test(candidate.transactionId))
    throw Error('Unsupported canonical transaction version or identifier.');
  const {version,reviewId,transactionId,...rest}=candidate;
  const expected=createCanonicalMacReviewedTransaction({
    reviewId,intent:{version,...rest}
  },{now});
  const a=Buffer.from(expected.transactionId,'hex');
  const b=Buffer.from(transactionId,'hex');
  if(!timingSafeEqual(a,b))
    throw Error('Canonical transaction identifier mismatch.');
  return expected;
}

/**
 * Strict ASCII wire envelope for one preissued synthetic review. The bytes
 * are DATA, not an HMAC or a bearer authorization. The only intended sender
 * is the trusted local test harness; native must check all fields again.
 */
export function encodeCanonicalMacReviewedHandoff(candidate,{now=Date.now()}={}){
  const tx=assertCanonicalMacReviewedTransaction(candidate,{now});
  return Buffer.concat([
    encodeCanonicalMacReviewedTransaction({
      version:tx.version,reviewId:tx.reviewId,operation:tx.operation,
      noteName:tx.noteName,byteLength:tx.byteLength,sha256:tx.sha256,
      nonce:tx.nonce,issuedAt:tx.issuedAt,expiresAt:tx.expiresAt
    }),
    Buffer.from('transactionId='+tx.transactionId+'\n','ascii')
  ]);
}
