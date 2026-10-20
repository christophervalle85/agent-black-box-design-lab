/**
 * Phase 5: validation-only sketch for synthetic macOS note import/export.
 * NOT connected to MCP tools, native file panels, controller approvals or
 * XPC. A matching review snapshot is NOT authentication/authorization.
 *
 * Intents contain NO filesystem paths, source bookmarks, payload bytes,
 * bearer tokens, model-selected destinations or arbitrary tool names.
 * The byte ceiling mirrors the current 2 KiB synthetic XPC note worker;
 * larger transfers will require a separately reviewed protocol.
 */
import {createHash,randomUUID,timingSafeEqual} from 'node:crypto';

export const MAC_TRANSFER_INTENT_VERSION=1;
export const MAC_TRANSFER_MAX_BYTES=2000;
export const MAC_TRANSFER_LIFETIME_MS=60_000;
const EXACT_KEYS=Object.freeze([
  'version','operation','noteName','byteLength','sha256','nonce','issuedAt','expiresAt'
].sort());
const NOTE=/^bbx-test-[A-Za-z0-9_-]{1,51}\.txt$/;
const SHA256=/^[a-f0-9]{64}$/;
const UUID_V4=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

function exactRecord(value,keys) {
  if(!value || typeof value!=='object' || Array.isArray(value))
    throw Error('Transfer metadata must be a plain record.');
  const prototype=Object.getPrototypeOf(value);
  if(prototype!==Object.prototype && prototype!==null)
    throw Error('Transfer metadata must have a plain prototype.');
  const descriptors=Object.getOwnPropertyDescriptors(value);
  const names=Object.keys(descriptors).sort();
  if(names.length!==keys.length || names.some((name,i)=>name!==keys[i]) ||
     names.some(name=>!('value' in descriptors[name])) ||
     Reflect.ownKeys(value).length!==keys.length)
    throw Error('Transfer metadata schema mismatch; extra fields forbidden.');
  return value;
}
function acceptableBytes(bytes) {
  if(!(bytes instanceof Uint8Array) || bytes.length<1 ||
     bytes.length>MAC_TRANSFER_MAX_BYTES)
    throw Error('Transfer payload must be 1–2000 raw bytes.');
  return Buffer.from(bytes); // Snapshot mutable caller-owned buffers.
}
function acceptableClock(now) {
  if(!Number.isSafeInteger(now) || now<0 ||
     now>Number.MAX_SAFE_INTEGER-MAC_TRANSFER_LIFETIME_MS)
    throw Error('Transfer clock must be a safe epoch-millisecond value.');
}
function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * Trusted host or worker creates a non-authorizing preview from exact bytes.
 * No approval decision or OS file path may be inserted into the record.
 */
export function createMacTransferIntent(fields={}) {
  // Even the *trusted* issuing API rejects unwanted path, bookmark and
  // approval fields; ignoring them would obscure a caller's unsafe intent.
  const hasNow=Object.prototype.hasOwnProperty.call(fields??{},'now');
  exactRecord(fields,(hasNow?
    ['bytes','noteName','now','operation']:
    ['bytes','noteName','operation']).sort());
  const {operation,noteName,bytes,now=Date.now()}=fields;
  acceptableClock(now);
  const snapshot=acceptableBytes(bytes);
  const intent={
    version:MAC_TRANSFER_INTENT_VERSION,operation,noteName,
    byteLength:snapshot.length,sha256:sha256(snapshot),
    nonce:randomUUID(),issuedAt:now,expiresAt:now+MAC_TRANSFER_LIFETIME_MS
  };
  return validateMacTransferIntent(intent,{now});
}

/** Validation only; this does not verify the record's provenance or approval. */
export function validateMacTransferIntent(intent,{now=Date.now()}={}) {
  acceptableClock(now);
  exactRecord(intent,EXACT_KEYS);
  if(intent.version!==MAC_TRANSFER_INTENT_VERSION ||
     !['import','export'].includes(intent.operation) ||
     typeof intent.noteName!=='string' || !NOTE.test(intent.noteName) ||
     intent.noteName.length>64 ||
     !Number.isSafeInteger(intent.byteLength) || intent.byteLength<1 ||
     intent.byteLength>MAC_TRANSFER_MAX_BYTES ||
     typeof intent.sha256!=='string' || !SHA256.test(intent.sha256) ||
     typeof intent.nonce!=='string' || !UUID_V4.test(intent.nonce) ||
     !Number.isSafeInteger(intent.issuedAt) || intent.issuedAt<0 ||
     !Number.isSafeInteger(intent.expiresAt) ||
     intent.expiresAt-intent.issuedAt!==MAC_TRANSFER_LIFETIME_MS ||
     now<intent.issuedAt || now>=intent.expiresAt)
    throw Error('Invalid, future-dated or expired transfer intent.');
  return Object.freeze({...intent});
}

/** Exact-byte binding for a validated intent, NOT permission to transfer. */
export function assertMacTransferBytes(intent,bytes,{now=Date.now()}={}) {
  const verified=validateMacTransferIntent(intent,{now});
  const snapshot=acceptableBytes(bytes);
  if(snapshot.length!==verified.byteLength)
    throw Error('Transfer byte count differs from intent.');
  const actual=Buffer.from(sha256(snapshot),'hex');
  const expected=Buffer.from(verified.sha256,'hex');
  if(!timingSafeEqual(actual,expected))
    throw Error('Transfer content digest differs from intent.');
  return true;
}

/**
 * Check only that metadata presented for review matches a later request.
 * IMPORTANT: callers MUST independently authenticate the existing controller's
 * single-use, unexpired operator approval. Never accept an agent-supplied
 * copy of the reviewed snapshot as proof of authorization.
 */
export function assertMacTransferReviewMatches(intent,review,{now=Date.now()}={}) {
  const requested=validateMacTransferIntent(intent,{now});
  const reviewed=validateMacTransferIntent(review,{now});
  for(const key of EXACT_KEYS)
    if(requested[key]!==reviewed[key])
      throw Error('Transfer request does not match reviewed metadata.');
  return true;
}
