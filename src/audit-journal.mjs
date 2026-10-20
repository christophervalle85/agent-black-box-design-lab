/**
 * Single-event write-ahead journal for v0.6's three-file HMAC store.
 * A fully fsynced, HMAC-authenticated pending intent is durable before writes.
 * Only the exact matching pending suffix may be replayed; arbitrary corruption
 * remains fail-closed. Requires caller's cross-process directory lock.
 */
import {
  constants, existsSync, lstatSync, readFileSync, openSync, closeSync,
  ftruncateSync, fsyncSync, unlinkSync
} from 'node:fs';
import { dirname } from 'node:path';

const ZERO='0'.repeat(64);
function secure(path) {
  if(!existsSync(path))return;
  const stat=lstatSync(path);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1)throw Error('Unsafe audit journal path: '+path);
}
function syncDir(path) {
  const fd=openSync(dirname(path),constants.O_RDONLY);
  try{fsyncSync(fd);}finally{closeSync(fd);}
}
function content(path){secure(path);return existsSync(path)?readFileSync(path,'utf8'):'';}
function examine(file,priorCount,expectedLine) {
  const text=content(file);
  const parts=text.split('\n');
  if(parts.length<priorCount+1)throw Error('RECOVERY REQUIRED: signed audit prefix missing.');
  const before=parts.slice(0,priorCount);
  if(before.some(x=>x.length===0))throw Error('RECOVERY REQUIRED: invalid signed audit prefix.');
  const prefix=before.length?before.join('\n')+'\n':'';
  if(!text.startsWith(prefix))throw Error('RECOVERY REQUIRED: incorrect signed audit prefix.');
  const tail=text.slice(prefix.length);
  const wanted=expectedLine+'\n';
  if(!wanted.startsWith(tail))throw Error('RECOVERY REQUIRED: unexpected journal tail; manual investigation needed.');
  return {before,complete:tail===wanted,truncateAt:Buffer.byteLength(prefix)};
}
function replay(file,prepared,expectedLine,appendDurable) {
  if(prepared.complete)return;
  const fd=openSync(file,constants.O_WRONLY|constants.O_NOFOLLOW);
  try{ftruncateSync(fd,prepared.truncateAt);fsyncSync(fd);}finally{closeSync(fd);}
  appendDurable(file,expectedLine);
}
export function finishPending(store,{sign,safeEqual,appendDurable,writeAtomic}){
  const file=store.pendingFile;
  secure(file);
  if(!existsSync(file))return false;
  let tx;
  try{tx=JSON.parse(content(file));}catch{throw Error('RECOVERY REQUIRED: invalid audit journal.');}
  if(tx?.version!==1||!Number.isSafeInteger(tx.seq)||tx.seq<1||typeof tx.raw!=='string'||
    tx.raw.includes('\n')||typeof tx.prev!=='string'||typeof tx.mac!=='string'||
    tx.prev.length!==64||tx.mac.length!==64||!safeEqual(tx.mac,sign(store.keyUnsafe(),tx.seq,tx.prev,tx.raw)))
    throw Error('RECOVERY REQUIRED: forged or invalid pending journal.');
  const macLine=JSON.stringify({seq:tx.seq,prev:tx.prev,mac:tx.mac});
  const prior=tx.seq-1;
  const events=examine(store.filename,prior,tx.raw);
  const signatures=examine(store.macFile,prior,macLine);
  if(events.before.length!==signatures.before.length)throw Error('RECOVERY REQUIRED: prefix count conflict.');
  let prev=ZERO;
  const key=store.keyUnsafe();
  for(let i=0;i<prior;i++){
    let m;
    try{m=JSON.parse(signatures.before[i]);JSON.parse(events.before[i]);}
    catch{throw Error('RECOVERY REQUIRED: invalid historical event or signature.');}
    const mac=sign(key,i+1,prev,events.before[i]);
    if(m.seq!==i+1||!safeEqual(m.prev,prev)||!safeEqual(m.mac,mac))throw Error('RECOVERY REQUIRED: tampered historical prefix.');
    prev=mac;
  }
  if(!safeEqual(prev,tx.prev))throw Error('RECOVERY REQUIRED: pending intent does not extend committed chain.');
  let checkpoint;
  try{checkpoint=JSON.parse(content(store.anchorFile));}
  catch{throw Error('RECOVERY REQUIRED: invalid local checkpoint.');}
  const old=checkpoint.seq===prior&&safeEqual(checkpoint.mac,tx.prev);
  const newer=checkpoint.seq===tx.seq&&safeEqual(checkpoint.mac,tx.mac);
  if(!old&&!newer)throw Error('RECOVERY REQUIRED: unexpected checkpoint rollback or fork.');
  if(newer&&(!events.complete||!signatures.complete))throw Error('RECOVERY REQUIRED: checkpoint ahead of audit files.');
  // Validation finishes before touching any file: only missing or partially
  // appended bytes of this specific authenticated intent can be reconstructed.
  replay(store.filename,events,tx.raw,appendDurable);
  replay(store.macFile,signatures,macLine,appendDurable);
  if(old)writeAtomic(store.anchorFile,JSON.stringify({seq:tx.seq,mac:tx.mac})+'\n');
  store.verifyUnsafe({allowPending:true});
  unlinkSync(file);syncDir(file);
  return true;
}
export function appendJournaled(store,{raw,seq,prev,mac,appendDurable,writeAtomic,fault}){
  secure(store.pendingFile);
  if(existsSync(store.pendingFile))throw Error('RECOVERY REQUIRED: unresolved prior journal.');
  writeAtomic(store.pendingFile,JSON.stringify({version:1,seq,prev,mac,raw})+'\n');
  fault?.('pending');
  appendDurable(store.filename,raw);
  fault?.('audit');
  appendDurable(store.macFile,JSON.stringify({seq,prev,mac}));
  fault?.('mac');
  writeAtomic(store.anchorFile,JSON.stringify({seq,mac})+'\n');
  fault?.('checkpoint');
  unlinkSync(store.pendingFile);syncDir(store.pendingFile);
}
