/**
 * Portable signed audit checkpoint receipts and independent append-only ledger.
 * No HMAC secret or raw event contents leave the source machine.
 * External ledger MUST be kept under a different OS/security identity.
 */
import { createHash, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify, randomBytes } from 'node:crypto';
import {
  constants, existsSync, mkdirSync, lstatSync, readFileSync, openSync, closeSync,
  writeSync, fsyncSync, rmdirSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';

const FORMAT='agent-black-box/checkpoint-v1';
const HEX=/^[a-f0-9]{64}$/;
const nap=new Int32Array(new SharedArrayBuffer(4));
function assertSafe(path) {
  if (!existsSync(path))return;
  const s=lstatSync(path);
  if(!s.isFile()||s.isSymbolicLink()||s.nlink!==1)throw Error('Unsafe checkpoint file: '+path);
}
function syncDir(path){const fd=openSync(dirname(path),constants.O_RDONLY);try{fsyncSync(fd);}finally{closeSync(fd);}}
function append(path,line){
  assertSafe(path);
  const fd=openSync(path,constants.O_WRONLY|constants.O_CREAT|constants.O_APPEND|constants.O_NOFOLLOW,0o600);
  try{const b=Buffer.from(line+'\n');let n=0;while(n<b.length)n+=writeSync(fd,b,n,b.length-n);fsyncSync(fd);}finally{closeSync(fd);}
  syncDir(path);
}
function withLock(path,cb){
  mkdirSync(dirname(path),{recursive:true,mode:0o700});
  let acquired=false;
  for(let i=0;i<200;i++){
    try{mkdirSync(path+'.lock',{mode:0o700});acquired=true;break;}
    catch(e){if(e.code!=='EEXIST')throw e;Atomics.wait(nap,0,0,10);}
  }
  if(!acquired)throw Error('Checkpoint ledger lock unavailable. Inspect stale lock before retrying.');
  try{return cb();}finally{rmdirSync(path+'.lock');}
}
function payload(r){return JSON.stringify({version:r.version,logId:r.logId,seq:r.seq,head:r.head,createdAt:r.createdAt,publicKey:r.publicKey});}
function parseLedger(path){
  assertSafe(path);
  if(!existsSync(path))return [];
  const s=readFileSync(path,'utf8');
  if(s.length>8*1024*1024)throw Error('Checkpoint ledger size limit exceeded.');
  if(s && !s.endsWith('\n'))throw Error('Incomplete checkpoint ledger; manual incident investigation required.');
  return s? s.slice(0,-1).split('\n').map(line=>validateReceipt(JSON.parse(line))):[];
}
export function validateReceipt(r){
  if(!r||typeof r!=='object'||r.version!==1||!HEX.test(r.logId)||!Number.isSafeInteger(r.seq)||r.seq<0||!HEX.test(r.head)||
    typeof r.createdAt!=='string'||!/^\d{4}-\d{2}-\d{2}T/.test(r.createdAt)||
    typeof r.publicKey!=='string'||r.publicKey.length>2000||typeof r.signature!=='string'||r.signature.length>2000)
    throw Error('Invalid checkpoint receipt schema.');
  try {
    const pub=createPublicKey(r.publicKey);
    if(pub.asymmetricKeyType!=='ed25519'||!verify(null,Buffer.from(payload(r)),pub,Buffer.from(r.signature,'base64')))
      throw Error('Bad checkpoint signature.');
  }catch{throw Error('Bad checkpoint signature.');}
  return r;
}
function signerFor(store){
  const file=store.filename+'.receipt-ed25519.key';
  const publicFile=store.filename+'.receipt-ed25519.public';
  assertSafe(file);assertSafe(publicFile);
  if(existsSync(file)!==existsSync(publicFile))throw Error('Receipt signing identity incomplete; refusing reinitialization.');
  if(!existsSync(file)){
    // This key signs *receipts*, never audit record HMACs. Strict one-time file create.
    // A lost key cannot be recreated without breaking external identity continuity.
    const {privateKey,publicKey}=generateKeyPairSync('ed25519');
    const pem=privateKey.export({type:'pkcs8',format:'pem'});
    const fd=openSync(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
    try{writeSync(fd,pem);fsyncSync(fd);}finally{closeSync(fd);}
    syncDir(file);
    const pub=publicKey.export({type:'spki',format:'pem'});
    const fd2=openSync(publicFile,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
    try{writeSync(fd2,pub);fsyncSync(fd2);}finally{closeSync(fd2);}
    syncDir(publicFile);
  }
  const key=createPrivateKey(readFileSync(file));
  if(key.asymmetricKeyType!=='ed25519')throw Error('Wrong receipt signing key type.');
  if(createPublicKey(key).export({type:'spki',format:'pem'})!==readFileSync(publicFile,'utf8'))throw Error('Receipt signing key does not match registered identity.');
  return key;
}
export function exportReceipt(store){
  // Same writer lock protects a consistent log head + signature metadata snapshot.
  return store.locked(()=>{
    const state=store.verifyUnsafe();
    const logId=createHash('sha256').update(store.keyUnsafe()).digest('hex');
    const key=signerFor(store);
    const receipt={version:1,logId,seq:state.records,head:state.head,createdAt:new Date().toISOString(),
      publicKey:createPublicKey(key).export({type:'spki',format:'pem'})};
    return {...receipt,signature:sign(null,Buffer.from(payload(receipt)),key).toString('base64')};
  });
}
export function readLedger(path){
  const records=parseLedger(resolve(path));
  for(let i=1;i<records.length;i++){
    const a=records[i-1],b=records[i];
    if(a.logId!==b.logId||a.publicKey!==b.publicKey||b.seq<a.seq||
      (b.seq===a.seq && a.head!==b.head))throw Error('Checkpoint ledger conflict or rollback.');
  }
  return records;
}
export function receiveReceipt(ledgerPath,input){
  const r=validateReceipt(input),path=resolve(ledgerPath);
  return withLock(path,()=>{
    const existing=readLedger(path);
    const previous=existing.at(-1);
    if(previous && (previous.logId!==r.logId||previous.publicKey!==r.publicKey))throw Error('Checkpoint identity conflict: refusing key substitution.');
    if(previous && (r.seq<previous.seq || (r.seq===previous.seq&&r.head!==previous.head)))
      throw Error('CHECKPOINT ROLLBACK OR FORK detected: refusing receipt.');
    if(previous && r.seq===previous.seq)return {accepted:false,idempotent:true,records:existing.length,seq:r.seq};
    append(path,JSON.stringify(r));
    return {accepted:true,records:existing.length+1,seq:r.seq};
  });
}
export function assertExternalReceipt(store,receipt,state){
  const r=validateReceipt(receipt);
  {
    const expectedLogId=createHash('sha256').update(store.keyUnsafe()).digest('hex');
    const keyFile=store.filename+'.receipt-ed25519.key';
    const pubFile=store.filename+'.receipt-ed25519.public';
    // Without a local signing key, a copied public receipt cannot be trusted as our identity.
    assertSafe(keyFile);
    assertSafe(pubFile);
    if(!existsSync(keyFile)||!existsSync(pubFile))throw Error('Local receipt signing key missing; refusing identity reset.');
    const pub=createPublicKey(createPrivateKey(readFileSync(keyFile))).export({type:'spki',format:'pem'});
    if(readFileSync(pubFile,'utf8')!==pub)throw Error('Local signing key does not match registered public key.');
    if(r.logId!==expectedLogId || r.publicKey!==pub)throw Error('Checkpoint identity or signing key mismatch.');
    if(state.records<r.seq)throw Error('CHECKPOINT ROLLBACK detected: local history shorter than external checkpoint.');
    const macs=readFileSync(store.macFile,'utf8');
    const actual=r.seq===0?'0'.repeat(64):JSON.parse(macs.split('\n')[r.seq-1]).mac;
    if(actual!==r.head)throw Error('CHECKPOINT FORK detected: local authenticated history differs from external checkpoint.');
    return {ok:true,anchoredRecords:r.seq,currentRecords:state.records,logId:r.logId};
  }
}
export function compareReceipt(store,receipt){
  return store.locked(()=>assertExternalReceipt(store,receipt,store.verifyUnsafe()));
}
