import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { AuditStore } from '../src/audit.mjs';
import { exportReceipt, receiveReceipt, compareReceipt, readLedger, validateReceipt } from '../src/checkpoints.mjs';

const event=id=>({id,decision:'allow',tool:'file.read',runId:'test',timestamp:'2026-10-13T00:00:00.000Z'});
function fixture(callback){const dir=mkdtempSync(join(tmpdir(),'abb-checkpoint-'));try{return callback({file:join(dir,'audit.jsonl'),ledger:join(dir,'other-account-ledger.jsonl')});}finally{rmSync(dir,{recursive:true,force:true});}}

test('Ed25519 receipt independently verifies without audit HMAC secret',()=>fixture(({file,ledger})=>{
  const store=new AuditStore(file);store.add(event('one'));
  const receipt=exportReceipt(store);
  assert.equal(receipt.seq,1);
  assert.ok(validateReceipt(receipt));
  assert.equal(receiveReceipt(ledger,receipt).accepted,true);
  assert.equal(receiveReceipt(ledger,receipt).idempotent,true);
  assert.equal(readLedger(ledger).length,1);
  store.add(event('two'));
  assert.equal(compareReceipt(store,receipt).ok,true);
  const next=exportReceipt(store);
  assert.equal(receiveReceipt(ledger,next).records,2);
  assert.equal(readLedger(ledger)[1].seq,2);
}));

test('receipts reject unsigned changes, mismatched key, rollback and equal-sequence fork',()=>fixture(({file,ledger})=>{
  const store=new AuditStore(file);
  store.add(event('one'));const one=exportReceipt(store);
  receiveReceipt(ledger,one);
  assert.throws(()=>validateReceipt({...one,head:'f'.repeat(64)}),/signature/i);
  store.add(event('two'));const two=exportReceipt(store);
  receiveReceipt(ledger,two);
  assert.throws(()=>receiveReceipt(ledger,one),/ROLLBACK|FORK/);
  const other=new AuditStore(join(file+'.other'));
  other.add(event('different'));
  assert.throws(()=>receiveReceipt(ledger,exportReceipt(other)),/identity conflict/);
  assert.throws(()=>compareReceipt(other,two),/identity|key mismatch/);
}));

test('local compromise may re-HMAC events but previously exported checkpoint detects fork',()=>fixture(({file})=>{
  const store=new AuditStore(file);store.add(event('original'));
  const trusted=exportReceipt(store);
  const raw=JSON.stringify(event('tampered'));
  writeFileSync(file,raw+'\n');
  // Attacker's access to local key allows a new valid chain + checkpoint.
  const {createHmac}=awaitImportCrypto();
  const key=store.keyUnsafe();
  const prev='0'.repeat(64);
  const mac=createHmac('sha256',key).update(JSON.stringify({version:1,seq:1,prev,raw}),'utf8').digest('hex');
  writeFileSync(store.macFile,JSON.stringify({seq:1,prev,mac})+'\n');
  writeFileSync(store.anchorFile,JSON.stringify({seq:1,mac})+'\n');
  assert.equal(store.verify().ok,true);
  assert.throws(()=>compareReceipt(store,trusted),/CHECKPOINT FORK/);
}));
import {createHmac as actualHmac} from 'node:crypto';
function awaitImportCrypto(){return {createHmac:actualHmac};}

test('missing signing identity and tampered ledger fail closed',()=>fixture(({file,ledger})=>{
  const store=new AuditStore(file);store.add(event('x'));
  const r=exportReceipt(store);receiveReceipt(ledger,r);
  unlinkSync(file+'.receipt-ed25519.key');
  assert.throws(()=>compareReceipt(store,r),/signing key missing/);
  const data=readFileSync(ledger,'utf8');
  writeFileSync(ledger,data.replace('"seq":1','"seq":7'));
  assert.throws(()=>readLedger(ledger),/signature/);
}));

test('external checkpoint mismatch blocks guarded operations before execution',async()=>fixture(async({file})=>{
  const {guardedToolCall}=await import('../src/monitor.mjs');
  const local=new AuditStore(file);
  local.add(event('first'));
  const trusted=exportReceipt(local);
  const external=file+'.independent-receipt.json';
  writeFileSync(external,JSON.stringify(trusted)+'\n');
  const guarded=new AuditStore(file,{externalReceiptFile:external});
  const forgedRaw=JSON.stringify(event('rewritten'));
  const key=local.keyUnsafe(),prev='0'.repeat(64);
  const mac=actualHmac('sha256',key).update(JSON.stringify({version:1,seq:1,prev,raw:forgedRaw}), 'utf8').digest('hex');
  writeFileSync(file,forgedRaw+'\n');
  writeFileSync(local.macFile,JSON.stringify({seq:1,prev,mac})+'\n');
  writeFileSync(local.anchorFile,JSON.stringify({seq:1,mac})+'\n');
  assert.equal(local.verify().ok,true);
  assert.throws(()=>new AuditStore(file,{externalReceiptFile:external}),/CHECKPOINT FORK/);
  let executed=false;
  await assert.rejects(()=>guardedToolCall({
    agentId:'adversary',runId:'rollback',tool:'file.read',args:{path:'notes.txt'},
    store:guarded,workspaceRoot:dirname(file),
    execute:async()=>{executed=true;return {value:'unsafe'};}
  }),/CHECKPOINT FORK/);
  assert.equal(executed,false);
}));
