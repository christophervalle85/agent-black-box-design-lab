/**
 * Auditable JSONL with a separate HMAC-SHA256 sequence chain and checkpoint.
 * Plain JSONL remains unchanged for prior API and dashboard compatibility.
 * This detects uncoordinated edits/truncation; it does NOT withstand an
 * attacker with access to the secret key + checkpoint or privileged OS access.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  constants, mkdirSync, rmdirSync, existsSync, lstatSync, statSync, readFileSync,
  openSync, closeSync, writeSync, fsyncSync, renameSync, unlinkSync, chmodSync, copyFileSync
} from 'node:fs';
import { dirname } from 'node:path';
import { EventEmitter } from 'node:events';
import { groupAuditEvents, filterActivity } from './activity.mjs';
import { appendJournaled, finishPending } from './audit-journal.mjs';
import { assertExternalReceipt } from './checkpoints.mjs';

const MAX_BYTES = 64 * 1024 * 1024;
const ZERO = '0'.repeat(64);
const sleep = new Int32Array(new SharedArrayBuffer(4));
function assertFile(path) {
  if (existsSync(path)) {
    const s = lstatSync(path);
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1) throw new Error(`Unsafe audit storage path: ${path}`);
  }
}
function rows(content) {
  if (content && !content.endsWith('\n')) throw new Error('Incomplete audit record; refusing to continue.');
  return content ? content.slice(0, -1).split('\n') : [];
}
function readBounded(path) {
  assertFile(path);
  if (!existsSync(path)) return '';
  if (statSync(path).size > MAX_BYTES) throw new Error('Audit storage reached maximum supported size.');
  return readFileSync(path, 'utf8');
}
function appendDurable(path, line) {
  assertFile(path);
  const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  try {
    const data = Buffer.from(line + '\n');
    let at = 0;
    while (at < data.length) at += writeSync(fd, data, at, data.length - at);
    fsyncSync(fd);
  } finally { closeSync(fd); }
}
function writeAtomic(path, content) {
  assertFile(path);
  const temp = `${path}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  const fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    const b = Buffer.from(content);
    let at = 0;
    while (at < b.length) at += writeSync(fd, b, at, b.length - at);
    fsyncSync(fd);
  } catch (err) { closeSync(fd); unlinkSync(temp); throw err; }
  closeSync(fd);
  renameSync(temp, path);
  const dirfd = openSync(dirname(path), constants.O_RDONLY);
  try { try { fsyncSync(dirfd); } catch(e) { if(!['EINVAL','ENOTSUP','EISDIR'].includes(e.code))throw e; } } finally { closeSync(dirfd); }
}
function sign(key, seq, prev, raw) {
  return createHmac('sha256', key).update(JSON.stringify({ version: 1, seq, prev, raw }), 'utf8').digest('hex');
}
function safeEqual(a, b) {
  return typeof a === 'string' && typeof b === 'string' && /^[0-9a-f]{64}$/.test(a) && /^[0-9a-f]{64}$/.test(b) && timingSafeEqual(Buffer.from(a,'hex'), Buffer.from(b,'hex'));
}
export class AuditStore extends EventEmitter {
  constructor(filename,{allowLegacySeal=false,fault=null,externalReceiptFile=process.env.MCP_EXTERNAL_RECEIPT_FILE??null}={}) {
    super();
    this.filename = filename;
    this.macFile = `${filename}.mac.jsonl`;
    this.keyFile = `${filename}.hmac.key`;
    this.anchorFile = `${filename}.anchor.json`;
    this.lock = `${filename}.writer.lock`;
    this.pendingFile = `${filename}.pending.json`;
    this.fault = fault;
    this.externalReceiptFile=externalReceiptFile;
    mkdirSync(dirname(filename), { recursive: true, mode: 0o700 });
    for (const file of [filename, this.macFile, this.keyFile, this.anchorFile, this.pendingFile]) assertFile(file);
    this.locked(() => {
      const present = [this.macFile, this.keyFile, this.anchorFile].map(existsSync);
      if (present.some(Boolean) && !present.every(Boolean)) throw new Error('Audit integrity metadata incomplete; refusing to reinitialize.');
      if (!present.some(Boolean)) {
        const original = rows(readBounded(filename));
        for (const line of original) JSON.parse(line);
        if (original.length && !allowLegacySeal) throw Error('Unsealed legacy audit log. Run npm run audit:seal once before starting v0.6.');
        if (original.length) {
          // Preserve bytes before user-authorized trust-on-first-use sealing.
          const backup = filename + '.pre-v06.jsonl';
          if (existsSync(backup)) throw Error('Existing migration backup; stop and review before sealing.');
          copyFileSync(filename, backup, constants.COPYFILE_EXCL);
          chmodSync(backup, 0o600);
        }
        const key = randomBytes(32);
        writeAtomic(this.keyFile, key.toString('hex') + '\n');
        let prev = ZERO;
        const sigs = original.map((raw,i) => {
          const mac = sign(key, i + 1, prev, raw);
          const item = JSON.stringify({seq:i + 1,prev,mac});
          prev = mac;return item;
        });
        writeAtomic(this.macFile, sigs.length ? sigs.join('\n') + '\n' : '');
        writeAtomic(this.anchorFile, JSON.stringify({seq:original.length,mac:prev}) + '\n');
        if (!existsSync(filename)) { const fd=openSync(filename, constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW, 0o600); closeSync(fd); }
      }
      finishPending(this,{sign,safeEqual,appendDurable,writeAtomic});
      this.verifyUnsafe();
      for (const file of [filename, this.macFile, this.keyFile, this.anchorFile]) chmodSync(file, 0o600);
    });
  }
  locked(fn) {
    let acquired = false;
    for (let i=0;i<200;i++) {
      try { mkdirSync(this.lock, {mode:0o700}); acquired=true;break; }
      catch(e) {if(e.code!=='EEXIST')throw e; Atomics.wait(sleep,0,0,10);}
    }
    if (!acquired) throw Error('Audit writer lock unavailable; refusing to proceed. Verify no writers and investigate stale lock.');
    try { return fn(); } finally { rmdirSync(this.lock); }
  }
  keyUnsafe() {
    const raw = readBounded(this.keyFile).trim();
    if (!/^[a-f0-9]{64}$/.test(raw)) throw Error('Invalid audit integrity key.');
    return Buffer.from(raw,'hex');
  }
  verifyUnsafe({allowPending=false}={}) {
    if(!allowPending && existsSync(this.pendingFile))throw Error('RECOVERY REQUIRED: outstanding authenticated audit transaction. Restart to recover.');
    const content = rows(readBounded(this.filename));
    const signatures = rows(readBounded(this.macFile));
    const checkpoint = JSON.parse(readBounded(this.anchorFile));
    if(content.length !== signatures.length) throw Error('Audit integrity failure: record count differs.');
    const key = this.keyUnsafe();
    let prev=ZERO;
    for(let i=0;i<content.length;i++) {
      const record=JSON.parse(signatures[i]);
      const mac=sign(key,i+1,prev,content[i]);
      if(record.seq!==i+1 || !safeEqual(record.prev,prev) || !safeEqual(record.mac,mac))
        throw Error(`Audit integrity failure at record ${i+1}.`);
      JSON.parse(content[i]);
      prev=mac;
    }
    if(checkpoint.seq!==content.length || !safeEqual(checkpoint.mac,prev))
      throw Error('Audit checkpoint mismatch: records may have been truncated or checkpoint changed.');
    const state={ok:true, records:content.length, head:prev, content};
    if(this.externalReceiptFile){
      const receipt=JSON.parse(readBounded(this.externalReceiptFile));
      assertExternalReceipt(this,receipt,state);
    }
    return state;
  }
  verify() { return this.locked(() => { const {content,...result}=this.verifyUnsafe();return result; }); }
  add(event) {
    this.locked(() => {
      const integrity=this.verifyUnsafe();
      const raw=JSON.stringify(event);
      if(raw.includes('\n'))throw Error('Audit records must remain single-line JSON.');
      const seq=integrity.records+1, mac=sign(this.keyUnsafe(),seq,integrity.head,raw);
      appendJournaled(this,{raw,seq,prev:integrity.head,mac,appendDurable,writeAtomic,fault:this.fault});
    });
    this.emit('event', event);
    return event;
  }
  list({limit=300,decision,runId}={}) {
    const safeLimit=Math.max(1,Math.min(Number(limit)||300,1000));
    return this.locked(()=>{
      const {content}=this.verifyUnsafe();
      const events=[];
      for(let i=content.length-1;i>=0 && events.length<safeLimit;i--){
        const event=JSON.parse(content[i]);
        if(decision && event.decision!==decision)continue;
        if(runId && event.runId!==runId)continue;
        events.push(event);
      }
      return events;
    });
  }
  activity({limit=300,decision,runId}={}) {
    const safeLimit=Math.max(1,Math.min(Number(limit)||300,1000));
    return filterActivity(groupAuditEvents(this.list({limit:1000,runId})),decision).slice(0,safeLimit);
  }
  stats() {
    const events=this.list({limit:1000}),activity=groupAuditEvents(events);
    const count=decision=>activity.filter(x=>x.decision===decision).length;
    return { total:activity.length,auditEvents:events.length,allowed:count('allow'),blocked:count('block'),pending:count('review'),
      errors:activity.filter(x=>x.outcome==='error').length,
      highRisk:activity.filter(x=>x.risk==='high'||x.risk==='critical').length,
      runs:new Set(activity.map(x=>x.runId)).size,
      window:'Tool requests represented in latest 1,000 audit events' };
  }
}
