import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, unlinkSync, chmodSync, symlinkSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditStore } from '../src/audit.mjs';

function fixture(fn){
  const dir=mkdtempSync(join(tmpdir(),'blackbox-integrity-'));
  const file=join(dir,'audit.jsonl');
  try{return fn({dir,file});}finally{rmSync(dir,{recursive:true,force:true});}
}
const event=i=>({id:`id-${i}`,timestamp:'2026-10-12T00:00:00.000Z',runId:'test',decision:'allow',tool:'file.read',outcome:'success'});

test('HMAC audit chain verifies after restart and retains plain JSONL',()=>fixture(({file})=>{
  const first=new AuditStore(file);
  first.add(event(1));first.add(event(2));
  assert.deepEqual(first.list().map(e=>e.id),['id-2','id-1']);
  assert.equal(first.verify().records,2);
  assert.deepEqual(JSON.parse(readFileSync(file,'utf8').split('\n')[0]),event(1));
  const second=new AuditStore(file);
  assert.equal(second.verify().records,2);
  second.add(event(3));
  assert.equal(first.verify().records,3);
  for(const p of [file,first.macFile,first.keyFile,first.anchorFile])assert.equal(statSync(p).mode&0o777,0o600);
}));

test('modification of record is detected and prevents new appends',()=>fixture(({file})=>{
  const store=new AuditStore(file);store.add(event(1));
  writeFileSync(file,readFileSync(file,'utf8').replace('file.read','shell.exec'));
  assert.throws(()=>store.verify(),/integrity failure/i);
  assert.throws(()=>store.add(event(2)),/integrity failure/i);
}));

test('truncation and checkpoint rollback are detected',()=>fixture(({file})=>{
  const store=new AuditStore(file);store.add(event(1));store.add(event(2));
  writeFileSync(file,readFileSync(file,'utf8').split('\n')[0]+'\n');
  assert.throws(()=>new AuditStore(file),/integrity failure/i);
}));

test('missing secret, signature or checkpoint is fatal, not silently recreated',()=>fixture(({file})=>{
  const store=new AuditStore(file);store.add(event(1));
  unlinkSync(store.keyFile);
  assert.throws(()=>new AuditStore(file),/metadata incomplete/i);
}));

test('unsealed historical records require explicit one-time migration and backup',()=>fixture(({file})=>{
  writeFileSync(file,JSON.stringify(event(1))+'\n');
  assert.throws(()=>new AuditStore(file),/Unsealed legacy audit/);
  const store=new AuditStore(file,{allowLegacySeal:true});
  assert.equal(store.verify().records,1);
  assert.deepEqual(JSON.parse(readFileSync(file+'.pre-v06.jsonl','utf8')),event(1));
  store.add(event(2));
  assert.equal(new AuditStore(file).verify().records,2);
}));

test('malformed legacy data does not get sealed',()=>fixture(({file})=>{
  writeFileSync(file,'not-json\n');
  assert.throws(()=>new AuditStore(file,{allowLegacySeal:true}));
}));

test('symlinked audit log is rejected before key or log creation',()=>fixture(({dir,file})=>{
  const elsewhere=join(dir,'other');writeFileSync(elsewhere,'');symlinkSync(elsewhere,file);
  assert.throws(()=>new AuditStore(file),/Unsafe audit storage path/);
}));

test('different store instances serialize writes rather than overwriting chain head',()=>fixture(({file})=>{
  const a=new AuditStore(file),b=new AuditStore(file);
  for(let i=0;i<24;i++)(i%2?a:b).add(event(i));
  assert.equal(new AuditStore(file).verify().records,24);
}));

test('locked audit refuses to proceed and fails closed',()=>fixture(({file})=>{
  const store=new AuditStore(file);store.add(event(1));
  writeFileSync(store.anchorFile,JSON.stringify({seq:0,mac:'0'.repeat(64)})+'\n');
  assert.throws(()=>store.list(),/checkpoint mismatch/i);
}));

test('independent Node processes coordinate HMAC appends without chain corruption',async()=>{
  const { spawn }=await import('node:child_process');
  const { once }=await import('node:events');
  const { pathToFileURL }=await import('node:url');
  const dir=mkdtempSync(join(tmpdir(),'blackbox-audit-processes-'));
  const file=join(dir,'audit.jsonl');
  const module=pathToFileURL(new URL('../src/audit.mjs',import.meta.url).pathname).href;
  try {
    new AuditStore(file);
    const worker=`import {AuditStore} from ${JSON.stringify(module)}; const store=new AuditStore(process.argv[1]); for(let i=0;i<12;i++) store.add({id:process.argv[2]+'-'+i,decision:'allow',runId:process.argv[2],tool:'file.read'});`;
    const children=['A','B','C'].map(label=>spawn(process.execPath,['--input-type=module','-e',worker,file,label],{stdio:['ignore','ignore','pipe']}));
    const outcomes=await Promise.all(children.map(async child=>{
      const chunks=[]; child.stderr.on('data',d=>chunks.push(d));
      const [exit]=await once(child,'exit');
      return {exit,errors:Buffer.concat(chunks).toString('utf8')};
    }));
    assert.ok(outcomes.every(x=>x.exit===0),JSON.stringify(outcomes));
    assert.equal(new AuditStore(file).verify().records,36);
  } finally {rmSync(dir,{recursive:true,force:true});}
});

test('tampering after initialization stops a guarded adapter before execution',async()=>{
  const {guardedToolCall}=await import('../src/monitor.mjs');
  return fixture(async({file,dir})=>{
    const store=new AuditStore(file);store.add(event(1));
    writeFileSync(file,readFileSync(file,'utf8').replace('file.read','shell.exec'));
    let executed=false;
    await assert.rejects(()=>guardedToolCall({
      agentId:'test',runId:'r',tool:'file.read',args:{path:'notes.txt'},store,workspaceRoot:dir,
      execute:async()=>{executed=true;return {value:'unsafe'};}
    }),/integrity failure/i);
    assert.equal(executed,false);
  });
});
