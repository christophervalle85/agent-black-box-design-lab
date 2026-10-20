import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AuditStore } from '../src/audit.mjs';
const event=i=>({id:'journal-'+i,tool:'file.read',decision:'allow',runId:'journal-test'});
const fixture=fn=>{const dir=mkdtempSync(join(tmpdir(),'abb-journal-')),file=join(dir,'audit.jsonl');try{return fn({file,dir});}finally{rmSync(dir,{recursive:true,force:true});}};
for(const phase of ['pending','audit','mac','checkpoint']){
  test('journal restart recovers interruption after '+phase,()=>fixture(({file})=>{
    const first=new AuditStore(file);
    first.add(event('baseline'));
    const crashed=new AuditStore(file,{fault:stage=>{if(stage===phase)throw Error('simulated crash');}});
    assert.throws(()=>crashed.add(event('after-crash')),/simulated crash/);
    assert.equal(existsSync(file+'.pending.json'),true);
    const recovered=new AuditStore(file);
    assert.equal(recovered.verify().records,2);
    assert.equal(recovered.list()[0].id,'journal-after-crash');
    assert.equal(existsSync(file+'.pending.json'),false);
    recovered.add(event('later'));
    assert.equal(new AuditStore(file).verify().records,3);
  }));
}
test('half-written pending audit event is reconstructed only when exact signed prefix matches',()=>fixture(({file})=>{
  const store=new AuditStore(file);
  store.add(event('one'));
  const crashed=new AuditStore(file,{fault:s=>{if(s==='audit')throw Error('crash');}});
  assert.throws(()=>crashed.add(event('two')),/crash/);
  const lines=readFileSync(file,'utf8').split('\n');
  writeFileSync(file,lines[0]+'\n'+lines[1].slice(0,12));
  assert.equal(new AuditStore(file).verify().records,2);
}));
test('journal does not silently repair unrelated audit alteration',()=>fixture(({file})=>{
  const store=new AuditStore(file);
  store.add(event('one'));
  const crashed=new AuditStore(file,{fault:s=>{if(s==='pending')throw Error('crash');}});
  assert.throws(()=>crashed.add(event('two')),/crash/);
  writeFileSync(file,readFileSync(file,'utf8').replace('journal-one','journal-evil'));
  assert.throws(()=>new AuditStore(file),/RECOVERY REQUIRED/);
}));
test('forged pending transaction triggers quarantine not automatic recovery',()=>fixture(({file})=>{
  const store=new AuditStore(file);
  store.add(event('one'));
  const crashed=new AuditStore(file,{fault:s=>{if(s==='pending')throw Error('crash');}});
  assert.throws(()=>crashed.add(event('two')),/crash/);
  const pending=file+'.pending.json';
  writeFileSync(pending,readFileSync(pending,'utf8').replace('journal-two','journal-evil'));
  assert.throws(()=>new AuditStore(file),/RECOVERY REQUIRED/);
}));
