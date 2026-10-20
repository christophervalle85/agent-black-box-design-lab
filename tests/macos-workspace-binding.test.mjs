import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,rmSync,symlinkSync,chmodSync,readFileSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {validateMacWorkspaceBinding} from '../src/macos-workspace-binding.mjs';

function fixture(run) {
 const base=realpathSync(mkdtempSync(join(tmpdir(),'bb-mac-authority-')));
 try {
  const root=join(base,'Library','Containers','dev.agentblackbox.xpc-authority.worker',
    'Data','Documents','AgentBlackBoxScratchNotes');
  mkdirSync(root,{recursive:true,mode:0o700});
  chmodSync(root,0o700);
  const unrelated=join(base,'demo-workspace');
  mkdirSync(unrelated,{mode:0o700});
  return run({base,root,unrelated});
 }finally{rmSync(base,{recursive:true,force:true});}
}

test('matching canonical private roots make an explicit, immutable binding',()=>fixture(({root})=>{
 const value=validateMacWorkspaceBinding({configuredRoot:root,reportedRoot:root,platform:'darwin'});
 assert.equal(value.matched,true);assert.equal(value.workerRoot,root);
 assert.equal(Object.isFrozen(value),true);
}));
test('policy workspace and XPC storage mismatch is a fatal denial',()=>fixture(({root,unrelated})=>{
 assert.throws(()=>validateMacWorkspaceBinding({
  configuredRoot:unrelated,reportedRoot:root,platform:'darwin'
 }),/differ/);
}));
test('workspace authority rejects missing roots, non-Mac OS, wrong container',()=>fixture(({root,unrelated})=>{
 for(const supplied of [
  {configuredRoot:undefined,reportedRoot:root},
  {configuredRoot:root,reportedRoot:undefined},
  {configuredRoot:'relative',reportedRoot:root},
  {configuredRoot:root,reportedRoot:unrelated},
  {configuredRoot:root+'/',reportedRoot:root}
 ])assert.throws(()=>validateMacWorkspaceBinding({...supplied,platform:'darwin'}));
 assert.throws(()=>validateMacWorkspaceBinding({
  configuredRoot:root,reportedRoot:root,platform:'linux'
 }),/requires macOS/);
}));
test('symlinked and group-accessible workspace roots are refused',()=>fixture(({base,root})=>{
 const alias=join(base,'alias');symlinkSync(root,alias);
 assert.throws(()=>validateMacWorkspaceBinding({
  configuredRoot:alias,reportedRoot:root,platform:'darwin'
 }));
 chmodSync(root,0o755);
 assert.throws(()=>validateMacWorkspaceBinding({
  configuredRoot:root,reportedRoot:root,platform:'darwin'
 }),/not be group/);
}));
test('production macOS required mode remains fail-closed during authority experiment',()=>{
 const existing=readFileSync(new URL('../src/sandbox.mjs',import.meta.url),'utf8');
 assert.match(existing,/if\(platform!==['"]linux['"]\) throw Error/);
});
