import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,rmSync,symlinkSync,chmodSync,writeFileSync,
  readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {
  enrollMacControllerPublicPin,assertMacControllerEnrolledPin,
  macControllerPinPath
} from '../src/macos-controller-pin.mjs';

const run=fn=>{
  const dir=mkdtempSync(join(tmpdir(),'bbx-controller-pin-'));
  const file=join(dir,'trust','controller.sha256');
  try{fn({dir,file});}
  finally{rmSync(dir,{recursive:true,force:true});}
};
test('enrollment pins exact fingerprint outside Keychain and refuses replacement',()=>run(
  ({file})=>{
    const first='a'.repeat(64),replacement='b'.repeat(64);
    assert.equal(enrollMacControllerPublicPin(first,{file}),true);
    assert.equal(assertMacControllerEnrolledPin(first,{file}),true);
    assert.equal(readFileSync(file,'ascii'),first+'\n');
    assert.throws(()=>enrollMacControllerPublicPin(replacement,{file}));
    assert.throws(()=>assertMacControllerEnrolledPin(replacement,{file}),
      /identity changed/);
    for(const malformed of ['',null,undefined,'A'.repeat(64),'a'.repeat(63)])
      assert.throws(()=>assertMacControllerEnrolledPin(malformed,{file}));
  }
));
test('symlinks and loose pin permissions fail closed',()=>run(({dir,file})=>{
  const expected='f'.repeat(64);
  enrollMacControllerPublicPin(expected,{file});
  chmodSync(file,0o644);
  assert.throws(()=>assertMacControllerEnrolledPin(expected,{file}),
    /permissions/);
  chmodSync(file,0o600);
  const link=join(dirname(file),'link.sha256');
  symlinkSync(file,link);
  assert.throws(()=>assertMacControllerEnrolledPin(expected,{file:link}));
  chmodSync(dirname(file),0o755);
  assert.throws(()=>assertMacControllerEnrolledPin(expected,{file}),
    /trust directory/);
}));
test('absent or corrupted enrollment cannot be manufactured by inspection',()=>run(
  ({file})=>{
    const expected='1'.repeat(64);
    assert.throws(()=>assertMacControllerEnrolledPin(expected,{file}));
    mkdirSync(dirname(file),{mode:0o700});
    writeFileSync(file,'not-a-pin\n',{mode:0o600});
    assert.throws(()=>assertMacControllerEnrolledPin(expected,{file}),
      /Malformed/);
  }
));
test('trust path is platform-local and never a repository-relative secret',()=>{
  const root='/Users/example';
  assert.ok(macControllerPinPath(root).startsWith(root+'/Library/Application Support/'));
  assert.ok(macControllerPinPath(root).endsWith('test-controller-rsa.sha256'));
});
