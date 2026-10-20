import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assessNativeMacSnapshot} from '../examples/mcp-macos-selected-snapshot.mjs';

const digest=s=>createHash('sha256').update(Buffer.from(s,'utf8')).digest('hex');
const expected=digest('BBX synthetic fd snapshot test\n');
const altered=digest('CBX synthetic fd snapshot test\n');
const size=Buffer.byteLength('BBX synthetic fd snapshot test\n');
const healthy=(d=expected)=>({
  status:0,signal:null,error:null,stderr:'',
  stdout:'BBX_SNAPSHOT_READ '+size+' '+d+'\n'
});
const fields=(stagedDigest=expected)=>({
  expectedDigest:expected,stagedDigest,byteLength:size
});

test('native fd snapshot requires exact expected content and separate altered-file denial',()=>{
  assert.equal(assessNativeMacSnapshot('select',healthy(),fields()),
    'exact synthetic snapshot');
  assert.equal(assessNativeMacSnapshot('altered',healthy(altered),fields(altered)),
    'modified synthetic snapshot rejected');
  assert.throws(()=>assessNativeMacSnapshot('select',healthy(altered),fields(altered)),
    /digest changed/);
  assert.throws(()=>assessNativeMacSnapshot('altered',healthy(),fields()),
    /unexpectedly matched/);
  assert.throws(()=>assessNativeMacSnapshot('altered',healthy(),
    fields(altered)),/differs/);
  assert.throws(()=>assessNativeMacSnapshot('select',healthy(altered),
    fields()),/differs/);
  assert.throws(()=>assessNativeMacSnapshot('unknown',healthy(),fields()));
});

test('native fd receipt rejects incorrect bytes, forged metadata and abnormal process outcomes',()=>{
  const valid=healthy();
  for(const invalid of [
    {...valid,status:83,stdout:'BBX_SNAPSHOT_USER_CANCELLED\n'},
    {...valid,status:87,stdout:'BBX_SNAPSHOT_WRONG_FILE\n'},
    {...valid,status:0,stdout:'BBX_SNAPSHOT_READ 999 '+expected+'\n'},
    {...valid,stdout:'BBX_SNAPSHOT_READ '+size+' '+expected.toUpperCase()+'\n'},
    {...valid,stdout:'BBX_SNAPSHOT_READ '+size+' '+expected+'\nextra\n'},
    {...valid,stdout:'BBX_SNAPSHOT_READ '+size+' '+expected+' /Users/private\n'},
    {...valid,stderr:'native path leakage\n'},
    {...valid,signal:'SIGKILL'},
    {...valid,error:new Error('timed out')},
    {...valid,status:null}
  ])assert.throws(()=>assessNativeMacSnapshot('select',invalid,fields()));
  for(const bad of [
    {...fields(),expectedDigest:'x'.repeat(64)},
    {...fields(),stagedDigest:'a'},
    {...fields(),byteLength:0},
    {...fields(),byteLength:2001},
    {...fields(),byteLength:1.5}
  ])assert.throws(()=>assessNativeMacSnapshot('select',valid,bad));
  assert.throws(()=>assessNativeMacSnapshot('select',null,fields()));
});

test('native selected-file snapshot requires fd identity, bounded read and content-free stdout',()=>{
  const native=readFileSync(new URL(
    '../native/macos/SelectedFileSnapshot.m',import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../examples/mcp-macos-selected-snapshot.mjs',import.meta.url),'utf8');
  assert.match(native,/#import <CommonCrypto\/CommonDigest\.h>/);
  assert.match(native,/#define __STDC_WANT_LIB_EXT1__ 1/);
  assert.match(native,/#include <string\.h>/);
  assert.match(native,/memset_s\(buffer,count,0,count\)/);
  assert.match(native,/secure_wipe\(buffer,sizeof\(buffer\)\)/);
  assert.doesNotMatch(native,/explicit_bzero\(/);
  assert.match(runner,/-Werror=implicit-function-declaration/);
  assert.match(native,/NSOpenPanel \*panel=\[NSOpenPanel openPanel\]/);
  assert.match(native,/O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC\|O_NONBLOCK/g);
  assert.match(native,/fstat\(fd,out\)/);
  assert.match(native,/a->st_dev==b->st_dev/);
  assert.match(native,/a->st_ino==b->st_ino/);
  assert.match(native,/out->st_nlink==1/);
  assert.match(native,/out->st_uid==geteuid\(\)/);
  assert.match(native,/out->st_size<=BBX_SNAPSHOT_MAX/);
  assert.match(native,/read\(fd,buffer\+offset,count-offset\)/);
  assert.match(native,/read\(fd,&extra,1\)/);
  assert.match(native,/CC_SHA256\(buffer/);
  assert.match(native,/before\.st_mtimespec/);
  assert.match(native,/BBX_SNAPSHOT_WRONG_FILE/);
  assert.match(native,/BBX_SNAPSHOT_CHANGED_OR_UNREADABLE/);
  assert.match(native,/printf\("BBX_SNAPSHOT_READ %zu "/);
  assert.doesNotMatch(native,/fopen\(|fwrite\(|write\(|system\(|popen\(/);
  assert.match(runner,/process\.platform!=='darwin'/);
  assert.match(runner,/process\.env\.MCP_SANDBOX!=='off'/);
  assert.match(runner,/--verify','--strict'/);
  assert.match(runner,/if\(mode==='altered'\)staged\[0\]\^=1/);
  assert.match(runner,/timingSafeEqual/);
  assert.match(runner,/rmSync\(temp,\{recursive:true,force:true\}\)/);
  assert.doesNotMatch(runner,/createBlackBoxServer|createAuditedMacTransferController/);
});
