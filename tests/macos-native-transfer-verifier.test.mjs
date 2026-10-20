import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {
  assessNativeMacTransferTouchId,evaluateNativeMacTransferTouchId
} from '../src/macos-native-transfer-verifier.mjs';
import {createMacTransferIntent} from '../src/macos-transfer-intent.mjs';

const now=1_790_000_000_000;
function review(){
  const intent=createMacTransferIntent({
    operation:'import',noteName:'bbx-test-review-auth.txt',
    bytes:Buffer.from('test-only content\n'),now
  });
  return Object.freeze({
    reviewId:'12345678-1234-4abc-8abc-123456789abc',
    intent,decision:'approve'
  });
}
function success(r){
  return {status:0,signal:null,stderr:'',stdout:
    'BBX_TRANSFER_TOUCHID_AUTHENTICATED '+r.reviewId+' '+
    r.intent.nonce+' '+r.intent.sha256+' '+r.intent.operation+' '+
    r.intent.noteName+' '+r.intent.byteLength+'\n'};
}
function cancelled(r){
  return {status:83,signal:null,stderr:'',stdout:
    'BBX_TRANSFER_TOUCHID_USER_CANCELLED '+r.reviewId+' '+
    r.intent.nonce+' '+r.intent.sha256+' '+r.intent.operation+' '+
    r.intent.noteName+' '+r.intent.byteLength+'\n'};
}
test('real-native review receipt requires matching review ID, intent nonce and full digest',()=>{
  const r=review();
  assert.equal(assessNativeMacTransferTouchId(r,success(r),{now}),
    'authenticated');
  assert.equal(assessNativeMacTransferTouchId(r,cancelled(r),{now}),
    'cancelled');
  const changed=review();
  for(const bad of [
    {...success(r),stdout:success(r).stdout.replace(r.intent.sha256,'0'.repeat(64))},
    {...success(r),stdout:success(r).stdout.replace(r.reviewId,'12345678-1234-4abc-8abc-123456789abd')},
    {...success(r),stdout:success(r).stdout.replace(r.intent.nonce,'12345678-1234-4abc-8abc-123456789abd')},
    {...success(r),stderr:'test helper noisy\n'},
    {...success(r),signal:'SIGTERM'},
    {...success(r),status:87},
    {...success(r),stdout:'BBX_TRANSFER_AUTH_DENIED\n',status:87},
    {...cancelled(r),status:0},
    {status:84,stdout:'BBX_TRANSFER_AUTH_TIMED_OUT\n',stderr:''}
  ])assert.throws(()=>assessNativeMacTransferTouchId(r,bad,{now}));
  assert.equal(changed.intent.noteName,r.intent.noteName);
  assert.throws(()=>assessNativeMacTransferTouchId(r,success(r),
    {now:r.intent.expiresAt}),/expired/);
  assert.throws(()=>assessNativeMacTransferTouchId({...r,decision:'deny'},
    success(r),{now}));
  assert.throws(()=>assessNativeMacTransferTouchId({
    ...r,intent:{...r.intent,noteName:'bbx-test-evil.txt'}
  },success(r),{now}));
  assert.throws(()=>assessNativeMacTransferTouchId({
    ...r,sourcePath:'/Users/operator/confidential'
  },success(r),{now}));
  assert.throws(()=>assessNativeMacTransferTouchId(r,null,{now}));
});
test('review verifier cannot claim Linux mock callbacks are native macOS OS evidence',async()=>{
  // Keep the fixture's original issuance clock: the purpose of this test
  // is platform/native helper evidence, not the intentionally short expiry.
  await assert.rejects(()=>evaluateNativeMacTransferTouchId(review(),{
    executable:'/tmp/not-a-native-auth-fixture',now:()=>now
  }),process.platform==='darwin'?/Native Touch ID helper failed/:/Real macOS required/);
});
test('real macOS helper uses biometric-only policy, an exact review and no arbitrary paths',()=>{
  const native=readFileSync(new URL(
    '../native/macos/TransferReviewAuthenticator.m',import.meta.url),'utf8');
  const harness=readFileSync(new URL(
    '../examples/mcp-macos-transfer-touchid.mjs',import.meta.url),'utf8');
  assert.match(native,/LAPolicyDeviceOwnerAuthenticationWithBiometrics/);
  assert.match(native,/evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics/);
  assert.match(native,/LAErrorUserCancel/);
  assert.match(native,/uuid4\(argv\[1\]\)/);
  assert.match(native,/uuid4\(argv\[6\]\)/);
  assert.match(native,/hexlower\(argv\[5\],64\)/);
  assert.match(native,/BBX_TRANSFER_TOUCHID_AUTHENTICATED/);
  assert.match(native,/BBX_TRANSFER_TOUCHID_USER_CANCELLED/);
  assert.match(harness,/process\.env\.MCP_SANDBOX!=='off'/);
  assert.match(harness,/--verify','--strict'/);
  assert.match(harness,/createAuditedMacTransferController/);
  assert.match(harness,/MAC_TRANSFER_CONSUMED/);
  assert.match(harness,/mode==='cancel'/);
  assert.doesNotMatch(native,/(?:open\(|fopen\(|fwrite\(|system\(|popen\()/);
});
