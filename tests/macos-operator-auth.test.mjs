import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessMacOperatorAuth} from '../examples/mcp-macos-operator-auth.mjs';

const evidence=Object.freeze({
  probe:{status:0,stdout:'BBX_LOCAL_AUTH_AVAILABLE\n',stderr:''},
  approve:{status:0,stdout:'BBX_LOCAL_AUTH_SUCCEEDED\n',stderr:''},
  cancel:{status:83,stdout:'BBX_LOCAL_AUTH_USER_CANCELLED\n',stderr:''},
  'touchid-probe':{status:0,stdout:'BBX_LOCAL_AUTH_TOUCHID_AVAILABLE\n',stderr:''},
  'touchid-approve':{status:0,stdout:'BBX_LOCAL_AUTH_TOUCHID_SUCCEEDED\n',stderr:''},
  'touchid-cancel':{status:83,stdout:'BBX_LOCAL_AUTH_TOUCHID_USER_CANCELLED\n',stderr:''}
});
test('OS-auth success and native user-cancellation require distinct exact evidence',()=>{
  for(const mode of Object.keys(evidence))
    assert.equal(assessMacOperatorAuth(mode,evidence[mode]),true);
  assert.throws(()=>assessMacOperatorAuth('invalid',evidence.probe));
  assert.throws(()=>assessMacOperatorAuth('approve',evidence.cancel));
  assert.throws(()=>assessMacOperatorAuth('cancel',evidence.approve));
  assert.throws(()=>assessMacOperatorAuth('cancel',evidence['touchid-cancel']));
  assert.throws(()=>assessMacOperatorAuth('touchid-cancel',evidence.cancel));
  assert.throws(()=>assessMacOperatorAuth('touchid-cancel',evidence['touchid-approve']));
  assert.throws(()=>assessMacOperatorAuth('touchid-approve',evidence['touchid-cancel']));
  assert.throws(()=>assessMacOperatorAuth('touchid-cancel',{
    status:85,stdout:'BBX_LOCAL_AUTH_TOUCHID_UNEXPECTED_SUCCESS\n',stderr:''
  }));
  assert.throws(()=>assessMacOperatorAuth('touchid-probe',{
    status:88,stdout:'BBX_LOCAL_AUTH_TOUCHID_UNAVAILABLE\n',stderr:''
  }));
  assert.throws(()=>assessMacOperatorAuth('cancel',{
    ...evidence.cancel,status:87,stdout:'BBX_LOCAL_AUTH_DENIED_OR_UNAVAILABLE\n'
  }));
  assert.throws(()=>assessMacOperatorAuth('approve',{
    ...evidence.approve,stdout:'BBX_LOCAL_AUTH_SUCCEEDED\nBBX_LOCAL_AUTH_SUCCEEDED\n'
  }));
  assert.throws(()=>assessMacOperatorAuth('probe',{
    ...evidence.probe,stderr:'OS authentication mocked\n'
  }));
  assert.throws(()=>assessMacOperatorAuth('cancel',{
    ...evidence.cancel,signal:'SIGTERM'
  }));
  assert.throws(()=>assessMacOperatorAuth('approve',{
    ...evidence.approve,error:new Error('timed out')
  }));
  assert.throws(()=>assessMacOperatorAuth('approve'));
});
test('native helper relies on real Apple policy and never a mock approval flag',()=>{
  const source=readFileSync(new URL('../native/macos/LocalOperatorAuthentication.m',import.meta.url),'utf8');
  const harness=readFileSync(new URL('../examples/mcp-macos-operator-auth.mjs',import.meta.url),'utf8');
  const server=readFileSync(new URL('../src/server.mjs',import.meta.url),'utf8');
  assert.match(source,/#import <LocalAuthentication\/LocalAuthentication\.h>/);
  assert.match(source,/const LAPolicy policy=touchIDOnly/);
  assert.match(source,/canEvaluatePolicy:policy/);
  assert.match(source,/evaluatePolicy:policy/);
  assert.match(source,/LAErrorUserCancel/);
  assert.match(source,/LAPolicyDeviceOwnerAuthenticationWithBiometrics/);
  assert.match(source,/touchIDOnly\?/);
  assert.match(source,/BBX_LOCAL_AUTH_TOUCHID_UNEXPECTED_SUCCESS/);
  assert.match(source,/BBX_LOCAL_AUTH_TOUCHID_UNAVAILABLE/);
  assert.match(harness,/touchid-cancel/);
  assert.match(source,/touchIDAuthenticationAllowableReuseDuration=0/);
  assert.match(source,/dispatch_semaphore_wait/);
  assert.match(source,/BBX_LOCAL_AUTH_TIMED_OUT/);
  assert.match(harness,/process\.env\.MCP_SANDBOX!=='off'/);
  assert.match(harness,/process\.platform!=='darwin'/);
  assert.match(harness,/--verify','--strict'/);
  assert.match(harness,/run\(executable,\[mode\]/);
  assert.match(harness,/NOTE: OS identity is not bound/);
  assert.doesNotMatch(server,/LocalOperatorAuthentication|mcp-macos-operator-auth/);
});
