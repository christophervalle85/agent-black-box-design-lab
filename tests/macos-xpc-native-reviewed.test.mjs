import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessNativeReviewedXpc} from '../examples/mcp-macos-xpc-native-reviewed.mjs';

const marker={
  approved:'BBX_REVIEWED_XPC_TOUCHID_APPROVED_TAMPER_REPLAY_BLOCKED\n',
  cancel:'BBX_REVIEWED_XPC_CANCELLED_NO_DISPATCH\n',
  expired:'BBX_REVIEWED_XPC_EXPIRED_NO_DISPATCH\n',
  'handoff-invalid':'BBX_REVIEWED_XPC_INVALID_HANDOFF_NO_AUTH_NO_XPC\n',
  'handoff-approved':'BBX_REVIEWED_XPC_PREISSUED_TOUCHID_ACCEPTED\n',
  'handoff-rsa-invalid':'BBX_REVIEWED_XPC_INVALID_RSA_HANDOFF_NO_AUTH_NO_XPC\n',
  'handoff-rsa-approved':'BBX_REVIEWED_XPC_RSA_PREISSUED_TOUCHID_ACCEPTED\n',
  'handoff-rsa-durable-invalid':'BBX_REVIEWED_XPC_INVALID_DURABLE_RSA_HANDOFF_NO_AUTH_NO_XPC\n',
  'handoff-rsa-durable-approved':'BBX_REVIEWED_XPC_RSA_DURABLE_TOUCHID_ACCEPTED\n',
  'handoff-rsa-durable-replay':'BBX_REVIEWED_XPC_DURABLE_REPLAY_REJECTED\n',
  'handoff-rsa-durable-restart':'BBX_REVIEWED_XPC_WORKER_RESTART_REPLAY_DENIED\n',
  'handoff-rsa-crash-before':'BBX_REVIEWED_XPC_CRASH_BEFORE_NO_MARKER_NO_RETRY\n',
  'handoff-rsa-crash-after':'BBX_REVIEWED_XPC_CRASH_AFTER_SPENT_NO_ACK_NO_RETRY\n'
};
const good=mode=>({stdout:marker[mode],stderr:'',status:0,
  signal:null,error:null});
test('native reviewed XPC mode-specific evidence is exact and fail-closed',()=>{
  for(const mode of Object.keys(marker)){
    assert.equal(assessNativeReviewedXpc(mode,good(mode)),true);
    for(const invalid of [
      {...good(mode),status:87},
      {...good(mode),status:null},
      {...good(mode),signal:'SIGKILL'},
      {...good(mode),error:new Error('spawn failed')},
      {...good(mode),stdout:marker[mode]+'extra'},
      {...good(mode),stderr:'sensitive debug'},
      ...Object.keys(marker).filter(x=>x!==mode).map(good)
    ])assert.throws(()=>assessNativeReviewedXpc(mode,invalid));
  }
  assert.throws(()=>assessNativeReviewedXpc('approve',good('approved')));
  assert.throws(()=>assessNativeReviewedXpc('approved',null));
});
test('native host owns authentication and worker validates exact reviewed receipt',()=>{
  const host=readFileSync(new URL(
    '../native/macos/xpc/ReviewedTransferHost.m',import.meta.url),'utf8');
  const worker=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptService.m',import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../examples/mcp-macos-xpc-native-reviewed.mjs',import.meta.url),'utf8');
  for(const requirement of [
    'LAPolicyDeviceOwnerAuthenticationWithBiometrics',
    'touchIDAuthenticationAllowableReuseDuration=0',
    '[context evaluatePolicy:policy',
    'LAErrorUserCancel',
    'reviewIsExact(&review)',
    'BBX_REVIEWED_XPC_CANCELLED_NO_DISPATCH',
    'BBX_REVIEWED_XPC_EXPIRED_NO_DISPATCH',
    'BBX_REVIEWED_XPC_TOUCHID_APPROVED_TAMPER_REPLAY_BLOCKED',
    'bbx_install_same_team_peer_requirement(peer,serviceID)',
    'statusIs(peer,&review,changed,sizeof(changed)',
    '"BAD_REQUEST","bad-transaction-id"',
    '"BAD_REQUEST","bad-version"',
    '"BAD_REQUEST","bad-note"',
    '"BAD_REQUEST","bad-nonce"',
    '"ACCEPTED",NULL)',
    '"REPLAY",NULL)',
    'xpc_dictionary_set_uint64(request,"version",BBX_REVIEWED_VERSION)',
    'xpc_dictionary_set_string(request,"transactionId",review->transactionId)',
    'randomUuid4(review->nonce)',
    'randomUuid4(review->reviewId)',
    'memset_s(changed'
  ])assert.ok(host.includes(requirement),requirement);
  assert.ok(host.includes('const NativeReview committed=review;'));
  assert.ok(host.includes('memcmp(&review,&committed,sizeof(review))!=0'));
  const auth=host.indexOf('const int auth=authenticateReview(&review);');
  const connect=host.indexOf('xpc_connection_t peer=openWorker();',auth);
  assert.ok(auth>0 && connect>auth);
  assert.ok(host.includes('if(auth!=0)'));
  for(const prohibited of ['open(', 'openat(', 'fopen(', 'unlink(', 'system(', 'popen('])
    assert.equal(host.includes(prohibited),false,prohibited);
  for(const requirement of [
    '#ifdef BBX_TEST_NATIVE_REVIEWED_RECEIPT',
    'return valid && count==12',
    'strcmp(method,"reviewed_snapshot_receipt")',
    'statedSize!=count',
    'bbx_reviewed_transaction_id(',
    'bbx_reviewed_equal_hash(expectedId,transactionId)',
    'now<issued || now>=expires',
    'xpc_dictionary_get_uint64(message,"version")',
    'xpc_dictionary_get_string(message,"transactionId")',
    'DIGEST_MISMATCH','REPLAY'
  ])assert.ok(worker.includes(requirement),requirement);
  for(const requirement of [
    "'--identifier',WORKER_ID","'--identifier',HOST_ID",
    'if(signingTeam(app,HOST_ID)!==signingTeam(service,WORKER_ID))',
    'verifyWorkerSandbox(service)',
    "MCP_SANDBOX!=='off'",
    'rmSync(temp,{recursive:true,force:true})'
  ])assert.ok(runner.includes(requirement),requirement);
  assert.ok(runner.includes("mode==='all'?['expired','approved','cancel']:[mode]"));
  assert.ok(runner.includes('for(const check of checks)'));
  assert.ok(runner.includes('assessNativeReviewedXpc(check,outcome)'));
  assert.ok(runner.includes("INSTRUCTION: At the native Touch ID prompt, choose Cancel"));
  assert.ok(!runner.includes('createBlackBoxServer'));
  assert.ok(runner.includes('createAuditedMacTransferController'));
  assert.ok(runner.includes('MAC_TRANSFER_DISPATCH_RESERVED'));
  assert.ok(runner.includes('SYNTHETIC_ACCEPTED'));
  assert.ok(runner.includes("const approveMode=crashPhase?'handoff-rsa-crash-'+crashPhase:"));
  assert.ok(runner.includes("const invalidMode=durable?'handoff-rsa-durable-invalid':"));
  assert.ok(runner.includes('await auditedHandoff(host,temp,{'));
  assert.ok(runner.includes('privateKey:signer?.privateKey??null,signController,'));
  assert.ok(runner.includes('durable,restart,crashPhase'));
  assert.ok(runner.includes("'BBX_REVIEWED_XPC_PREISSUED_TOUCHID_ACCEPTED"));
  assert.ok(host.includes('#ifdef BBX_TEST_EXTERNAL_REVIEW_HANDOFF'));
  assert.ok(host.includes('bbx_read_preissued_review(stdin,&preissued)'));
  assert.ok(host.indexOf('const bool valid=importPreissuedReview(&review);') <
    host.indexOf('const int auth=authenticateReview(&review);'));
  assert.ok(host.includes('BBX_REVIEWED_XPC_INVALID_HANDOFF_NO_AUTH_NO_XPC'));
  assert.ok(host.includes('bbx_read_signed_preissued_review(stdin,&preissued)'));
  assert.ok(host.includes('#ifdef BBX_TEST_RSA_CONTROLLER_HANDOFF'));
  assert.ok(host.indexOf('importSignedPreissuedReview(&review)') <
    host.indexOf('const int auth=authenticateReview(&review);'));
  assert.ok(runner.includes('formatPinnedMacRsaPublicHeader(signer.publicKey)'));
  assert.ok(runner.includes('reservationMac:store.verify().head'));
  assert.ok(runner.includes("mode==='handoff-rsa'||durable"));
  assert.ok(runner.includes("const durable=mode==='handoff-rsa-durable'"));
  assert.ok(runner.includes('signedCommittedWire=Buffer.from(wire)'));
  assert.ok(runner.includes("['handoff-rsa-durable-replay']"));
  assert.ok(runner.includes("assessNativeReviewedXpc('handoff-rsa-durable-replay',replay)"));
  assert.ok(host.includes('BBX_REVIEWED_XPC_DURABLE_REPLAY_REJECTED'));
  assert.ok(host.includes('"REPLAY",NULL)'));
  assert.ok(worker.includes('BBX_TEST_DURABLE_REPLAY'));
  assert.ok(worker.includes('bbx_reviewed_replay_reserve('));
});

test('controlled worker restart proves old PID exited and a new signed worker denied replay',()=>{
  const host=readFileSync(new URL(
    '../native/macos/xpc/ReviewedTransferHost.m',import.meta.url),'utf8');
  const worker=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptService.m',import.meta.url),'utf8');
  const restart=readFileSync(new URL(
    '../native/macos/xpc/ReviewedWorkerRestartTest.h',import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../examples/mcp-macos-xpc-native-reviewed.mjs',import.meta.url),'utf8');
  const ci=readFileSync(new URL(
    '../.github/workflows/ci.yml',import.meta.url),'utf8');
  for(const item of [
    'BBX_TEST_DURABLE_WORKER_RESTART',
    'bbx_test_handle_worker_lifecycle(peer,event)',
    'bbx_test_initialize_worker_instance()'
  ])assert.ok(worker.includes(item),item);
  assert.match(restart,/#error "Test worker shutdown requires signed-peer-gated durable receipts/);
  assert.match(restart,/arc4random_buf\(randomBytes,sizeof\(randomBytes\)\)/);
  assert.match(restart,/strcmp\(method,"bbx_test_worker_identity"\)/);
  assert.match(restart,/strcmp\(method,"bbx_test_worker_exit"\)/);
  assert.match(restart,/strcmp\(key,"method"\)!=0/);
  assert.match(restart,/count!=1/);
  assert.match(restart,/dispatch_after\(/);
  assert.match(restart,/_exit\(0\)/);
  for(const item of [
    'if(kill((pid_t)before.pid,0)==-1&&errno==ESRCH)',
    'after.pid!=before.pid',
    'strcmp(after.instance,before.instance)!=0',
    'strcmp(before.instance,exitAck.instance)!=0',
    '"REPLAY",NULL)',
    'BBX_REVIEWED_XPC_WORKER_RESTART_REPLAY_DENIED',
    'BBX_REVIEWED_XPC_WORKER_RESTART_NOT_PROVEN',
    'bbx_test_force_restart_and_reject(&review)'
  ])assert.ok(host.includes(item),item);
  assert.ok(host.indexOf('importSignedPreissuedReview(&review)') <
    host.indexOf('bbx_test_force_restart_and_reject(&review)'));
  assert.ok(host.indexOf('bbx_test_force_restart_and_reject(&review)') <
    host.indexOf('const int auth=authenticateReview(&review);'));
  assert.match(runner,/const restart=mode==='handoff-rsa-durable-restart'/);
  assert.match(runner,/assessNativeReviewedXpc\('handoff-rsa-durable-restart',outcome\)/);
  assert.match(runner,/timeout:18000,maxBuffer:1024/);
  assert.match(runner,/if\(restart&&!durable\)throw/);
  assert.match(ci,/ReviewedWorkerRestartHost/);
  assert.match(ci,/ReviewedWorkerRestartWorker/);
  assert.match(ci,/BBX_TEST_DURABLE_WORKER_RESTART=1/);
  assert.doesNotMatch(worker,/kill\s*\(|\bexecl?\s*\(/);
});

test('native crash injection and reconciliation cannot produce a success receipt or retry',()=>{
  const host=readFileSync(new URL(
    '../native/macos/xpc/ReviewedTransferHost.m',import.meta.url),'utf8');
  const worker=readFileSync(new URL(
    '../native/macos/xpc/TransferReceiptService.m',import.meta.url),'utf8');
  const crash=readFileSync(new URL(
    '../native/macos/xpc/ReviewedCrashReconcileTest.h',import.meta.url),'utf8');
  const replay=readFileSync(new URL(
    '../native/macos/xpc/ReviewedDurableReplay.h',import.meta.url),'utf8');
  const runner=readFileSync(new URL(
    '../examples/mcp-macos-xpc-native-reviewed.mjs',import.meta.url),'utf8');
  const ci=readFileSync(new URL(
    '../.github/workflows/ci.yml',import.meta.url),'utf8');
  for(const requirement of [
    '#ifdef BBX_TEST_CRASH_RECONCILE',
    'bbx_test_maybe_crash_receipt(nonce,transactionId,1)',
    'bbx_test_maybe_crash_receipt(nonce,transactionId,2)',
    'bbx_test_handle_crash_reconcile_control(peer,event)'
  ])assert.ok(worker.includes(requirement),requirement);
  assert.ok(worker.indexOf('bbx_test_maybe_crash_receipt(nonce,transactionId,1)') <
    worker.indexOf('bbx_reviewed_replay_reserve('));
  assert.ok(worker.indexOf('bbx_test_maybe_crash_receipt(nonce,transactionId,2)') >
    worker.indexOf('bbx_reviewed_replay_reserve('));
  for(const requirement of [
    'BBX_REPLAY_MATCHING_MARKER',
    'BBX_REPLAY_NO_MARKER',
    'BBX_REPLAY_UNVERIFIABLE',
    'O_RDONLY|O_NOFOLLOW|O_CLOEXEC',
    'S_ISREG(fileStat.st_mode)',
    'fileStat.st_nlink==1',
    'memcmp(observed,expected,(size_t)n)==0',
    'errno==ENOENT'
  ])assert.ok(replay.includes(requirement),requirement);
  assert.match(crash,/bbx_test_arm_receipt_crash/);
  assert.match(crash,/bbx_test_observe_receipt/);
  assert.match(crash,/bbx_test_armed_nonce/);
  assert.match(crash,/bbx_test_armed_txid/);
  assert.match(crash,/bbx_reviewed_replay_observe/);
  assert.match(crash,/_exit\(boundary==1\?91:92\)/);
  assert.match(crash,/count==\(arm\?4U:3U\)/);
  assert.match(crash,/#error "Crash reconciliation requires a signed durable worker restart fixture/);
  for(const requirement of [
    'bbx_test_crash_and_observe(&review',
    'oldExited',
    'errno==ESRCH',
    'restarted.pid!=before.pid',
    'strcmp(restarted.instance,before.instance)!=0',
    'bbx_test_observe_receipt',
    'NO_MARKER',
    'MATCHING_MARKER',
    'BBX_REVIEWED_XPC_CRASH_RECONCILIATION_NOT_PROVEN'
  ])assert.ok(host.includes(requirement),requirement);
  assert.ok(host.indexOf('const int auth=authenticateReview(&review)') <
    host.indexOf('bbx_test_crash_and_observe(&review'));
  for(const requirement of [
    "mode==='handoff-rsa-crash-before'",
    "mode==='handoff-rsa-crash-after'",
    'if(!uncertain||!nativeCrashVerified||callbackCount!==1||',
    'classifyMacSyntheticUncertainReceipt(report',
    "ruleId!=='MAC_TRANSFER_DISPATCH_UNCERTAIN'",
    'if(callbackCount!==1)',
    'observation:crashPhase',
    'if(evidence.status!=='
  ])assert.ok(runner.includes(requirement),requirement);
  assert.match(ci,/ReviewedCrashHost/);
  assert.match(ci,/ReviewedCrashWorker/);
  assert.match(ci,/BBX_TEST_CRASH_RECONCILE=1/);
  assert.match(ci,/observe-foreign/);
  assert.match(ci,/observe-corrupt/);
  assert.doesNotMatch(worker,/\b(?:kill|fork|exec)\s*\(/);
});
