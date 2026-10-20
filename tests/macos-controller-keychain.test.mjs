import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createEphemeralMacControllerSigner,encodeMacReviewedRsaHandoff}
  from '../src/macos-reviewed-signed-authority.mjs';
import {
  parseMacKeychainPublicRecord,encodeMacKeychainUnsignedReview,
  validateMacKeychainSignedReview
} from '../src/macos-controller-keychain.mjs';
import {fixedMacReviewedVector,FIXED_ISSUED}
  from '../examples/mcp-macos-reviewed-contract-vector.mjs';

const contents=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const pubRecord=key=>{
  const der=key.export({type:'pkcs1',format:'der'});
  return 'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64='+der.toString('base64')+'\n';
};
test('separate Keychain RSA public enrollment requires one exact public record',()=>{
  const pair=createEphemeralMacControllerSigner();
  const enrolled=parseMacKeychainPublicRecord(pubRecord(pair.publicKey));
  assert.equal(enrolled.sha256.length,64);
  assert.equal(enrolled.publicKey.asymmetricKeyType,'rsa');
  assert.ok(Object.isFrozen(enrolled));
  for(const bad of [
    '',null,undefined,'BBX_KEYCHAIN_CONTROLLER_PROVISIONED\n',
    pubRecord(pair.publicKey)+'extra',
    pubRecord(pair.publicKey).replace(/\n$/,''),
    pubRecord(pair.publicKey).replace('BASE64=','BASE64= '),
    'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=Zm9v\n',
    'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=****\n',
    'BBX_CONTROLLER_RSA_PUBLIC_PKCS1_BASE64=Zm9v===\n'
  ])assert.throws(()=>parseMacKeychainPublicRecord(bad));
});
test('Keychain-issued synthetic review binds fixed fields and HMAC audit with independently pinned RSA',()=>{
  const first=createEphemeralMacControllerSigner();
  const foreign=createEphemeralMacControllerSigner();
  const tx=fixedMacReviewedVector();
  const checkpoint='b'.repeat(64);
  const input=encodeMacKeychainUnsignedReview(tx,{
    reservationMac:checkpoint,now:FIXED_ISSUED
  });
  assert.ok(input.toString('ascii').endsWith('reservationMac='+checkpoint+'\n'));
  assert.ok(!input.toString('ascii').includes('controllerSig='));
  const pinned=parseMacKeychainPublicRecord(pubRecord(first.publicKey));
  const wire=encodeMacReviewedRsaHandoff(tx,{
    privateKey:first.privateKey,reservationMac:checkpoint,now:FIXED_ISSUED
  });
  assert.deepEqual(validateMacKeychainSignedReview(wire,{
    publicKey:pinned.publicKey,transaction:tx,reservationMac:checkpoint,
    now:FIXED_ISSUED
  }),wire);
  const wrong=encodeMacReviewedRsaHandoff(tx,{
    privateKey:foreign.privateKey,reservationMac:checkpoint,now:FIXED_ISSUED
  });
  for(const invalid of [
    wrong,wire.subarray(0,-1),Buffer.concat([wire,Buffer.from('\n')]),
    Buffer.from(wire.toString('ascii').replace(
      'reservationMac='+checkpoint,'reservationMac='+'c'.repeat(64))),
    Buffer.alloc(1537)
  ])assert.throws(()=>validateMacKeychainSignedReview(invalid,{
    publicKey:pinned.publicKey,transaction:tx,reservationMac:checkpoint,
    now:FIXED_ISSUED
  }));
  for(const bad of ['X'.repeat(64),'b'.repeat(63),'',null,undefined])
    assert.throws(()=>encodeMacKeychainUnsignedReview(tx,{
      reservationMac:bad,now:FIXED_ISSUED
    }));
});
test('Keychain signer never emits private key material, provisions only explicitly, and fails on absent enrollment',()=>{
  const code=contents('native/macos/xpc/KeychainControllerSigner.m');
  const cli=contents('examples/mcp-macos-controller-keychain.mjs');
  const runner=contents('examples/mcp-macos-xpc-native-reviewed.mjs');
  const ci=contents('.github/workflows/ci.yml');
  const packageFile=JSON.parse(contents('package.json'));
  for(const symbol of [
    'SecItemCopyMatching','SecKeyCreateRandomKey',
    'SecKeyCreateSignature','SecKeyCopyPublicKey',
    'SecKeyCopyExternalRepresentation(publicKey',
    'kSecAttrIsExtractable:@NO',
    'kSecAttrIsSensitive:@YES',
    'bbx_parse_preissued_review',
    'strcmp(argv[1],"provision")',
    'strcmp(argv[1],"public")',
    'strcmp(argv[1],"sign")',
    'kSecKeyAlgorithmRSASignatureMessagePSSSHA256'
  ])assert.ok(code.includes(symbol),symbol);
  assert.doesNotMatch(code,/SecKeyCopyExternalRepresentation\(privateKey/);
  assert.doesNotMatch(code,/SecKeyCreateSignature\([^]*\bsha256=bad\b/);
  assert.match(code,/if\(existing\)\{CFRelease\(existing\);return 86;\}/);
  assert.match(code,/if\(found!=errSecItemNotFound\)return 87/);
  assert.ok(cli.includes("['provision']"));
  assert.ok(cli.includes("['public']"));
  assert.ok(!runner.includes("['provision']"));
  assert.ok(runner.includes("mode==='handoff-rsa-keychain'"));
  assert.ok(runner.includes('readMacKeychainControllerIdentity(helper)'));
  assert.ok(runner.includes('signMacKeychainReviewedTransaction(helper,transaction'));
  assert.ok(runner.includes('formatPinnedMacRsaPublicHeader(enrolled.publicKey)'));
  assert.ok(runner.includes('if(privateKey!==null&&signController!==null)'));
  assert.ok(ci.includes('native/macos/xpc/KeychainControllerSigner.m'));
  assert.ok(ci.includes('no Keychain identity created on CI'));
  assert.equal(packageFile.scripts['mcp:mac-controller-key'],
    'node examples/mcp-macos-controller-keychain.mjs');
});

test('native controller consent cannot be bypassed and only signs exact synthetic bytes',()=>{
  const source=contents('native/macos/xpc/KeychainControllerSigner.m');
  const build=contents('examples/mcp-macos-controller-keychain.mjs');
  const runner=contents('examples/mcp-macos-xpc-native-reviewed.mjs');
  const ci=contents('.github/workflows/ci.yml');
  const signingFunction=source.slice(source.indexOf('static int signFixedSyntheticReview(const char *auditDirectory)'));
  assert.match(source,/LAPolicyDeviceOwnerAuthenticationWithBiometrics/);
  assert.match(source,/touchIDAuthenticationAllowableReuseDuration=0/);
  assert.match(source,/evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics/);
  assert.match(source,/dispatch_semaphore_wait\(completed/);
  assert.match(source,/if\(review\.byteLength!=39\|\|/);
  assert.match(source,/661a096ac3bcad82021fdc5db4aff8358cc011409053809e9ebd19b0b81d6be3/);
  assert.match(source,/if\(afterApproval<review\.issuedAt\|\|afterApproval>=review\.expiresAt\)/);
  assert.match(source,/return timeout==0&&approved/);
  assert.ok(signingFunction.indexOf('if(!approveExactlyReviewedSyntheticTransaction(&review))return 87;') <
    signingFunction.indexOf('SecKeyCreateSignature('));
  assert.ok(signingFunction.indexOf('expectedSyntheticSHA') <
    signingFunction.indexOf('if(!approveExactlyReviewedSyntheticTransaction(&review))return 87;'));
  assert.match(build,/'-framework','LocalAuthentication'/);
  assert.match(build, /invoke\(helper,\['sign',auditDirectory\]/);
  assert.ok(!runner.includes("['provision']"));
  // Native signing must only happen AFTER a durable controller reservation;
  // preflight failures use an UNTRUSTED fixture and require no biometrics.
  assert.ok(runner.includes('const preflightKey=signController?'));
  assert.ok(runner.includes('signController(context.transaction,store.verify().head,'));
  assert.ok(runner.includes('MAC_TRANSFER_DISPATCH_RESERVED'));
  assert.match(ci,/KeychainControllerSigner\.m -framework Foundation -framework Security -framework LocalAuthentication/);
});
test('combined Keychain suite exercises independent reviews with durable restart and both uncertain crashes',()=>{
  const runner=contents('examples/mcp-macos-xpc-native-reviewed.mjs');
  const host=contents('native/macos/xpc/ReviewedTransferHost.m');
  const ci=contents('.github/workflows/ci.yml');
  assert.ok(runner.includes("mode==='handoff-rsa-keychain-suite'"));
  for(const required of [
    "['restart',{restart:true}]",
    "['crash-before',{crashPhase:'before'}]",
    "['crash-after',{crashPhase:'after'}]",
    'mkdirSync(auditDir,{mode:0o700})',
    'signController,durable:true,...options',
    '-DBBX_TEST_KEYCHAIN_FULL_SUITE=1',
    'One pinned Keychain controller identity passed native consent',
    'same-user Keychain access and production controller authority are NOT proven'
  ])assert.ok(runner.includes(required),required);
  assert.match(host,/#ifdef BBX_TEST_KEYCHAIN_FULL_SUITE/);
  assert.match(ci,/ReviewedKeychainSuiteHost/);
  assert.match(ci,/BBX_TEST_KEYCHAIN_FULL_SUITE=1/);
  assert.ok(ci.includes('no Keychain identity created on CI'));
});

test('denied signer biometric cannot be replaced by a forged success or native XPC launch',()=>{
  const runner=contents('examples/mcp-macos-xpc-native-reviewed.mjs');
  assert.match(runner,/mode==='handoff-rsa-keychain-deny'/);
  assert.match(runner,/if\(denyController&&typeof signController!=='function'\)/);
  assert.match(runner,/consentUnexpectedlyGranted=true/);
  assert.match(runner,/nativeHostLaunchCount\+\+/);
  assert.ok(runner.indexOf('if(denyController){\n        // An actual signature') <
    runner.indexOf('nativeHostLaunchCount++'));
  assert.match(runner,/if\(!uncertain\|\|consentUnexpectedlyGranted\|\|nativeHostLaunchCount!==0\|\|/);
  assert.match(runner,/audit\.hasUncertainDispatch!==true/);
  assert.match(runner,/verdict\?\.canRetry!==false/);
  assert.match(runner,/No unconsumed/);
  assert.match(runner,/choose Cancel\. Do NOT approve/);
});


test('native Keychain controller consumes one durable nonce before any signature',()=>{
  const signer=contents('native/macos/xpc/KeychainControllerSigner.m');
  const ledger=contents('native/macos/xpc/ControllerSigningReservation.h');
  const runner=contents('examples/mcp-macos-xpc-native-reviewed.mjs');
  assert.match(signer,/#include "ControllerSigningReservation\.h"/);
  assert.match(signer,/bbx_reviewed_replay_observe\(\s*beforeDir,review\.nonce,review\.transactionId\)/);
  assert.match(signer,/prior!=BBX_REPLAY_NO_MARKER/);
  assert.match(signer,/bbx_reviewed_replay_reserve\(\s*signingDir,review\.nonce,review\.transactionId\)/);
  assert.match(signer,/reserved!=BBX_REPLAY_FRESH_COMMITTED/);
  assert.ok(signer.indexOf('if(!approveExactlyReviewedSyntheticTransaction(&review))return 87;') <
    signer.indexOf('bbx_reviewed_replay_reserve('));
  assert.ok(signer.indexOf('bbx_reviewed_replay_reserve(') <
    signer.indexOf('SecKeyCreateSignature('));
  assert.match(ledger,/O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(ledger,/NSHomeDirectory\(\)/);
  assert.match(ledger,/Application Support/);
  assert.match(ledger,/ControllerSigning/);
  assert.match(ledger,/st\.st_uid!=geteuid\(\)/);
  assert.match(ledger,/st\.st_mode&077/);
  assert.match(ledger,/bbx_test_open_signing_subfolder/);
  assert.doesNotMatch(ledger,/unlink(at)?\s*\(/);
  assert.match(runner,/let signerReplayDenied=false/);
  assert.match(runner,/signController\.verifyReplay\(/);
  assert.match(runner,/signController\(context\.transaction,store\.verify\(\)\.head,/);
  assert.match(runner,/Native controller signing nonce was durably consumed/);
  assert.ok(signer.includes('if(prior==BBX_REPLAY_MATCHING_MARKER)return 88;'));
  const helper=contents('examples/mcp-macos-controller-keychain.mjs');
  assert.match(helper,/outcome\.status!==88/);
  assert.match(helper,/outcome\.stdout\.length!==0/);
  assert.match(helper,/outcome\.stderr\.length!==0/);
  assert.match(helper,/timeout:2500/);
  assert.doesNotMatch(signer,/SecKeyCopyExternalRepresentation\(privateKey/);
});

test('native Keychain signer independently re-verifies Node HMAC audit and exact reservation before consent',()=>{
  const signer=contents('native/macos/xpc/KeychainControllerSigner.m');
  const verifier=contents('native/macos/xpc/ControllerAuditVerifier.h');
  const vector=contents('native/macos/xpc/ControllerAuditVector.m');
  const generator=contents('examples/mcp-macos-controller-audit-vector.mjs');
  const controller=contents('src/macos-transfer-controller.mjs');
  const runner=contents('examples/mcp-macos-xpc-native-reviewed.mjs');
  const ci=contents('.github/workflows/ci.yml');
  assert.ok(signer.includes('#include "ControllerAuditVerifier.h"'));
  assert.ok(signer.includes('bbx_test_verify_native_audit(auditDirectory,&review,mac)'));
  assert.ok(signer.indexOf('bbx_test_verify_native_audit(auditDirectory,&review,mac)') <
    signer.indexOf('if(!approveExactlyReviewedSyntheticTransaction(&review))return 87;'));
  assert.ok(signer.indexOf('bbx_test_verify_native_audit(auditDirectory,&review,mac)') <
    signer.indexOf('SecKeyCreateSignature('));
  for(const marker of [
    'CCHmac(kCCHmacAlgSHA256',
    'handoff-audit.jsonl.mac.jsonl',
    'handoff-audit.jsonl.hmac.key',
    'handoff-audit.jsonl.anchor.json',
    'O_RDONLY|O_NOFOLLOW|O_CLOEXEC',
    'transferTransactionId',
    'transferNonce',
    'transferSHA256',
    'transferBytes',
    'transferExpiresAt',
    'MAC_TRANSFER_DISPATCH_RESERVED',
    'bbx_test_json_quoted_raw',
    '[checkpoint[@"mac"] isEqualToString:previous]'
  ])assert.ok(verifier.includes(marker),marker);
  assert.ok(controller.includes('transferTransactionId:transfer.transactionId'));
  assert.ok(controller.includes('transferNonce:transfer.nonce'));
  assert.ok(runner.includes('dirname(store.filename)'));
  assert.ok(vector.includes('bbx_test_verify_native_audit('));
  assert.ok(generator.includes('BBX_AUDIT_FIXTURE_RESERVED'));
  assert.match(ci,/ControllerAuditVector\.m/);
  assert.match(ci,/mcp-macos-controller-audit-vector\.mjs/);
  assert.doesNotMatch(verifier,/unlink(at)?\s*\(/);
});

test('native audit gate is rechecked after operator consent and rejects type-confused proof fields',()=>{
  const signer=contents('native/macos/xpc/KeychainControllerSigner.m');
  const verifier=contents('native/macos/xpc/ControllerAuditVerifier.h');
  const witness='bbx_test_verify_native_audit(auditDirectory,&review,mac)';
  const consent='if(!approveExactlyReviewedSyntheticTransaction(&review))return 87;';
  const reservation='bbx_reviewed_replay_reserve(';
  const signature='SecKeyCreateSignature(';
  const first=signer.indexOf(witness);
  const after=signer.indexOf(witness,first+1);
  assert.ok(first>0&&first<signer.indexOf(consent));
  assert.ok(after>signer.indexOf(consent)&&after<signer.indexOf(reservation));
  assert.ok(after<signer.indexOf(signature));
  for(const required of [
    '![mac[@"prev"] isKindOfClass:[NSString class]]',
    '![source isKindOfClass:[NSString class]]',
    '![event[@"transferTransactionId"] isKindOfClass:[NSString class]]',
    '![event[@"transferNonce"] isKindOfClass:[NSString class]]',
    '![event[@"transferSHA256"] isKindOfClass:[NSString class]]',
    '![checkpoint[@"mac"] isKindOfClass:[NSString class]]'
  ])assert.ok(verifier.includes(required),required);
  assert.match(verifier,/O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC/);
});
