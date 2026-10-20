import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  createMacTransferIntent,validateMacTransferIntent,
  assertMacTransferBytes,assertMacTransferReviewMatches,
  MAC_TRANSFER_MAX_BYTES,MAC_TRANSFER_LIFETIME_MS
} from '../src/macos-transfer-intent.mjs';
const NOW=1_790_000_000_000;
const payload=()=>Buffer.from('synthetic import content\n','utf8');
const make=(overrides={})=>createMacTransferIntent({
  operation:'import',noteName:'bbx-test-import.txt',bytes:payload(),now:NOW,
  ...overrides
});
test('Phase 5 intents describe only exact synthetic note operation and digest, never file access',()=>{
  const intent=make();
  assert.equal(intent.version,1);
  assert.equal(intent.operation,'import');
  assert.equal(intent.byteLength,payload().byteLength);
  assert.equal(intent.sha256,createHash('sha256').update(payload()).digest('hex'));
  assert.equal(intent.expiresAt-intent.issuedAt,MAC_TRANSFER_LIFETIME_MS);
  assert.match(intent.nonce,/^[0-9a-f-]{36}$/);
  assert.deepEqual(Object.keys(intent).sort(),[
    'byteLength','expiresAt','issuedAt','nonce','noteName','operation','sha256','version'
  ]);
  assert.equal(Object.isFrozen(intent),true);
  assert.doesNotMatch(JSON.stringify(intent),/synthetic import content|path|bookmark|token|approval/i);
  assert.equal(assertMacTransferBytes(intent,payload(),{now:NOW}),true);
  assert.equal(assertMacTransferReviewMatches(intent,{...intent},{now:NOW}),true);
});
test('intent validation fails closed on paths, extra fields, accessors, expired or forged identity',()=>{
  const intent=make();
  for(const mutation of [
    {operation:'shell'},{noteName:'../../secrets.txt'},{noteName:'/tmp/bbx-test-a.txt'},
    {noteName:'bbx-test-secret.json'},{noteName:'bbx-test-'+'a'.repeat(52)+'.txt'},
    {byteLength:0},{byteLength:2001},{byteLength:1.5},{sha256:'abc'},
    {sha256:intent.sha256.toUpperCase()},{nonce:'fake-nonce'},
    {version:2},{expiresAt:intent.expiresAt+1000},{issuedAt:NOW+1000},
    {sourcePath:'/Users/operator/Documents/note.txt'},
    {destinationPath:'/tmp/out.txt'},{approval:true},{token:'fake'},
    {securityScopedBookmark:'fake'}
  ])assert.throws(()=>validateMacTransferIntent({...intent,...mutation},{now:NOW}));
  assert.throws(()=>validateMacTransferIntent(intent,{now:intent.expiresAt}));
  assert.throws(()=>validateMacTransferIntent(intent,{now:NOW-1}));
  assert.throws(()=>validateMacTransferIntent(Object.create({inherited:true})));
  assert.throws(()=>validateMacTransferIntent(Object.defineProperty(
    {...intent},'noteName',{get:()=>intent.noteName}),{now:NOW}));
  assert.throws(()=>validateMacTransferIntent(null,{now:NOW}));
});
test('byte binding rejects mutation, wrong length, malicious strings and oversize buffers',()=>{
  const input=payload();
  const intent=make({bytes:input});
  input[0]=0x58;
  assert.throws(()=>assertMacTransferBytes(intent,input,{now:NOW}),/digest/);
  assert.equal(assertMacTransferBytes(intent,payload(),{now:NOW}),true);
  assert.throws(()=>assertMacTransferBytes(intent,Buffer.from('one'),{now:NOW}),/byte count/);
  assert.throws(()=>assertMacTransferBytes(intent,'synthetic import content\n',{now:NOW}));
  assert.throws(()=>make({bytes:Buffer.alloc(MAC_TRANSFER_MAX_BYTES+1)}));
  assert.throws(()=>make({bytes:Buffer.alloc(0)}));
  assert.throws(()=>make({bytes:Buffer.from('hi'),now:-1}));
  for(const extra of [
    {sourcePath:'/Users/example/private.txt'},
    {destinationPath:'/tmp/out.txt'},
    {approved:true},{securityScopedBookmark:'untrusted'},
    {bearerToken:'untrusted'}
  ])assert.throws(()=>createMacTransferIntent({
    operation:'import',noteName:'bbx-test-import.txt',bytes:payload(),
    now:NOW,...extra
  }),/schema mismatch/);
});
test('review snapshot equality is not a bearer approval and changes invalidate a request',()=>{
  const intent=make();
  assert.equal(assertMacTransferReviewMatches(intent,{...intent},{now:NOW}),true);
  for(const mutation of [
    {operation:'export'},{noteName:'bbx-test-other.txt'},
    {byteLength:intent.byteLength+1},{sha256:'a'.repeat(64)},
    {nonce:'01234567-1234-4abc-8abc-123456789abc'}
  ])assert.throws(()=>assertMacTransferReviewMatches(intent,{
    ...intent,...mutation
  },{now:NOW}));
  assert.throws(()=>assertMacTransferReviewMatches(intent,{
    ...intent,approved:true
  },{now:NOW}));
});
test('export preview has same strict byte contract and does not accept a destination path',()=>{
  const intent=make({operation:'export',noteName:'bbx-test-out.txt'});
  assert.equal(intent.operation,'export');
  assert.equal(assertMacTransferBytes(intent,payload(),{now:NOW}),true);
  assert.throws(()=>validateMacTransferIntent({...intent,target:'/tmp/out'},{now:NOW}));
});
