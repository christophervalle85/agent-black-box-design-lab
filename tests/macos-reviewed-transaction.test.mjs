import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  createCanonicalMacReviewedTransaction,
  assertCanonicalMacReviewedTransaction,
  encodeCanonicalMacReviewedHandoff,
  MAC_REVIEWED_TRANSACTION_DOMAIN
} from '../src/macos-reviewed-transaction.mjs';
import {
  fixedMacReviewedVector,FIXED_BYTES,FIXED_ISSUED
} from '../examples/mcp-macos-reviewed-contract-vector.mjs';

const FIXED_ID='ddd1f149360dd897fff0ffd506deb2273c7d67997ce6c9f900180ecade1884e1';
const base=()=>fixedMacReviewedVector();
test('canonical reviewed contract matches independent deterministic golden vector',()=>{
  const tx=base();
  assert.equal(MAC_REVIEWED_TRANSACTION_DOMAIN,'bbx-reviewed-transaction-v1');
  assert.equal(FIXED_BYTES.length,39);
  assert.equal(createHash('sha256').update(FIXED_BYTES).digest('hex'),
    '661a096ac3bcad82021fdc5db4aff8358cc011409053809e9ebd19b0b81d6be3');
  assert.equal(tx.transactionId,FIXED_ID);
  assert.equal(Object.isFrozen(tx),true);
  assert.deepEqual(Object.keys(tx).sort(),[
    'byteLength','expiresAt','issuedAt','nonce','noteName',
    'operation','reviewId','sha256','transactionId','version'
  ]);
  assert.deepEqual(assertCanonicalMacReviewedTransaction(tx,{now:FIXED_ISSUED}),tx);
});
test('same payload with any other review or nonce produces a distinct identity',()=>{
  const original=base();
  for(const change of [
    {reviewId:'123e4567-e89b-42d3-a456-426614174001'},
    {nonce:'abcdef12-3456-4789-8abc-123456789abd'},
    {operation:'export'},
    {noteName:'bbx-test-else.txt'},
    {issuedAt:FIXED_ISSUED+1,expiresAt:FIXED_ISSUED+60001},
    {byteLength:40},
    {sha256:'f'.repeat(64)}
  ]){
    const {reviewId,transactionId,...intent}=original;
    const {reviewId:nextReviewId,...changeIntent}=change;
    const updated=createCanonicalMacReviewedTransaction({
      reviewId:nextReviewId??reviewId,
      intent:{...intent,...changeIntent}
    },{now:FIXED_ISSUED+1});
    assert.notEqual(updated.transactionId,original.transactionId);
    // Copying the old checksum cannot disguise a different reviewed record.
    assert.throws(()=>assertCanonicalMacReviewedTransaction({
      ...updated,transactionId
    },{now:FIXED_ISSUED+1}),/identifier mismatch/);
  }
});
test('unsupported, noncanonical and dangerous review representations fail closed',()=>{
  const valid=base();
  const altered=[
    {...valid,version:2},
    {...valid,reviewId:valid.reviewId.toUpperCase()},
    {...valid,nonce:valid.nonce.toUpperCase()},
    {...valid,nonce:'abcdef12-3456-1789-8abc-123456789abc'},
    {...valid,reviewId:'123e4567-e89b-42d3-7456-426614174000'},
    {...valid,transactionId:'A'.repeat(64)},
    {...valid,operation:'delete'},
    {...valid,operation:'import\nnoteName=bbx-test-hack.txt'},
    {...valid,noteName:'../../secrets.txt'},
    {...valid,noteName:'bbx-test-other.txt\nversion=1'},
    {...valid,byteLength:0},
    {...valid,byteLength:2001},
    {...valid,issuedAt:FIXED_ISSUED+1000000},
    {...valid,expiresAt:FIXED_ISSUED+59999},
    {...valid,additional:'approved'},
    {...valid,approved:true},
    {...valid,path:'/Users/private'},
    {...valid,payload:FIXED_BYTES},
    {...valid,sha256:'q'.repeat(64)}
  ];
  for(const item of altered)
    assert.throws(()=>assertCanonicalMacReviewedTransaction(item,{
      now:FIXED_ISSUED
    }));
  assert.throws(()=>assertCanonicalMacReviewedTransaction(valid,{
    now:FIXED_ISSUED+60000
  }),/expired|Invalid/i);
  assert.throws(()=>assertCanonicalMacReviewedTransaction(valid,{
    now:FIXED_ISSUED-1
  }));
  assert.throws(()=>assertCanonicalMacReviewedTransaction(null));
  assert.throws(()=>assertCanonicalMacReviewedTransaction([valid]));
  assert.throws(()=>assertCanonicalMacReviewedTransaction(Object.create(valid)));
  const accessor={...valid};
  Object.defineProperty(accessor,'noteName',{get(){return 'bbx-test-reviewed.txt';}});
  assert.throws(()=>assertCanonicalMacReviewedTransaction(accessor));
  assert.throws(()=>assertCanonicalMacReviewedTransaction({
    ...valid,[Symbol('injected')]:1
  }));
});
test('fixed canonical hash is DATA equality, not operator approval',()=>{
  const tx=base();
  assert.equal('decision' in tx,false);
  assert.equal('approved' in tx,false);
  assert.equal('signature' in tx,false);
  assert.equal('auditMac' in tx,false);
  assert.equal('credential' in tx,false);
});

test('canonical stdin envelope is strict ASCII and cannot supply approval',()=>{
  const tx=base();
  const wire=encodeCanonicalMacReviewedHandoff(tx,{now:FIXED_ISSUED});
  const expected=[
    'bbx-reviewed-transaction-v1',
    'version=1',
    'reviewId='+tx.reviewId,
    'operation=import',
    'noteName=bbx-test-reviewed.txt',
    'byteLength=39',
    'sha256='+tx.sha256,
    'nonce='+tx.nonce,
    'issuedAt='+tx.issuedAt,
    'expiresAt='+tx.expiresAt,
    'transactionId='+tx.transactionId,
    ''
  ].join('\\n').replaceAll('\\n','\n');
  assert.equal(wire.toString('ascii'),expected);
  assert.equal(wire.toString('ascii').includes('approved='),false);
  assert.equal(wire.toString('ascii').includes('bearer='),false);
  assert.equal(wire.toString('ascii').includes('filePath='),false);
  for(const altered of [
    {...tx,transactionId:'0'.repeat(64)}, {...tx,extra:'model-supplied'},
    {...tx,noteName:'bbx-test-other.txt'}
  ])assert.throws(()=>encodeCanonicalMacReviewedHandoff(altered,{
    now:FIXED_ISSUED
  }));
});
