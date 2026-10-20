import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const source=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');

test('persistent native replay is opt-in, worker-owned and never input-supplied',()=>{
  const worker=source('native/macos/xpc/TransferReceiptService.m');
  const ledger=source('native/macos/xpc/ReviewedDurableReplay.h');
  const root=source('native/macos/xpc/ReviewedDurableReplayDirectory.h');
  const runner=source('examples/mcp-macos-xpc-native-reviewed.mjs');
  const host=source('native/macos/xpc/ReviewedTransferHost.m');
  assert.match(worker,/#ifdef BBX_TEST_DURABLE_REPLAY/);
  assert.match(worker,/#ifndef BBX_TEST_SIGNED_PEER_REQUIREMENT/);
  assert.match(worker,/#ifndef BBX_TEST_NATIVE_REVIEWED_RECEIPT/);
  assert.match(worker,/#include "ReviewedDurableReplayDirectory.h"/);
  assert.match(worker,/bbx_reviewed_replay_reserve\(\s*folder,nonce,transactionId\)/);
  assert.match(worker,/BBX_REPLAY_FRESH_COMMITTED/);
  assert.match(worker,/BBX_REPLAY_ALREADY_SPENT/);
  assert.match(worker,/STORAGE_DENIED/);
  // Default worker contains no direct filesystem operations: only the
  // explicitly compiled test header has the native storage capability.
  assert.doesNotMatch(worker,/\b(?:open|openat|fopen|fwrite|write|unlink|mkdir)\s*\(/);
  assert.match(root,/URLForDirectory:NSDocumentDirectory/);
  assert.match(root,/\/Library\/Containers\//);
  assert.match(root,/O_RDONLY\|O_DIRECTORY\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(root,/AgentBlackBoxReviewedReplay/);
  assert.match(root,/info\.st_uid!=geteuid\(\)/);
  assert.match(root,/fsync\(parent\)!=0/);
  assert.match(ledger,/O_WRONLY\|O_CREAT\|O_EXCL\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(ledger,/bbx_reviewed_uuid4\(nonce\)/);
  assert.match(ledger,/bbx_reviewed_lowerhex\(transactionId,64\)/);
  assert.match(ledger,/dirStat\.st_uid!=geteuid\(\)/);
  assert.match(ledger,/fsync\(fd\)==0/);
  assert.match(ledger,/fsync\(directory\)==0/);
  assert.match(ledger,/return BBX_REPLAY_ALREADY_SPENT/);
  assert.doesNotMatch(ledger,/unlinkat\s*\(/);
  assert.match(host,/BBX_REVIEWED_XPC_DURABLE_REPLAY_REJECTED/);
  assert.match(host,/handoff-rsa-durable-replay/);
  assert.match(host,/BBX_TEST_DURABLE_REPLAY/);
  assert.match(runner,/signedCommittedWire=Buffer\.from\(wire\)/);
  assert.match(runner,/assessNativeReviewedXpc\('handoff-rsa-durable-replay',replay\)/);
  assert.match(runner,/MCP_SANDBOX!=='off'/);
  assert.doesNotMatch(runner,/createBlackBoxServer/);
});
test('native Apple CI must compile both durable gate and signed host and run real POSIX races',()=>{
  const ci=source('.github/workflows/ci.yml');
  for(const required of [
    'ReviewedDurableReplayVector.c','ReviewedDurableWorker',
    'ReviewedDurableSignedHost',
    'BBX_TEST_DURABLE_REPLAY=1',
    'symlink-marker','native-replay-race',
    'race "$race"',
    '"$fresh" -ne 1',
    '"$replayed" -ne 7'
  ])assert.ok(ci.includes(required),required);
});
