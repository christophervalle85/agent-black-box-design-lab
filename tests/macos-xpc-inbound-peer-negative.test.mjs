import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessInboundPeerRejection} from '../examples/mcp-macos-xpc-inbound-peer-negative.mjs';
const file=p=>readFileSync(new URL(p,import.meta.url),'utf8');
const valid=()=>({
  armedPid:1234,workerAlive:true,workerMarkerFresh:true,
  hostAttempted:true,hostStdout:'',hostStderr:'BBX_INBOUND_REQUEST_ATTEMPTED\n',
  hostExited:false,hostExitCode:null,hostExitSignal:null,
  hostError:null,hostOverflow:false,deliverySeen:false
});
test('worker-side peer-identity acceptance requires armed live worker and no incoming messages',()=>{
  assert.equal(assessInboundPeerRejection(valid()),true);
  for(const bad of [
    {armedPid:0},{armedPid:-1},{armedPid:'1234'},
    {workerAlive:false},{workerMarkerFresh:false},
{hostAttempted:false},{hostStdout:'OK 1\na'},{deliverySeen:true},
    {hostError:'ENOENT'},{hostOverflow:true},{hostExitSignal:'SIGKILL'},
    {hostExited:true,hostExitCode:65},{hostExited:true,hostExitCode:0,hostStdout:'ERR 0\n'},
    {hostExited:true,hostExitCode:0,hostStdout:'OK 1\na',
      hostStderr:'BBX_INBOUND_XPC_ERROR'}
  ])assert.throws(()=>assessInboundPeerRejection({...valid(),...bad}));
  assert.throws(()=>assessInboundPeerRejection());
  assert.equal(assessInboundPeerRejection({
    ...valid(),hostExited:true,hostExitCode:0,hostStdout:'ERR 0\n',
    hostStderr:'BBX_INBOUND_REQUEST_ATTEMPTED\nBBX_INBOUND_XPC_ERROR\n'
  }),true);
});
test('only test worker builds install the OS incoming code-signing requirement before resume',()=>{
  const worker=file('../native/macos/xpc/AuthorityNotesService.m');
  const host=file('../native/macos/xpc/AuthorityBridgeHost.c');
  const script=file('../examples/mcp-macos-xpc-inbound-peer-negative.mjs');
  const ordinary=file('../examples/mcp-macos-xpc-authority.mjs');
  assert.match(worker,/#ifdef BBX_TEST_INBOUND_PEER_REQUIREMENT/);
  assert.match(worker,/"dev\.agentblackbox\.xpc-inbound-restricted\.host"/);
  assert.match(worker,/peerGate=bbx_install_same_team_peer_requirement/);
  assert.match(worker,/if\(peerGate!=0/);
  assert.match(worker,/xpc_transaction_begin\(\)/);
  assert.match(worker,/xpc_transaction_end\(\)/);
  assert.match(worker,/6\*NSEC_PER_SEC/);
  assert.match(worker,/bbx-test-inbound-armed\.txt/);
  assert.match(worker,/bbx-test-inbound-delivered\.txt/);
  assert.ok(worker.indexOf('peerGate=bbx_install_same_team_peer_requirement')<
    worker.indexOf('xpc_connection_resume(peer)'));
  assert.match(worker,/O_EXCL\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(host,/#elif defined\(BBX_TEST_INBOUND_CLIENT\)/);
  assert.match(host,/"dev\.agentblackbox\.xpc-inbound-baseline\.worker"/);
  assert.match(host,/"dev\.agentblackbox\.xpc-inbound-restricted\.worker"/);
  assert.match(host,/BBX_INBOUND_REQUEST_ATTEMPTED/);
  assert.match(host,/BBX_INBOUND_XPC_ERROR/);
  assert.match(script,/buildVariant\('baseline'\)/);
  assert.match(script,/buildVariant\('restricted'\)/);
  assert.match(script,/const baselineTail=/);
  assert.match(script,/No verified worker-side signing requirement marker/);
  assert.match(script,/inspectMinimalWorkerEntitlements/);
  assert.match(script,/validateMacWorkspaceBinding/);
  assert.match(script,/liveWorker\(armedPid\)/);
  assert.match(script,/function workerProcess\(pid\)/);
  assert.match(script,/BlackBoxAuthorityWorker/);
  assert.match(script,/Worker not alive after incoming signing requirement setup/);
  assert.match(script,/MCP_SANDBOX!=='off'/);
  assert.doesNotMatch(ordinary,/BBX_TEST_INBOUND_PEER_REQUIREMENT/);
});
