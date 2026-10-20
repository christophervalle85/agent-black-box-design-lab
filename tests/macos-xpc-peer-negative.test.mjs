import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessAdhocPeerRejection} from '../examples/mcp-macos-xpc-peer-negative.mjs';
const read=p=>readFileSync(new URL(p,import.meta.url),'utf8');
const baseline=()=>({status:0,signal:null,stdout:'OK 9\nworkspace',stderr:''});
const negative=()=>({status:86,signal:null,stdout:'',stderr:'BBX_PEER_REQUIREMENT_OS_REJECTED\n'});
test('on-device peer acceptance demands both working baseline and explicit OS identity rejection',()=>{
  assert.equal(assessAdhocPeerRejection(baseline(),negative()),true);
  for(const b of [{...baseline(),status:1},{...baseline(),stdout:'ERR 0\n'},
   {...baseline(),signal:'SIGKILL'},null])
    assert.throws(()=>assessAdhocPeerRejection(b,negative()));
  for(const v of [{...negative(),status:85},{...negative(),status:87},
    {...negative(),stderr:'BBX_PEER_REQUIREMENT_UNAVAILABLE'},
    {...negative(),stdout:'OK 1\na'},{...negative(),signal:'SIGKILL'},null])
    assert.throws(()=>assessAdhocPeerRejection(baseline(),v));
});
test('peer identity requirement is OS-enforced and can never silently degrade to PID/UID',()=>{
  const gate=read('../native/macos/xpc/PeerRequirementGate.h');
  const host=read('../native/macos/xpc/AuthorityBridgeHost.c');
  const harness=read('../examples/mcp-macos-xpc-peer-negative.mjs');
  assert.match(gate,/xpc_connection_set_peer_team_identity_requirement/);
  assert.match(gate,/dlsym\(RTLD_DEFAULT/);
  assert.match(gate,/if\(!symbol\)return -2/);
  assert.match(gate,/bbx_valid_signing_identifier/);
  assert.doesNotMatch(gate,/xpc_connection_get_(?:pid|euid|egid)/);
  assert.match(host,/#ifdef BBX_TEST_PEER_REQUIREMENT/);
  assert.match(host,/peerGate=bbx_install_same_team_peer_requirement/);
  assert.match(host,/if\(peerGate!=0\)/);
  assert.match(host,/xpc_connection_set_event_handler\(connection/);
  assert.match(host,/BBX_PEER_REQUIREMENT_OS_REJECTED/);
  assert.match(harness,/compileHost\(\['-DBBX_TEST_PEER_REQUIREMENT=1'\]\)/);
  assert.match(harness,/MCP_SANDBOX==='required'/);
});
