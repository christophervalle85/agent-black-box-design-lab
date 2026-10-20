import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessNotesWorkerIsolation} from '../examples/mcp-macos-xpc-notes-isolation.mjs';
const source=path=>readFileSync(new URL(path,import.meta.url),'utf8');
const accepted=()=>({valid:true,hostPID:111,workerPID:222,
  hostFileDenied:true,hostFileErrno:1,networkDenied:true,networkErrorNumber:13,
  temporaryWriteAllowed:true,temporaryWriteErrno:0});
test('final notes-worker OS acceptance needs real separate PID and genuine OS denials',()=>{
  assert.equal(assessNotesWorkerIsolation(accepted()).ok,true);
  const verdict=assessNotesWorkerIsolation(accepted());
  assert.equal(verdict.checks.length,4);
  assert.match(verdict.checks[3].label,/private Documents scratch root/);
  for(const bad of [
    {workerPID:111},{hostFileErrno:2},{hostFileDenied:false},
    {networkErrorNumber:61},{networkDenied:false},
    {temporaryWriteAllowed:false},{temporaryWriteErrno:5},
  ])assert.equal(assessNotesWorkerIsolation({...accepted(),...bad}).ok,false);
  for(const bad of [null,{},[],{...accepted(),valid:false}])
    assert.throws(()=>assessNotesWorkerIsolation(bad));
});
test('probe is compiled only into a disposable AuthorityNotesService build, not the existing normal worker',()=>{
  const worker=source('../native/macos/xpc/AuthorityNotesService.m');
  const host=source('../native/macos/xpc/ProbeHost.c');
  const script=source('../examples/mcp-macos-xpc-notes-isolation.mjs');
  const original=source('../examples/mcp-macos-xpc-authority.mjs');
  assert.match(worker,/#ifdef BBX_TEST_NOTES_ISOLATION/);
  assert.match(worker,/static void isolation_probe/);
  assert.match(worker,/notes_fd\(\)/);
  assert.match(worker,/openat\(dir,name,O_WRONLY\|O_CREAT\|O_EXCL\|/);
  assert.match(worker,/fsync\(out\)/);
  assert.match(worker,/unlinkat\(dir,name,0\)/);
  assert.match(worker,/networkDenied=connected<0&&/);
  assert.match(worker,/fileDenied=fd<0&&/);
  assert.match(host,/"dev\.agentblackbox\.xpc-authority\.worker"/);
  // The host verifies the XPC response before serializing its test-only
  // acknowledgement. Never weaken assessNotesWorkerIsolation(valid).
  assert.match(host,/!xpc_dictionary_get_bool\(reply,"valid"\)/);
  assert.match(host,/const char \*verifiedPrefix="\{\\\"valid\\\":true,";/);
  assert.match(host,/printf\("%s\\\"hostPID\\\"/);
  assert.match(host,/#else\s+const char \*verifiedPrefix="\{";/);

  assert.match(script,/-DBBX_TEST_NOTES_ISOLATION=1/);
  assert.match(script,/AuthorityNotesService\.m/);
  assert.match(script,/MCP_SANDBOX!=='off'/);
  assert.doesNotMatch(original,/BBX_TEST_NOTES_ISOLATION/);
});

test('required MCP worker OS-denial probe uses signed same-Team XPC and keeps diagnostics out of the installed app',()=>{
  const script=source('../examples/mcp-macos-xpc-notes-isolation.mjs');
  const installer=source('../examples/mcp-macos-native-required.mjs');
  const worker=source('../native/macos/xpc/AuthorityNotesService.m');
  const packageFile=JSON.parse(source('../package.json'));
  assert.equal(packageFile.scripts['mcp:mac-native-required-isolation'],
    'node examples/mcp-macos-xpc-notes-isolation.mjs --required-signed');
  assert.ok(script.includes("process.argv[2]==='--required-signed'"));
  assert.ok(script.includes("requiredSigned?selectLocalDevelopmentIdentity("));
  assert.ok(script.includes("['-DBBX_NATIVE_REQUIRED_MCP=1']"));
  assert.ok(script.includes("parseSignedIdentity(team(app)"));
  assert.ok(script.includes("parseSignedIdentity(team(service)"));
  assert.ok(worker.includes("bbx_install_same_team_peer_requirement(peer,"));
  assert.ok(installer.includes("'-DBBX_NATIVE_REQUIRED_MCP=1'"));
  assert.ok(!installer.includes("'-DBBX_TEST_NOTES_ISOLATION=1'"));
});
