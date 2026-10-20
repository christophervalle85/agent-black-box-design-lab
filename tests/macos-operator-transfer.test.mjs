import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {assessOperatorTransfer,assessOperatorImportDenial,
  assessOperatorNegativeFixture,summarizeNativeBuildFailure}
  from '../examples/mcp-macos-operator-transfer.mjs';

const source=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const id='bbx-test-123e4567-e89b-42d3-a456-426614174000.txt';
const digest='a'.repeat(64);
const ok=(mode,name=id)=>({
  status:0,signal:null,stderr:'',stdout:
    'BBX_OPERATOR_'+mode.toUpperCase()+'_COMMITTED '+name+' 25 '+digest+'\n'
});
test('operator transfer receipts require exact direction, canonical test note, bounded byte count and full digest',()=>{
  assert.deepEqual(assessOperatorTransfer('import',ok('import')),{
    noteName:id,byteLength:25,sha256:digest
  });
  assert.deepEqual(assessOperatorTransfer('export',ok('export'),{
    requestedName:id
  }),{noteName:id,byteLength:25,sha256:digest});
  for(const invalid of [
    {...ok('import'),stdout:ok('import').stdout+'extra\n'},
    {...ok('import'),stdout:ok('import').stdout.replace(' 25 ',' 2001 ')},
    {...ok('import'),stdout:ok('import').stdout.replace(digest,'A'.repeat(64))},
    {...ok('import'),stdout:ok('import').stdout.replace('bbx-test-','../')},
    {...ok('import'),status:83},
    {...ok('import'),status:89},
    {...ok('import'),signal:'SIGTERM'},
    {...ok('import'),stderr:'native diagnostic\n'},
    {...ok('import'),stdout:'BBX_OPERATOR_EXPORT_COMMITTED '+id+' 25 '+digest+'\n'}
  ])assert.throws(()=>assessOperatorTransfer('import',invalid));
  assert.throws(()=>assessOperatorTransfer('export',ok('export'),{
    requestedName:'bbx-test-123e4567-e89b-42d3-a456-426614174001.txt'
  }));
});
test('operator-only native file capability is not exposed in normal macOS required mode or MCP tools',()=>{
  const script=source('examples/mcp-macos-operator-transfer.mjs');
  const gateway=source('src/mcp-gateway.mjs');
  const packageFile=JSON.parse(source('package.json'));
  const build=source('native/macos/xpc/OperatorTransferHost.m');
  const worker=source('native/macos/xpc/AuthorityNotesService.m');
  assert.equal(packageFile.scripts['mcp:mac-operator-transfer'],
    'node examples/mcp-macos-operator-transfer.mjs');
  assert.match(script,/process\.env\.MCP_SANDBOX!=='off'/);
  assert.match(script,/process\.platform!=='darwin'/);
  assert.match(script,/selectLocalDevelopmentIdentity/);
  assert.match(script,/parseSignedIdentity/);
  assert.match(script,/requireSandbox\(service\)/);
  assert.match(script,/BBX_NATIVE_OPERATOR_TRANSFER=1/);
  assert.match(script,/MAC_OPERATOR_TRANSFER_UNCERTAIN/);
  assert.match(script,/MAC_OPERATOR_TRANSFER_NATIVE_RECEIPT/);
  assert.match(script,/new AuditStore/);
  assert.doesNotMatch(gateway,/operator[_-]transfer|native\.operator\.transfer/);
  assert.match(worker,/#if defined\(BBX_NATIVE_OPERATOR_TRANSFER\) \|\| defined\(BBX_NATIVE_REQUIRED_MCP\)/);
  assert.match(worker,/bbx_install_same_team_peer_requirement\(peer,/);
  assert.match(worker,/dev\.agentblackbox\.xpc-authority\.host/);
  assert.match(build,/NSOpenPanel \*panel=\[NSOpenPanel openPanel\]/);
  assert.match(build,/NSSavePanel \*panel=\[NSSavePanel savePanel\]/);
  assert.match(build,/LAPolicyDeviceOwnerAuthenticationWithBiometrics/);
  assert.match(build,/O_RDONLY\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(build,/O_WRONLY\|O_CREAT\|O_EXCL\|O_NOFOLLOW\|O_CLOEXEC/);
  assert.match(build,/fsync\(fd\)/);
  assert.match(build,/bbx-test-/);
  assert.match(build,/xpc_connection_send_message_with_reply_sync/);
  assert.match(build,/memchr\(bytes,0,used\)==NULL/);
  assert.match(build,/before\.st_ino==after\.st_ino/);
  assert.match(build,/readNote\(peer,note\)/);
  assert.doesNotMatch(build,/system\s*\(|popen\s*\(/);
});
test('unsigned, ad-hoc or automatic feature branch CI cannot silently enable transfer',()=>{
  const script=source('examples/mcp-macos-operator-transfer.mjs');
  const ci=source('.github/workflows/ci.yml');
  const req=source('src/sandbox.mjs');
  assert.ok(script.includes("'--sign',identity"));
  assert.ok(script.includes("'--entitlements'"));
  assert.ok(script.includes("'--verify','--strict','--deep'"));
  assert.ok(ci.includes('branches: [main]'));
  assert.ok(!ci.includes("'feature/v0.8-*'"));
  assert.ok(!req.includes('mcp-macos-operator-transfer.mjs'));
});

test('macOS native operator host uses manual XPC lifetime and exposes redacted Clang build errors',()=>{
  const runner=source('examples/mcp-macos-operator-transfer.mjs');
  assert.match(runner,/const buildOnly=mode==='build-check'/);
  assert.match(runner,/if\(buildOnly\)\{/);
  assert.ok(runner.includes('No picker, Touch ID, transfer or HMAC audit was launched.'));
  const hostBuild=runner.slice(
    runner.indexOf("command('/usr/bin/xcrun',['clang',...flags"),
    runner.indexOf("command('/usr/bin/xcrun',['clang',...flags")+290
  );
  assert.ok(hostBuild.includes("OperatorTransferHost.m"));
  assert.ok(!hostBuild.includes("'-fobjc-arc'"));
  const path='/Users/hidden/work/agent-black-box/native/macos/xpc/OperatorTransferHost.m';
  const issue=summarizeNativeBuildFailure(path+':174:8: error: ARC forbids explicit message send of release\n');
  assert.equal(issue,'OperatorTransferHost.m:174:8: error: ARC forbids explicit message send of release');
  assert.ok(!issue.includes('/Users/hidden/'));
  assert.equal(summarizeNativeBuildFailure('ld: library not found for -lxyz\n'),
    'linker/compiler: library not found for -lxyz');
  assert.match(summarizeNativeBuildFailure('nonspecific error'),/No recognized compiler/);
});

test('native import failure reasons are strict, fixed and pre-dispatch only',()=>{
  const marker=label=>'BBX_OPERATOR_IMPORT_DENIED_'+label+String.fromCharCode(10);
  const event=label=>({
    status:87,signal:null,error:null,stderr:'',stdout:marker(label)
  });
  for(const label of ['SOURCE_URL','SOURCE_PATH','SOURCE_OPEN',
    'SOURCE_POLICY','SOURCE_SIZE','SOURCE_CHANGED','SOURCE_TEXT',
    'SOURCE_CLOSE','FIXTURE_MISMATCH','XPC_SETUP','NOTE_SCHEMA']){
    const result=event(label);
    assert.equal(assessOperatorImportDenial(result),label);
    assert.throws(()=>assessOperatorTransfer('import',result));
  }
  for(const result of [
    {...event('SOURCE_SIZE'),status:0},
    {...event('SOURCE_SIZE'),signal:'SIGKILL'},
    {...event('SOURCE_SIZE'),stderr:'unexpected'},
    {...event('SOURCE_SIZE'),stdout:marker('UNRECOGNIZED')},
    {...event('SOURCE_SIZE'),stdout:marker('SOURCE_SIZE')+'extra'},
    {...event('SOURCE_SIZE'),stdout:''}
  ])assert.equal(assessOperatorImportDenial(result),null);
});
test('generated import fixture is selected by exact inode and never bypasses native panel',()=>{
  const native=source('native/macos/xpc/OperatorTransferHost.m');
  const script=source('examples/mcp-macos-operator-transfer.mjs');
  assert.ok(script.includes("const fixtureImport=['fixture-import','fixture-oversize','fixture-cancel']"));
  assert.ok(script.includes('.includes(mode)&&process.argv.length===3;'));
  assert.ok(script.includes("writeFileSync(fixture,mode==='fixture-oversize'?'X'.repeat(2001):"));
  assert.ok(script.includes("'BBX disposable operator transfer fixture"));
  assert.ok(script.includes("fixtureImport?['import-fixture',fixture]"));
  assert.ok(native.includes('panel.directoryURL=[NSURL fileURLWithPath:'));
  assert.ok(native.includes('if([panel runModal]!=NSModalResponseOK)return 83;'));
  assert.ok(native.includes('expected.st_dev!=before.st_dev'));
  assert.ok(native.includes('expected.st_ino!=before.st_ino'));
  assert.ok(native.includes('if(!snapshot)return denyImport('));
  assert.ok(native.includes('bbx_test')===false);
  assert.ok(!source('src/mcp-gateway.mjs').includes('fixture-import'));
});

test('negative operator fixtures require actual OS picker cancellation, overflow rejection and no-clobber',()=>{
  const wrapper=source('examples/mcp-macos-operator-transfer.mjs');
  const native=source('native/macos/xpc/OperatorTransferHost.m');
  for(const mode of ['fixture-cancel','fixture-oversize','fixture-export-overwrite'])
    assert.ok(wrapper.includes(mode));
  assert.match(wrapper,/strictPickerCancel/);
  assert.match(wrapper,/BBX_OPERATOR_IMPORT_CANCELLED_PICKER/);
  assert.match(wrapper,/mode==='fixture-oversize'&&reason==='SOURCE_SIZE'/);
  assert.match(wrapper,/BBX_OPERATOR_EXPORT_OVERWRITE_DENIED/);
  assert.match(wrapper,/readFileSync\(existing,'utf8'\)===existingBytes/);
  assert.match(wrapper,/MAC_OPERATOR_TRANSFER_OVERWRITE_DENIED/);
  assert.match(native,/puts\("BBX_OPERATOR_IMPORT_CANCELLED_PICKER"\)/);
  assert.match(native,/rejectExistingExport\(xpc_connection_t peer,/);
  assert.match(native,/const char sentinel\[\]="BBX existing destination preserved\\n";/);
  assert.match(native,/if\(exclusiveExport\(payload,destination\)!=87\)return 89;/);
  assert.match(native,/if\(!after\|\|!\[after isEqualToData:expected\]\)return 89;/);
  assert.ok(!source('src/mcp-gateway.mjs').includes('fixture-export-overwrite'));
});

test('negative native diagnostic receipts reject target resolution, cancellation, and unrelated file selection',()=>{
  const allowed={
    'symlink-open':'BBX_OPERATOR_SYMLINK_OPEN_DENIED\n',
    'symlink-picker':'BBX_OPERATOR_SYMLINK_PICKER_DENIED\n',
    'wrong-picker':'BBX_OPERATOR_WRONG_FIXTURE_DENIED\n'
  };
  const receipt=stdout=>({
    status:0,signal:null,error:null,stderr:'',stdout
  });
  for(const [mode,marker] of Object.entries(allowed)){
    assert.equal(assessOperatorNegativeFixture(mode,receipt(marker)),true);
    for(const candidate of [
      {...receipt(marker),status:88},
      {...receipt(marker),signal:'SIGKILL'},
      {...receipt(marker),stderr:'unexpected diagnostic'},
      {...receipt(marker),stdout:marker+'extra'},
      {...receipt(marker),stdout:''}
    ])assert.throws(()=>assessOperatorNegativeFixture(mode,candidate),
      /NOT ACCEPTED/);
  }
  assert.throws(()=>assessOperatorNegativeFixture('symlink-picker',{
    ...receipt('BBX_OPERATOR_SYMLINK_PICKER_RESOLVED_TARGET\n'),status:88
  }),/INCONCLUSIVE/);
  assert.throws(()=>assessOperatorNegativeFixture('symlink-picker',{
    ...receipt('BBX_OPERATOR_SYMLINK_PICKER_CANCELLED\n'),status:88
  }),/NOT ACCEPTED/);
  assert.throws(()=>assessOperatorNegativeFixture('wrong-picker',{
    ...receipt('BBX_OPERATOR_WRONG_PICKER_OTHER_SELECTION\n'),status:88
  }),/NOT ACCEPTED/);
  assert.throws(()=>assessOperatorNegativeFixture('unknown',receipt('')),
    /Unsupported/);
});
test('macro-gated negative fixture paths reuse actual source validation and cannot dispatch to XPC',()=>{
  const wrapper=source('examples/mcp-macos-operator-transfer.mjs');
  const native=source('native/macos/xpc/OperatorTransferHost.m');
  assert.match(wrapper,/const negativeFixture=\['fixture-symlink','fixture-wrong-selection'\]/);
  assert.match(wrapper,/-DBBX_OPERATOR_NEGATIVE_DIAGNOSTICS=1/);
  assert.match(wrapper,/symlinkSync\('bbx-test-target\.txt',link\)/);
  assert.match(wrapper,/negative-fixtures\.jsonl/);
  assert.match(wrapper,/assessOperatorNegativeFixture\(label,observed\)/);
  assert.match(wrapper,/test-symlink-open/);
  assert.match(wrapper,/test-symlink-panel/);
  assert.match(wrapper,/test-wrong-panel/);
  assert.match(native,/#ifdef BBX_OPERATOR_NEGATIVE_DIAGNOSTICS/);
  assert.match(native,/errno!=ELOOP/);
  assert.match(native,/selectedRegularText\(negativeFileURL\(link\),NULL,&why\)/);
  assert.match(native,/selectedRegularText\(url,NULL,&why\)/);
  assert.match(native,/selectedRegularText\(url,allowed,&why\)/);
  assert.match(native,/strcmp\(why,"FIXTURE_MISMATCH"\)/);
  assert.match(native,/selected\.st_ino==l\.st_ino/);
  assert.match(native,/selected\.st_ino!=w\.st_ino/);
  const main=native.slice(native.indexOf('int main('));
  assert.ok(main.indexOf('#ifdef BBX_OPERATOR_NEGATIVE_DIAGNOSTICS')>=0);
  assert.ok(main.indexOf('#ifdef BBX_OPERATOR_NEGATIVE_DIAGNOSTICS')<
    main.indexOf('xpc_connection_create'));
  const normal=wrapper.indexOf('// Fixture path is created by THIS local harness');
  assert.ok(wrapper.indexOf('if(negativeFixture)')<normal);
  assert.ok(wrapper.indexOf('if(negativeFixture)')>wrapper.indexOf('if(buildOnly)'));
});
