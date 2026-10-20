/**
 * v0.8 opt-in native operator import/export acceptance, NOT an MCP tool or
 * released macOS required-mode implementation.
 *
 * Never accept a host filesystem path from the CLI, model, or IPC.
 * AppKit alone selects real source/destination. The sandboxed XPC worker
 * receives only narrow test note names and bounded UTF-8 note contents.
 *
 * Apple Development-signed host/worker; worker checks incoming host OS
 * identity. An HMAC audit records only redacted event metadata. Signing
 * and audit keys are still same-user local, not independent trust anchors.
 */
import {spawnSync} from 'node:child_process';
import {copyFileSync,mkdirSync,mkdtempSync,rmSync,writeFileSync,readFileSync,
  symlinkSync,lstatSync,readlinkSync} from 'node:fs';
import {homedir,tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {AuditStore} from '../src/audit.mjs';
import {
  selectLocalDevelopmentIdentity,parseSignedIdentity,
  describeCodesignFailure
} from './mcp-macos-xpc-signed-peers.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const native=join(root,'native','macos','xpc');
const hostId='dev.agentblackbox.xpc-authority.host';
const workerId='dev.agentblackbox.xpc-authority.worker';
const note=/^bbx-test-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\.txt$/;
const resultPattern=/^BBX_OPERATOR_(IMPORT|EXPORT)_COMMITTED (bbx-test-[a-f0-9-]+\.txt) ([1-9][0-9]{0,3}) ([a-f0-9]{64})\n$/;
const allowedDenials=new Set([
  'XPC_SETUP','FIXTURE_PATH','FIXTURE_MISMATCH','SOURCE_URL',
  'SOURCE_PATH','SOURCE_OPEN','SOURCE_POLICY','SOURCE_SIZE',
  'SOURCE_CHANGED','SOURCE_TEXT','SOURCE_CLOSE','SOURCE_UNKNOWN',
  'NOTE_SCHEMA','NOTE_ENCODING'
]);
const negativeMarkers=Object.freeze({
  'symlink-open':'BBX_OPERATOR_SYMLINK_OPEN_DENIED\n',
  'symlink-picker':'BBX_OPERATOR_SYMLINK_PICKER_DENIED\n',
  'wrong-picker':'BBX_OPERATOR_WRONG_FIXTURE_DENIED\n'
});
/** Test-only results: cancellation, incorrect selection and target resolution
 * must not be accepted as a successful filesystem-boundary test. */
export function assessOperatorNegativeFixture(mode,observed){
  if(!Object.hasOwn(negativeMarkers,mode))
    throw Error('Unsupported native negative fixture.');
  if(mode==='symlink-picker'&&observed?.status===88&&
     observed.stdout==='BBX_OPERATOR_SYMLINK_PICKER_RESOLVED_TARGET\n'&&
     observed.stderr===''&&!observed.signal&&!observed.error)
    throw Error('INCONCLUSIVE: AppKit returned the symlink target inode, not the link. No Touch ID or XPC write was attempted.');
  if(!observed||observed.error||observed.signal||
     observed.status!==0||observed.stderr!==''||
     observed.stdout!==negativeMarkers[mode])
    throw Error('Native '+mode+' negative fixture NOT ACCEPTED: expected exact denial, not cancellation, a different selection, or an unexpected outcome.');
  return true;
}
export function assessOperatorImportDenial(observed){
  if(!observed||observed.status!==87||observed.error||
     observed.signal||observed.stderr!==''||
     typeof observed.stdout!=='string')return null;
  const match=/^BBX_OPERATOR_IMPORT_DENIED_([A-Z_]+)\n$/.exec(observed.stdout);
  return match&&allowedDenials.has(match[1])?match[1]:null;
}

export function assessOperatorTransfer(mode,observed,{requestedName=null}={}){
  if(!['import','export'].includes(mode))
    throw Error('Unsupported native transfer mode.');
  if(!observed||observed.error||observed.signal||
     observed.status!==0||observed.stderr!==''||
     typeof observed.stdout!=='string')
    throw Error('Native operator transfer produced no accepted receipt.');
  const matched=resultPattern.exec(observed.stdout);
  if(!matched||matched[1]!==(mode==='import'?'IMPORT':'EXPORT')||
     !note.test(matched[2])||
     (requestedName!==null&&requestedName!==matched[2])||
     Number(matched[3])>2000)
    throw Error('Native operator transfer receipt invalid.');
  return Object.freeze({noteName:matched[2],byteLength:Number(matched[3]),
    sha256:matched[4]});
}
/**
 * Render compiler failures without printing local home directories, selected
 * file paths, signing identities, or raw (potentially sensitive) diagnostics.
 */
export function summarizeNativeBuildFailure(stderr=''){
  if(typeof stderr!=='string')return 'No compiler diagnostic available.';
  const cleaned=stderr.split(/\r?\n/).flatMap(line=>{
    const source=/(?:^|\/)([A-Za-z][\w.-]*\.(?:m|c|h)):(\d+):(\d+):\s*(fatal\s+)?error:\s*(.*)/.exec(line);
    if(source)return [source[1]+':'+source[2]+':'+source[3]+
      ': '+(source[4]??'')+'error: '+source[5].slice(0,220)];
    const linker=/^(?:ld: |clang: error: )(.*)/.exec(line);
    if(linker)return ['linker/compiler: '+linker[1].replace(/\/[^\s"'():]+/g,'<path>').slice(0,220)];
    return [];
  });
  return cleaned.length?cleaned.slice(0,4).join(' | '):
    'No recognized compiler error line (use xcrun clang locally for diagnostics).';
}
function command(binary,args,label,{timeout=90000}={}){
  const result=spawnSync(binary,args,{
    encoding:'utf8',timeout,maxBuffer:16384,
    env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
  });
  if(result.error||result.signal||result.status!==0){
    const extra=binary==='/usr/bin/codesign'&&args.includes('--sign')?
      ' ('+describeCodesignFailure(result)+')':'';
    const diagnostic=binary==='/usr/bin/xcrun'&&args[0]==='clang'?
      ' — '+summarizeNativeBuildFailure(result.stderr):'';
    throw Error(label+' denied'+extra+diagnostic);
  }
  return result;
}
function signedTeam(path,id){
  const output=command('/usr/bin/codesign',['--display','--verbose=4',path],
                       'Native signed identity inspection');
  return parseSignedIdentity(output.stdout+'\n'+output.stderr,id);
}
function requireSandbox(worker){
  const report=command('/usr/bin/codesign',[
    '--display','--entitlements','-','--xml',worker
  ],'Native worker entitlements');
  const output=report.stdout+'\n'+report.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(output)||
     /<key>com\.apple\.security\.network\.(client|server)<\/key>\s*<true\s*\/>/.test(output))
    throw Error('Signed XPC worker must be sandboxed with no network entitlement.');
}
function build(temp,identity,{negativeDiagnostics=false}={}){
  const app=join(temp,'BlackBoxOperatorTransferHost.app');
  const host=join(app,'Contents','MacOS','BlackBoxOperatorTransferHost');
  const service=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
  const worker=join(service,'Contents','MacOS','BlackBoxAuthorityWorker');
  mkdirSync(dirname(host),{recursive:true});
  mkdirSync(dirname(worker),{recursive:true});
  copyFileSync(join(native,'OperatorTransferHost-Info.plist'),
               join(app,'Contents','Info.plist'));
  copyFileSync(join(native,'AuthorityService-Info.plist'),
               join(service,'Contents','Info.plist'));
  const flags=['-std=c11','-fblocks','-O2','-Wall','-Wextra',
    '-Werror=implicit-function-declaration',
    ...(negativeDiagnostics?['-DBBX_OPERATOR_NEGATIVE_DIAGNOSTICS=1']:[])];
  // xpc_object_t requires explicit xpc_release() in this C/ObjC host.
  // ARC and manual XPC lifetime management must not be mixed.
  command('/usr/bin/xcrun',['clang',...flags,'-o',host,
    join(native,'OperatorTransferHost.m'),'-framework','AppKit',
    '-framework','Foundation','-framework','LocalAuthentication'],
    'Operator transfer native host build');
  command('/usr/bin/xcrun',['clang',...flags,'-DBBX_NATIVE_OPERATOR_TRANSFER=1',
    '-o',worker,join(native,'AuthorityNotesService.m'),
    '-framework','Foundation'],'Operator transfer XPC worker build');
  command('/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',
    '--identifier',workerId,
    '--entitlements',join(root,'native','macos','SandboxProbe.entitlements'),
    service],'Native worker signing');
  command('/usr/bin/codesign',['--force','--sign',identity,'--options','runtime',
    '--identifier',hostId,app],'Native operator host signing');
  command('/usr/bin/codesign',['--verify','--strict','--deep',app],
    'Native host and nested worker seal');
  command('/usr/bin/codesign',['--verify','--strict',service],
    'Native operator worker signature');
  if(signedTeam(app,hostId)!==signedTeam(service,workerId))
    throw Error('Operator transfer host and worker signing Team IDs differ.');
  requireSandbox(service);
  return host;
}
function auditEvent(store,ruleId,decision,outcome,summary,metadata=null){
  store.verify();
  store.add({
    id:randomUUID(),timestamp:new Date().toISOString(),
    runId:'mac-operator-transfer-v0.8',
    agentId:'trusted-local-operator',source:'native-macos-operator-transfer',
    tool:'native.operator.transfer',
    input:'Opt-in interactive native file picker; host paths omitted',
    decision,outcome,risk:'high',riskScore:85,ruleId,
    summary,reason:summary,durationMs:0,
    ...(metadata===null?{}:{approvalId:metadata.noteName,
      transferBytes:metadata.byteLength,
      transferSHA256:metadata.sha256})
  });
  store.verify();
}
async function main(){
  if(process.platform!=='darwin')
    throw Error('Interactive macOS required.');
  if(process.env.MCP_SANDBOX!=='off')
    throw Error('Explicit MCP_SANDBOX=off required; normal MCP gateway is unchanged.');
  const mode=process.argv[2],name=process.argv[3]??null;
  const buildOnly=mode==='build-check'&&process.argv.length===3;
  const fixtureImport=['fixture-import','fixture-oversize','fixture-cancel']
    .includes(mode)&&process.argv.length===3;
  const negativeFixture=['fixture-symlink','fixture-wrong-selection']
    .includes(mode)&&process.argv.length===3;
  const rejectOverwrite=mode==='fixture-export-overwrite'&&
    process.argv.length===4&&note.test(name??'');
  if(!buildOnly&&!fixtureImport&&!negativeFixture&&!rejectOverwrite&&(!(['import','export'].includes(mode))||
     (mode==='import'&&process.argv.length!==3)||
     (mode==='export'&&(process.argv.length!==4||!note.test(name)))))
    throw Error('Use build-check, fixture-import, fixture-cancel, fixture-oversize, fixture-symlink, fixture-wrong-selection, import, export <note>, or fixture-export-overwrite <note>.');
  const identity=selectLocalDevelopmentIdentity(command('/usr/bin/security',[
    'find-identity','-v','-p','codesigning'
  ],'Apple Development identity lookup').stdout);
  const temp=mkdtempSync(join(tmpdir(),'bbx-native-operator-transfer-'));
  try {
    const host=build(temp,identity,{negativeDiagnostics:negativeFixture});
    if(buildOnly){
      console.log('PASS: Operator native host compiled; Apple Development host/XPC signatures, Team IDs and App Sandbox entitlements verified. No picker, Touch ID, transfer or HMAC audit was launched.');
      return;
    }
    if(negativeFixture){
      // Test data and its paths exist only in this private disposable folder.
      // No real source is imported, Touch ID is never requested, and the XPC
      // service is never connected by these macro-gated native entry points.
      const nativeDiagnostic=(args,label)=>{
        const observed=spawnSync(host,args,{
          encoding:'utf8',timeout:130000,maxBuffer:4096,
          env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
        });
        assessOperatorNegativeFixture(label,observed);
      };
      const audit=new AuditStore(join(temp,'negative-fixtures.jsonl'),{
        externalReceiptFile:null
      });
      if(mode==='fixture-symlink'){
        const target=join(temp,'bbx-test-target.txt');
        const link=join(temp,'bbx-test-link.txt');
        const content='BBX disposable symlink target\n';
        writeFileSync(target,content,{mode:0o600,flag:'wx'});
        symlinkSync('bbx-test-target.txt',link);
        if(!lstatSync(link).isSymbolicLink()||
           !lstatSync(target).isFile()||
           readlinkSync(link)!=='bbx-test-target.txt'||
           readFileSync(target,'utf8')!==content)
          throw Error('Disposable symlink fixture not established.');
        nativeDiagnostic(['test-symlink-open',link,target],'symlink-open');
        auditEvent(audit,'MAC_OPERATOR_SYMLINK_OPEN_DENIED','block','blocked',
          'O_NOFOLLOW denied exact disposable symbolic-link source; no XPC or Touch ID.');
        console.log('PASS: Native selected-file opener rejected the exact disposable symlink with O_NOFOLLOW; no picker, Touch ID or XPC.');
        console.log('ACTION: In the native picker select ONLY bbx-test-link.txt (symbolic link); do not select the regular target or approve Touch ID.');
        nativeDiagnostic(['test-symlink-panel',link,target],'symlink-picker');
        auditEvent(audit,'MAC_OPERATOR_SYMLINK_PICKER_DENIED','block','blocked',
          'AppKit returned exact link inode; native opener rejected it before Touch ID/XPC.');
        console.log('PASS: AppKit returned the selected symlink inode and the native source opener rejected it before Touch ID or XPC.');
      }else{
        const allowed=join(temp,'bbx-test-allowed.txt');
        const wrong=join(temp,'bbx-test-other.txt');
        writeFileSync(allowed,'BBX allowed disposable fixture\n',
          {mode:0o600,flag:'wx'});
        writeFileSync(wrong,'BBX intentionally wrong disposable fixture\n',
          {mode:0o600,flag:'wx'});
        if(!lstatSync(allowed).isFile()||!lstatSync(wrong).isFile()||
           lstatSync(allowed).ino===lstatSync(wrong).ino)
          throw Error('Distinct disposable fixture files not established.');
        console.log('ACTION: In the native picker select ONLY bbx-test-other.txt (the WRONG fixture). Do not select allowed file or approve Touch ID.');
        nativeDiagnostic(['test-wrong-panel',allowed,wrong],'wrong-picker');
        auditEvent(audit,'MAC_OPERATOR_WRONG_FIXTURE_DENIED','block','blocked',
          'Independently verified wrong-file inode denied by native FIXTURE_MISMATCH before Touch ID/XPC.');
        console.log('PASS: Exact wrong fixture selection produced native FIXTURE_MISMATCH before Touch ID or XPC.');
      }
      audit.verify();
      console.log('PASS: Disposable negative-fixture HMAC audit verified; no files or paths imported into XPC.');
      return;
    }
    // Fixture path is created by THIS local harness, never read from an
    // agent/MCP argument. The native panel must independently select this
    // exact inode; the path is only a UI starting point and negative gate.
    const fixture=fixtureImport?
      join(temp,'bbx-test-operator-fixture.txt'):null;
    if(fixture!==null)
      writeFileSync(fixture,mode==='fixture-oversize'?'X'.repeat(2001):
        'BBX disposable operator transfer fixture\n',
        {mode:0o600,flag:'wx'});
    const existing=rejectOverwrite?
      join(temp,'bbx-test-preexisting.txt'):null;
    const existingBytes='BBX existing destination preserved\n';
    if(existing!==null)
      writeFileSync(existing,existingBytes,{mode:0o600,flag:'wx'});
    const folder=join(homedir(),'Library','Application Support',
                      'AgentBlackBox','OperatorTransfer');
    mkdirSync(folder,{recursive:true,mode:0o700});
    const store=new AuditStore(join(folder,'operator-transfers.jsonl'),{
      externalReceiptFile:null
    });
    auditEvent(store,'MAC_OPERATOR_TRANSFER_OPENED','review','pending',
      'Separate signed native operator transfer initiated; no operation claimed.');
    console.log('PASS: Native operator host and sandboxed XPC worker verified with matching Apple Team ID; worker requires OS-verified incoming host.');
    console.log(rejectOverwrite?
      'ACTION: Verify the native host refuses exclusive export onto a disposable preexisting file. No picker or Touch ID is needed for the negative test.':
      mode==='fixture-cancel'?
      'ACTION: Click Cancel in the native file picker. Do NOT select a file or approve Touch ID.':
      mode==='fixture-oversize'?
      'ACTION: Select ONLY bbx-test-operator-fixture.txt (2001 bytes). It MUST deny before Touch ID/XPC.':
      fixtureImport?
      'ACTION: Select ONLY bbx-test-operator-fixture.txt from the opened private test directory; approve Touch ID only for this generated fixture.':
      mode==='import'?
      'ACTION: Select one small, NON-SENSITIVE text file in the native Open Panel and approve fresh Touch ID.':
      'ACTION: Choose a NEW export destination in the Save Panel and approve fresh Touch ID. Existing files are never overwritten.');
    const observed=spawnSync(host,rejectOverwrite?
      ['export-overwrite-test',name,existing]:
      fixtureImport?['import-fixture',fixture]:
      mode==='import'?[mode]:[mode,name],{
      encoding:'utf8',timeout:130000,maxBuffer:4096,
      env:{PATH:'/usr/bin:/bin',LANG:'C',HOME:homedir(),TMPDIR:tmpdir()}
    });
    if(rejectOverwrite){
      if(!observed.error&&!observed.signal&&observed.status===0&&
         observed.stdout==='BBX_OPERATOR_EXPORT_OVERWRITE_DENIED\n'&&
         observed.stderr===''&&
         readFileSync(existing,'utf8')===existingBytes){
        auditEvent(store,'MAC_OPERATOR_TRANSFER_OVERWRITE_DENIED','block','blocked',
          'Existing exclusive-export fixture retained exact original bytes; no write or overwrite accepted.');
        console.log('PASS: Native signed XPC export rejected the existing destination and verified unchanged original fixture bytes.');
        return;
      }
      auditEvent(store,'MAC_OPERATOR_TRANSFER_UNCERTAIN','block','error',
        'Existing export fixture was not proven unchanged; investigate manually.');
      throw Error('Native exclusive-export overwrite negative acceptance failed.');
    }
    const strictPickerCancel=fixtureImport&&observed.status===83&&
      !observed.error&&!observed.signal&&observed.stderr===''&&
      observed.stdout==='BBX_OPERATOR_IMPORT_CANCELLED_PICKER\n';
    const biometricCancel=observed.status===83&&!observed.error&&
      !observed.signal&&observed.stderr===''&&observed.stdout==='';
    if(strictPickerCancel||biometricCancel){
      if(mode==='fixture-oversize')
        throw Error('Oversized file must be explicitly rejected, not cancelled.');
      if(mode==='fixture-cancel'&&!strictPickerCancel)
        throw Error('Fixture negative gate requires explicit picker cancellation before Touch ID.');
      auditEvent(store,'MAC_OPERATOR_TRANSFER_CANCELLED','block','blocked',
        strictPickerCancel?'Native file picker explicitly cancelled before dispatch.':
          'Native operator authorization explicitly cancelled.');
      console.log('PASS: Operator cancellation denied the transfer; no receipt accepted.');
      return;
    }
    const reason=(mode==='import'||fixtureImport)?
      assessOperatorImportDenial(observed):null;
    if(reason!==null){
      auditEvent(store,'MAC_OPERATOR_TRANSFER_DENIED','block','blocked',
        'Native pre-dispatch file selection denied at '+reason+
        '; no XPC file write was attempted.');
      if(mode==='fixture-oversize'&&reason==='SOURCE_SIZE'){
        console.log('PASS: Exact selected 2001-byte fixture rejected before Touch ID and XPC dispatch; HMAC denial recorded.');
        return;
      }
      throw Error('Native import safely rejected before XPC dispatch: '+reason+
        '. No file path or contents were logged.');
    }
    if(mode==='fixture-oversize'||mode==='fixture-cancel'){
      auditEvent(store,'MAC_OPERATOR_TRANSFER_UNEXPECTED','block','error',
        'Negative fixture unexpectedly progressed beyond its specified denial.');
      throw Error('Negative fixture did not produce required explicit denial.');
    }
    if(observed.status===87&&!observed.error&&!observed.signal&&
       observed.stdout===''&&observed.stderr===''){
      auditEvent(store,'MAC_OPERATOR_TRANSFER_DENIED','block','blocked',
        'Native filesystem precondition rejected transfer before committed receipt.');
      throw Error('Native transfer rejected without an accepted receipt.');
    }
    let evidence;
    try{
      evidence=assessOperatorTransfer(fixtureImport?'import':mode,
        observed,{requestedName:fixtureImport?null:name});
    }catch{
      auditEvent(store,'MAC_OPERATOR_TRANSFER_UNCERTAIN','block','error',
        'No authenticated end-to-end native receipt; possible write must not be automatically retried.');
      throw Error('Unknown native transfer outcome; manually reconcile, NEVER retry automatically.');
    }
    auditEvent(store,'MAC_OPERATOR_TRANSFER_NATIVE_RECEIPT','allow','native-test-committed',
      'Native host reported completed bounded transfer; not a production MCP approval.',evidence);
    console.log('PASS: Native Touch ID and user-selected '+
      (fixtureImport?'import':mode)+
      ' produced an accepted bounded XPC receipt; HMAC metadata audit verified.');
    console.log('NOTE: '+evidence.noteName+
      ' ('+evidence.byteLength+' bytes, SHA256 '+evidence.sha256+').');
    console.log('NOTE: Operator-only test, not a production transfer grant. MCP required mode stays disabled.');
  }finally{rmSync(temp,{recursive:true,force:true});}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))
  main().catch(error=>{
    console.error('MAC OPERATOR TRANSFER NOT ACCEPTED: '+error.message);
    process.exitCode=1;
  });
