import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,rmSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  verifyMacDistributionSigner,developerIdRequirement,
  inspectMacSignerDisplay,inspectMinimalWorkerEntitlements
} from '../src/macos-signer-trust.mjs';

const team='A1B2C3D4E5',hostId='dev.agentblackbox.signed.host';
const workerId='dev.agentblackbox.signed.worker';
const plist='<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>';
const display=id=>`Executable=/tmp/binary\nIdentifier=${id}\nFormat=app bundle\nCodeDirectory v=20500 flags=0x10000(runtime)\nSignature=size(9000)\nAuthority=Developer ID Application: Independent Test (${team})\nAuthority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=${team}\n`;
function fixture(callback,modify=()=>{}) {
  const root=mkdtempSync(join(tmpdir(),'bb-signer-trust-'));
  const app=join(root,'Host.app');
  const service=join(app,'Contents','XPCServices','Worker.xpc');
  mkdirSync(service,{recursive:true});
  // macOS often aliases /var to /private/var. Production verification uses
  // realpathSync; mocked codesign must recognize those canonical paths too.
  const canonicalApp=realpathSync(app);
  const canonicalService=realpathSync(service);
  const calls=[];
  function run(cmd,args,options){
    calls.push({cmd,args,options});
    const path=args.at(-1);
    let text='';
    if(args.includes('--entitlements'))text=plist;
    else if(args.includes('--display'))text=display(path===canonicalApp?hostId:workerId);
    const response={status:0,stdout:'',stderr:text};
    modify({cmd,args,path,app:canonicalApp,service:canonicalService,response});
    return response;
  }
  try{return callback({app,service,canonicalApp,canonicalService,run,calls});}
  finally{rmSync(root,{force:true,recursive:true});}
}
const valid=(fixtureArgs)=>verifyMacDistributionSigner({
  platform:'darwin',expectedTeamId:team,
  hostIdentifier:hostId,serviceIdentifier:workerId,...fixtureArgs
});
test('explicit requirement pins Apple Developer ID issuer, leaf, bundle identity and quoted team',()=>{
  const req=developerIdRequirement(workerId,team);
  assert.match(req,/anchor apple generic/);
  assert.match(req,/certificate 1\[field\.1\.2\.840\.113635\.100\.6\.2\.6\] exists/);
  assert.match(req,/certificate leaf\[field\.1\.2\.840\.113635\.100\.6\.1\.13\] exists/);
  assert.ok(req.includes('identifier "'+workerId+'"'));
  assert.ok(req.includes('certificate leaf[subject.OU] = "'+team+'"'));
  assert.throws(()=>developerIdRequirement(workerId,'A1;bad'),/Invalid/);
});
test('only explicitly matching Developer ID and sandbox-only XPC worker can be accepted',()=>fixture(f=>{
  const r=valid(f);
  assert.equal(r.trusted,true);
  const req=f.calls.filter(x=>x.args.some(a=>a.startsWith('-R=')));
  assert.equal(req.length,2);
  assert.ok(req[0].args.join(' ').includes(hostId));
  assert.ok(req[1].args.join(' ').includes(workerId));
  assert.ok(f.calls.some(x=>x.args.includes('--deep')));
  // These are resolved native bundle paths even when tmpdir() uses /var.
  assert.ok(f.calls.some(x=>x.args.at(-1)===f.canonicalApp));
  assert.ok(f.calls.some(x=>x.args.at(-1)===f.canonicalService));
  assert.equal(f.calls.length,6);
}));
test('platform, identity, path and missing independently pinned Team ID all fail closed',()=>fixture(f=>{
  assert.throws(()=>verifyMacDistributionSigner({...f,platform:'linux',expectedTeamId:team,hostIdentifier:hostId,serviceIdentifier:workerId}),/macOS/);
  assert.throws(()=>verifyMacDistributionSigner({...f,platform:'darwin',hostIdentifier:hostId,serviceIdentifier:workerId}),/Team ID/);
  assert.throws(()=>verifyMacDistributionSigner({...f,platform:'darwin',expectedTeamId:'evil',hostIdentifier:hostId,serviceIdentifier:workerId}),/Team ID/);
  assert.throws(()=>valid({...f,service:join(f.app,'not-nested.xpc')}),/ENOENT|nested/);
  assert.throws(()=>valid({...f,serviceIdentifier:hostId}),/distinct/);
}));
test('an ad-hoc signature, wrong Team ID, wrong identifier or missing runtime never passes',()=>{
  for(const payload of [
    display(hostId).replace('Signature=size(9000)','Signature=adhoc'),
    display(hostId).replace('TeamIdentifier='+team,'TeamIdentifier=BADBADBAD0'),
    display(workerId),
    display(hostId).replace('0x10000(runtime)','0x0(none)'),
    display(hostId).replace('Authority=Developer ID Application:','Authority=Apple Development:'),
  ])assert.throws(()=>inspectMacSignerDisplay(payload,{teamId:team,identifier:hostId,label:'Host'}));
});
test('unneeded worker entitlement requests and invalid sandbox values fail closed',()=>{
  assert.equal(inspectMinimalWorkerEntitlements(plist),true);
  for(const bad of [
    plist.replace('<true/>','<false/>'),
    plist.replace('</dict>','<key>com.apple.security.network.client</key><true/></dict>'),
    plist.replace('</dict>','<key>com.apple.security.inherit</key><true/></dict>'),
    '<plist><dict></dict></plist>'
  ])assert.throws(()=>inspectMinimalWorkerEntitlements(bad),/entitlement|Sandbox/);
});
test('codesign verification error cannot be converted into a trusted display result',()=>fixture(f=>{
  assert.throws(()=>valid({...f,run:(cmd,args,options)=>{
    if(args.includes('--verify'))return {status:1,stderr:'invalid signature'};
    return f.run(cmd,args,options);
  }}),/verification failed/);
}));
test('metadata mismatch in a signed-looking bundle fails after explicit requirement checks',()=>fixture(f=>{
  assert.throws(()=>valid({...f,run:(cmd,args,options)=>{
    const result=f.run(cmd,args,options);
    if(args.includes('--display')&&!args.includes('--entitlements')&&args.at(-1)===f.canonicalService)
      result.stderr=display(hostId);
    return result;
  }}),/mismatch/);
}));
