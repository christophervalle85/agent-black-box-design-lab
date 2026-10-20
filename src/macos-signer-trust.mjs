/**
 * Fail-closed, read-only macOS distribution-signing acceptance diagnostic.
 * This is NOT wired into the gateway, and cannot enable required mode.
 *
 * An externally pinned Developer ID Team ID and signing identifiers are
 * checked against Apple's *cryptographic* code-signing requirements.
 * Displayed TeamIdentifier/Authority strings are additional consistency
 * checks, NOT a substitute for Apple verifying the explicit requirement.
 *
 * Official references: Apple TN3127 and Creating distribution-signed
 * code for macOS.
 */
import {spawnSync} from 'node:child_process';
import {realpathSync} from 'node:fs';
import {dirname,join,resolve,isAbsolute,basename} from 'node:path';

const TEAM=/^[A-Z0-9]{10}$/;
const IDENTIFIER=/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;
const DEVELOPER_ID_ISSUER='1.2.840.113635.100.6.2.6';
const DEVELOPER_ID_APPLICATION='1.2.840.113635.100.6.1.13';

function checkIdentity(expectedTeamId,hostIdentifier,serviceIdentifier) {
  if(typeof expectedTeamId!=='string'||!TEAM.test(expectedTeamId))
    throw Error('A separately pinned, 10-character uppercase Apple Team ID is required.');
  if(typeof hostIdentifier!=='string'||!IDENTIFIER.test(hostIdentifier) ||
     typeof serviceIdentifier!=='string'||!IDENTIFIER.test(serviceIdentifier) ||
     hostIdentifier===serviceIdentifier)
    throw Error('Two distinct, explicit signing identifiers are required.');
}
export function developerIdRequirement(identifier,teamId) {
  if(!TEAM.test(teamId)||!IDENTIFIER.test(identifier))
    throw Error('Invalid signing requirement input.');
  // Quote the Team ID even when it begins with a digit (Apple DTS guidance).
  // Limit this gate to Developer ID Application certificates; do not accept
  // arbitrary Apple Development, Mac App Store or ad-hoc signatures.
  return 'anchor apple generic and identifier "'+identifier+
    '" and certificate 1[field.'+DEVELOPER_ID_ISSUER+
    '] exists and certificate leaf[field.'+DEVELOPER_ID_APPLICATION+
    '] exists and certificate leaf[subject.OU] = "'+teamId+'"';
}

export function inspectMacSignerDisplay(display,{teamId,identifier,label}) {
  if(typeof display!=='string')throw Error(label+': missing code-signing metadata.');
  if(/\bSignature=adhoc\b/i.test(display)||
     /\bSignature=adhoc\b/i.test(display.replace(/\s+/g,' ')))
    throw Error(label+': ad-hoc signature is not a production identity.');
  const observedId=/^Identifier=(.+)$/m.exec(display)?.[1]?.trim();
  const observedTeam=/^TeamIdentifier=(.+)$/m.exec(display)?.[1]?.trim();
  if(observedId!==identifier || observedTeam!==teamId)
    throw Error(label+': expected signing identifier or Team ID mismatch.');
  if(!/^Authority=Developer ID Application:/m.test(display))
    throw Error(label+': Developer ID Application leaf certificate absent.');
  if(!/\bflags=0x[0-9a-f]+\([^\r\n]*\bruntime\b[^\r\n]*\)/im.test(display))
    throw Error(label+': hardened runtime flag not confirmed.');
  return true;
}

export function inspectMinimalWorkerEntitlements(xml) {
  if(typeof xml!=='string'||!/<plist\b/.test(xml)||!/<dict>/.test(xml))
    throw Error('XPC worker entitlements unavailable or malformed.');
  const keys=[...xml.matchAll(/<key>([^<]*)<\/key>/g)].map(x=>x[1]);
  if(keys.length!==1||keys[0]!=='com.apple.security.app-sandbox'||
     !/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('XPC worker must have only the App Sandbox entitlement.');
  return true;
}

export function verifyMacDistributionSigner({
  app,service,expectedTeamId,hostIdentifier,serviceIdentifier,
  platform=process.platform,run=spawnSync,canonicalize=realpathSync
}={}) {
  if(platform!=='darwin')throw Error('Distribution signing must be checked on macOS.');
  checkIdentity(expectedTeamId,hostIdentifier,serviceIdentifier);
  if(typeof app!=='string'||typeof service!=='string'||
     !isAbsolute(app)||!isAbsolute(service))
    throw Error('App and nested XPC service must be explicit absolute paths.');
  const appPath=canonicalize(resolve(app));
  const servicePath=canonicalize(resolve(service));
  if(!appPath.endsWith('.app')||!servicePath.endsWith('.xpc') ||
     dirname(servicePath)!==join(appPath,'Contents','XPCServices') ||
     !basename(servicePath).endsWith('.xpc'))
    throw Error('XPC service is not directly nested in the expected app.');
  const codesign=(args,label)=>{
    const result=run('/usr/bin/codesign',args,{encoding:'utf8',timeout:15000,maxBuffer:128*1024});
    if(result?.error || result?.status!==0 || result?.signal)
      throw Error(label+': Apple code-signing verification failed (no trust fallback).');
    return (result.stdout??'')+'\n'+(result.stderr??'');
  };
  // The app's nested code seal must validate before either identity is
  // accepted. Each leaf then needs its *own* Apple-issued certificate
  // requirement (host ID, service ID, same separately pinned Team ID).
  codesign(['--verify','--strict','--deep','--verbose=2',appPath],'Nested app seal');
  for(const [path,identifier,label] of [
    [appPath,hostIdentifier,'Host app'],
    [servicePath,serviceIdentifier,'XPC worker']
  ]) {
    const requirement=developerIdRequirement(identifier,expectedTeamId);
    codesign(['--verify','--strict','--verbose=2','-R='+requirement,path],label);
    const displayed=codesign(['--display','--verbose=4',path],label+' identity');
    inspectMacSignerDisplay(displayed,{teamId:expectedTeamId,identifier,label});
  }
  const workerEntitlements=codesign(['--display','--entitlements','-','--xml',servicePath],
    'XPC worker entitlements');
  inspectMinimalWorkerEntitlements(workerEntitlements);
  return Object.freeze({
    trusted:true,teamId:expectedTeamId,hostIdentifier,serviceIdentifier,
    appPath,servicePath,
    assertion:'Apple Developer ID Application requirement verified on both signed bundles.'
  });
}
