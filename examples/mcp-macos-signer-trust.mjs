/**
 * Read-only macOS signer trust probe. The Team ID and signing IDs MUST come
 * from an independently approved release manifest, never from codesign
 * output for the candidate binary being checked.
 *
 * It is impossible to enable MCP_SANDBOX=required through this command.
 */
import {verifyMacDistributionSigner} from '../src/macos-signer-trust.mjs';
const args=process.argv.slice(2);
const fields=new Map();
const options=new Set(['--app','--service','--team-id','--host-id','--worker-id']);
function main(){
  if(args.length!==10 || args.some((value,i)=>i%2===0&&!options.has(value)))
    throw Error('Usage: npm run mcp:mac-signer-trust -- --app /absolute/Host.app --service /absolute/Host.app/Contents/XPCServices/Worker.xpc --team-id PINNEDTEAM --host-id dev.example.host --worker-id dev.example.worker');
  for(let i=0;i<args.length;i+=2) {
    if(fields.has(args[i])||!args[i+1])throw Error('Duplicate or empty signing option.');
    fields.set(args[i],args[i+1]);
  }
  if(fields.size!==5)throw Error('All five identity and path options are required.');
  const result=verifyMacDistributionSigner({
    app:fields.get('--app'),service:fields.get('--service'),
    expectedTeamId:fields.get('--team-id'),
    hostIdentifier:fields.get('--host-id'),
    serviceIdentifier:fields.get('--worker-id')
  });
  console.log('PASS: Apple Developer ID Application requirements satisfied for pinned host and XPC worker identities.');
  console.log('PASS: Nested signature, matching Team ID, hardened runtime and minimal worker App Sandbox entitlements verified.');
  console.log('NOTE: This read-only check does NOT prove live XPC peer authentication, Gatekeeper/notarization, or enable macOS required mode.');
  console.log('Verified identifiers: '+result.hostIdentifier+' / '+result.serviceIdentifier+'; Team ID: '+result.teamId);
}
try{main();}catch(error){console.error('MACOS SIGNER TRUST NOT ACCEPTED: '+error.message);process.exitCode=1;}
