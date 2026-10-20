/**
 * macOS v0.8 developer-only REQUIRED MCP native launcher.
 *
 * The control plane stays in Node; ONLY fixed note reads and exclusive
 * note creates cross to a signed native host and an OS App Sandbox XPC worker.
 * No arbitrary filesystem transfer, shell execution or network delegation.
 * The signed bundle is installed explicitly by the operator. Required-mode
 * startup refuses missing, unsigned, mismatched, or moved identities.
 *
 * Threat limits: same-user compromise of this locally writable trust pin or
 * Node controller, and production distribution/notarization, remain OUTSIDE
 * the prototype's proven isolation guarantee.
 */
import {spawnSync} from 'node:child_process';
import {lstatSync,readFileSync,realpathSync,statSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {homedir,tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {parseBridgeReply} from './macos-xpc-bridge-wire.mjs';
import {validateMacWorkspaceBinding} from './macos-workspace-binding.mjs';
import {parseSignedIdentity} from '../examples/mcp-macos-xpc-signed-peers.mjs';

export const MAC_NATIVE_REQUIRED_DIR=join(homedir(),'Library',
  'Application Support','AgentBlackBox','RequiredNativeMcp');
export const MAC_NATIVE_REQUIRED_APP='BlackBoxAuthorityHost.app';
const HOST_ID='dev.agentblackbox.xpc-authority.host';
const WORKER_ID='dev.agentblackbox.xpc-authority.worker';
const TEAM=/^[A-Z0-9]{10}$/;

export function assertMacRequiredPin(pin){
  if(!pin||typeof pin!=='object'||Array.isArray(pin)||
     Object.keys(pin).sort().join(',')!=='teamId,version'||
     pin.version!==1||typeof pin.teamId!=='string'||!TEAM.test(pin.teamId))
    throw Error('Invalid required native MCP trust pin; refusing launch.');
  return pin.teamId;
}
function secureFile(path,isDir){
  const stat=lstatSync(path);
  if(stat.isSymbolicLink()||stat.uid!==process.getuid?.()||
     (isDir?!stat.isDirectory():!stat.isFile()||stat.nlink!==1)||
     (stat.mode&0o077)!==0)
    throw Error('Native MCP installation or pin is not private, owner-owned, and non-symlink.');
  if(realpathSync(path)!==path)throw Error('Native MCP trust path is noncanonical.');
}
function command(binary,args,label,{input=undefined,maxBuffer=8192,timeout=12000}={}){
  const result=spawnSync(binary,args,{
    input,timeout,maxBuffer,encoding:input===undefined?'utf8':null,
    env:{PATH:'/usr/bin:/bin',HOME:homedir(),TMPDIR:tmpdir(),LANG:'C'}
  });
  if(result.error||result.signal||result.status!==0)
    throw Error(label+' failed closed; no native MCP launched.');
  return result;
}
function signedTeam(path,id){
  const result=command('/usr/bin/codesign',['--display','--verbose=4',path],
    'Native signing identity inspection');
  return parseSignedIdentity(result.stdout+'\n'+result.stderr,id);
}
function verifySandbox(service){
  const r=command('/usr/bin/codesign',
    ['--display','--entitlements','-','--xml',service],
    'Native XPC sandbox entitlements');
  const xml=r.stdout+'\n'+r.stderr;
  if(!/<key>com\.apple\.security\.app-sandbox<\/key>\s*<true\s*\/>/.test(xml)||
     /<key>com\.apple\.security\.network\.(client|server)<\/key>\s*<true\s*\/>/.test(xml))
    throw Error('Required XPC worker lacks correct App Sandbox/no-network rights.');
}
export function verifyMacRequiredInstallation({directory=MAC_NATIVE_REQUIRED_DIR,
  platform=process.platform}={}){
  if(platform!=='darwin')
    throw Error('Required native MCP host is macOS-only.');
  if(directory!==MAC_NATIVE_REQUIRED_DIR)
    throw Error('Native MCP install root is fixed, not caller-selected.');
  secureFile(directory,true);
  const pinPath=join(directory,'trust-pin.json');
  secureFile(pinPath,false);
  const team=assertMacRequiredPin(JSON.parse(readFileSync(pinPath,'utf8')));
  const app=join(directory,MAC_NATIVE_REQUIRED_APP);
  const host=join(app,'Contents','MacOS','BlackBoxAuthorityHost');
  const service=join(app,'Contents','XPCServices','BlackBoxAuthorityWorker.xpc');
  const worker=join(service,'Contents','MacOS','BlackBoxAuthorityWorker');
  for(const path of [app,host,service,worker]){
    const st=lstatSync(path);
    if(st.isSymbolicLink()||st.uid!==process.getuid?.()||
       realpathSync(path)!==path)
      throw Error('Native MCP app contains an untrusted path.');
  }
  command('/usr/bin/codesign',['--verify','--strict','--deep',app],
    'Required signed macOS host+worker');
  command('/usr/bin/codesign',['--verify','--strict',service],
    'Required native XPC worker seal');
  if(signedTeam(app,HOST_ID)!==team||signedTeam(service,WORKER_ID)!==team)
    throw Error('Native MCP host/worker do not match independently enrolled Team ID.');
  verifySandbox(service);
  return Object.freeze({host,app,service,teamId:team});
}
export function probeMacRequiredWorkspace(host){
  if(typeof host!=='string'||!host.startsWith('/'))
    throw Error('Required signed native host unavailable.');
  const result=command(host,[], 'Required signed native XPC workspace handshake',
    {input:Buffer.from('ROOT - 0\n','ascii'),timeout:11000,maxBuffer:2500});
  const response=parseBridgeReply(result.stdout);
  if(!response.ok||typeof response.content!=='string')
    throw Error('Required native worker workspace report refused.');
  return response.content;
}
export function planMacRequiredMcp({env=process.env,workspaceRoot,
  platform=process.platform,nodePath=process.execPath,
  verify=verifyMacRequiredInstallation,probe=probeMacRequiredWorkspace,
  bind=validateMacWorkspaceBinding}={}){
  if(platform!=='darwin')
    throw Error('Native required MCP is only for macOS.');
  if(!workspaceRoot||typeof env.MCP_WORKSPACE_ROOT!=='string')
    throw Error('Native MCP requires an explicitly configured, exact worker-owned MCP_WORKSPACE_ROOT.');
  if(env.MCP_WORKSPACE_ROOT!==workspaceRoot)
    throw Error('MCP_WORKSPACE_ROOT differs from canonical workspace.');
  const {host}=verify({platform});
  const reportedRoot=probe(host);
  bind({configuredRoot:workspaceRoot,reportedRoot,platform});
  if(!nodePath.startsWith('/'))
    throw Error('Required-mode Node executable must be absolute.');
  return Object.freeze({
    command:nodePath,
    args:[fileURLToPath(new URL('../examples/mcp-macos-xpc-mcp-downstream.mjs',
      import.meta.url))],
    env:Object.freeze({
      HOME:homedir(),TMPDIR:tmpdir(),PATH:'/usr/bin:/bin',LANG:'C.UTF-8',
      MCP_SANDBOX:'required',BLACKBOX_NATIVE_REQUIRED_XPC_HOST:host,
      BLACKBOX_WORKSPACE_ROOT:workspaceRoot
    }),
    enabled:true,
    description:'macOS Apple Development-signed, OS peer-gated XPC App Sandbox worker (test namespace only)'
  });
}
