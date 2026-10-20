/**
 * Explicit Linux OS sandbox for the bundled downstream MCP server.
 * No best-effort fallback: requested sandboxing either starts or refuses.
 * macOS Node CLI is not a signed/entitled Apple App Sandbox helper.
 */
import { realpathSync, lstatSync, existsSync, readlinkSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { planMacRequiredMcp } from './macos-required-mcp.mjs';

const ROOT_SYSTEM = Object.freeze(['/usr', '/lib', '/lib64', '/bin', '/sbin']);
const OPTIONAL_FILES = Object.freeze(['/etc/ld.so.cache']);
const envSafe = workspaceRoot => ({
  BLACKBOX_WORKSPACE_ROOT: workspaceRoot, LANG: 'C.UTF-8',
  HOME: '/tmp', TMPDIR: '/tmp', PATH: '/usr/bin:/bin', NODE_ENV: 'production'
});
function ancestors(path) {
  const parts=[];
  let p=dirname(path);
  while(p!==sep && p!=='.') {parts.push(p);p=dirname(p);}
  return parts.reverse();
}
function isUnder(path, prefix) { return path===prefix || path.startsWith(prefix+sep); }

/** Pure builder; `platform` is injectable for deterministic policy tests. */
export function planMcpSandbox({mode='off',platform=process.platform,nodePath=process.execPath,scriptPath,workspaceRoot,bwrap='/usr/bin/bwrap'}={}) {
  if(!['off','required'].includes(mode)) throw Error('MCP_SANDBOX must be off or required.');
  const workspace = realpathSync(workspaceRoot);
  const script = realpathSync(scriptPath);
  const node = realpathSync(nodePath);
  const childEnv=envSafe(workspace);
  if(mode==='off') return {command:node,args:[script],env:childEnv,enabled:false,description:'disabled (explicit local demo mode)'};
  if(platform!=='linux') throw Error('MCP_SANDBOX=required is only supported on Linux with Bubblewrap. macOS requires a signed App Sandbox helper; no unsandboxed fallback.');
  if(!bwrap.startsWith('/') || bwrap.includes('\0')) throw Error('Bubblewrap must be an absolute executable path.');
  const executable = realpathSync(bwrap);
  const options=['--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts',
    '--unshare-net','--new-session','--die-with-parent'];
  // Only mount executable/runtime and the *specific* audited source files.
  for(const system of ROOT_SYSTEM) {
    if(!existsSync(system))continue;
    const s=lstatSync(system);
    if(s.isSymbolicLink()) options.push('--symlink',readlinkSync(system),system);
    else if(s.isDirectory()) options.push('--ro-bind',system,system);
  }
  for(const file of OPTIONAL_FILES) if(existsSync(file) && lstatSync(file).isFile()) options.push('--ro-bind',file,file);
  const sourceFiles=[node,script,resolve(dirname(script),'../src/policy.mjs'),resolve(dirname(script),'../src/mcp-wire.mjs')];
  const unique = new Set(sourceFiles.map(x=>realpathSync(x)));
  const bindFiles=[...unique].filter(path=>!ROOT_SYSTEM.some(prefix=>isUnder(path,prefix)));
  const targets=[...bindFiles,workspace];
  const dirs=new Set(targets.flatMap(ancestors).filter(path=>!ROOT_SYSTEM.some(prefix=>isUnder(path,prefix))));
  for(const dir of [...dirs].sort((a,b)=>a.length-b.length)) options.push('--dir',dir);
  for(const path of bindFiles) options.push('--ro-bind',path,path);
  // The ONLY writable host mount is the demo workspace. No home, no project
  // root, no audit key/checkpoint, and no network namespace.
  options.push('--proc','/proc','--dev','/dev','--tmpfs','/tmp','--bind',workspace,workspace,'--chdir','/');
  return {command:executable,args:[...options,'--',node,script],env:childEnv,enabled:true,description:'Linux Bubblewrap namespaces (no network, workspace-only write mount)'};
}

export function downstreamLaunch({env=process.env,workspaceRoot,scriptPath,platform=process.platform,nodePath=process.execPath}={}) {
  const mode = env.MCP_SANDBOX ?? 'off';
  if (mode==='required') {
    if(platform==='darwin')return planMacRequiredMcp({env,workspaceRoot,platform,nodePath});
    if(platform!=='linux')return planMcpSandbox({mode,platform,workspaceRoot,scriptPath,nodePath});
    const tool = env.MCP_BWRAP_PATH || '/usr/bin/bwrap';
    // Verify availability in advance; failure is fatal, not a downgrade.
    const check = spawnSync(tool,['--version'],{timeout:3000,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
    if(check.error || check.status!==0)throw Error('Bubblewrap unavailable; MCP_SANDBOX=required refuses unsandboxed launch.');
    return planMcpSandbox({mode,platform,workspaceRoot,scriptPath,nodePath,bwrap:tool});
  }
  return planMcpSandbox({mode,platform,workspaceRoot,scriptPath,nodePath});
}
