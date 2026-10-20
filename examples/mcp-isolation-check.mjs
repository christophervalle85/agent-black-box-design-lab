/**
 * Real Linux sandbox acceptance: identical downstream mount/namespace plan,
 * substituting only a harmless diagnostic Node command.
 */
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readlinkSync, realpathSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { downstreamLaunch } from '../src/sandbox.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
if (process.platform !== 'linux' || process.env.MCP_SANDBOX !== 'required') {
  console.error('FAIL: Linux and MCP_SANDBOX=required are necessary.');
  process.exit(1);
}
const workspace = realpathSync(resolve(process.env.MCP_WORKSPACE_ROOT ?? join(root,'demo-workspace')));
const temporary = mkdtempSync(join(homedir(), '.blackbox-isolation-'));
const privateFile = join(temporary,'host-only.txt');
const proof = join(workspace, 'isolation-proof-' + randomUUID() + '.txt');
const probe = [
  "const fs=require('node:fs'),net=require('node:net');",
  "const [secret,proof,hostMount,hostNet]=process.argv.slice(1);",
  "function check(name,ok,info=''){console.log((ok?'PASS':'FAIL')+': '+name+(info?' ('+info+')':''));if(!ok)process.exitCode=1;}",
  "try{const profile=fs.readFileSync('/proc/self/attr/current','utf8').trim();check('AppArmor enforcing child',profile.includes('unpriv_bwrap')&&profile.includes('(enforce)'),profile);}catch(e){check('AppArmor enforcing child',false,e.code||e.message);}",
  "for(const [label,ns,host] of [['Mount namespace','mnt',hostMount],['Network namespace','net',hostNet]]){try{const child=fs.readlinkSync('/proc/self/ns/'+ns);check(label+' differs from host',child!==host,child);}catch(e){check(label+' differs from host',false,e.code||e.message);}}",
  "try{fs.readFileSync(secret);check('Host-only file denied',false);}catch(e){check('Host-only file denied',['ENOENT','EACCES','EPERM'].includes(e.code),e.code);}",
  "try{fs.writeFileSync(proof,'sandbox-workspace-proof\\n',{flag:'wx',mode:0o600});check('Workspace write allowed',true);}catch(e){check('Workspace write allowed',false,e.code||e.message);}",
  "const sock=net.createConnection({host:'1.1.1.1',port:443});sock.setTimeout(3000);",
  "sock.once('connect',()=>{check('External TCP denied',false,'connected');sock.destroy();});",
  "sock.once('error',e=>check('External TCP denied',['ENETUNREACH','EHOSTUNREACH','EACCES','EPERM'].includes(e.code),e.code));",
  "sock.once('timeout',()=>{check('External TCP denied',false,'timeout is inconclusive');sock.destroy();});"
].join('\n');
let passed=false;
try {
  writeFileSync(privateFile,'host-only test file\n',{mode:0o600});
  const launch=downstreamLaunch({env:process.env,workspaceRoot:workspace,scriptPath:join(root,'examples/mcp-notes-server.mjs')});
  if(!launch.enabled || !launch.args.at(-1)?.endsWith('mcp-notes-server.mjs'))throw Error('Unexpected downstream launch plan.');
  const result=spawnSync(launch.command,[
    ...launch.args.slice(0,-1),'-e',probe,privateFile,proof,
    readlinkSync('/proc/self/ns/mnt'),readlinkSync('/proc/self/ns/net')
  ],{env:launch.env,encoding:'utf8',timeout:12000,maxBuffer:1024*1024});
  if(result.stdout)process.stdout.write(result.stdout);
  if(result.stderr)process.stderr.write(result.stderr);
  const observed=existsSync(proof)&&readFileSync(proof,'utf8')==='sandbox-workspace-proof\n';
  console.log((observed?'PASS':'FAIL')+': Host observed workspace write');
  if(result.error)console.error(result.error.message);
  passed=result.status===0&&!result.error&&observed;
}catch(e){
  console.error('FAIL: Isolation setup: '+e.message);
}finally{
  rmSync(temporary,{recursive:true,force:true});
  if(existsSync(proof))unlinkSync(proof);
}
if(!passed)process.exitCode=1;
