/**
 * Phase 2D EXPERIMENTAL: fail-closed comparison of the gateway's configured
 * policy workspace and the separately sandboxed XPC worker's actual storage.
 *
 * This is NOT signer attestation or a license to execute MCP requests.
 */
import {lstatSync,realpathSync,statSync} from 'node:fs';
import {resolve} from 'node:path';
const CONTAINER_DOCUMENTS=/\/Library\/Containers\/[^/]+\/Data\/Documents\/AgentBlackBoxScratchNotes$/;
const isString=v=>typeof v==='string'&&v.length>0&&v.length<=4096&&!v.includes('\0');

export function validateMacWorkspaceBinding({configuredRoot,reportedRoot,platform=process.platform}={}) {
  if(platform!=='darwin')throw Error('Native App Sandbox workspace validation requires macOS.');
  if(!isString(configuredRoot)||!isString(reportedRoot))
    throw Error('Both MCP and XPC workspace roots must be explicitly provided.');
  if(!configuredRoot.startsWith('/')||!reportedRoot.startsWith('/'))
    throw Error('Workspace roots must be absolute.');
  const configured=resolve(configuredRoot);
  const reported=resolve(reportedRoot);
  if(configured!==configuredRoot||reported!==reportedRoot)
    throw Error('Unnormalized workspace roots refused.');
  if(!CONTAINER_DOCUMENTS.test(reported))
    throw Error('Native worker root is not under an App Sandbox Documents scratch container.');
  for(const candidate of [configured,reported]) {
    if(lstatSync(candidate).isSymbolicLink())
      throw Error('Workspace root symlinks are not trusted.');
    const stats=statSync(candidate);
    if(!stats.isDirectory())throw Error('Workspace root must be a directory.');
    if((stats.mode&0o077)!==0)
      throw Error('Workspace must not be group/other accessible.');
    if(stats.uid!==process.getuid?.())
      throw Error('Native workspace owner differs from current user.');
    if(realpathSync(candidate)!==candidate)
      throw Error('Workspace contains unresolved or redirected path components.');
  }
  if(configured!==reported)
    throw Error('Gateway policy root and XPC worker storage differ; refusing native routing.');
  return Object.freeze({configuredRoot:configured,workerRoot:reported,matched:true});
}
