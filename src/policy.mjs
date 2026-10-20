import { realpathSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

export const POLICIES = Object.freeze([
  { id: 'ALLOW_WORKSPACE_READ', description: 'Read ordinary files only within the demo workspace.', category: 'Filesystem' },
  { id: 'DENY_PATH_ESCAPE', description: 'Block absolute paths, traversal, and symlinks leaving the workspace.', category: 'Filesystem' },
  { id: 'DENY_SENSITIVE_FILE', description: 'Block reads of credentials, private keys, and hidden configuration.', category: 'Data loss prevention' },
  { id: 'ALLOW_MOCK_DOCS', description: 'Simulate GET requests to docs.example.test only; make no network request.', category: 'Network' },
  { id: 'DENY_UNAPPROVED_EGRESS', description: 'Block all other network destinations, methods, and credentialed URLs.', category: 'Network' },
  { id: 'REQUIRE_NOTE_APPROVAL', description: 'Creating a new plain-text note requires one-time human approval of its exact contents.', category: 'Human approval' },
  { id: 'DENY_UNSAFE_WRITE', description: 'Reject sensitive, oversized, or non-note write attempts before review.', category: 'Filesystem' },
  { id: 'DENY_SHELL', description: 'Disallow arbitrary operating-system command execution.', category: 'Execution' },
  { id: 'DENY_UNKNOWN_TOOL', description: 'Unregistered tools are never executed.', category: 'Execution' }
]);

function outcome(decision, risk, ruleId, reason) {
  return { decision, risk, ruleId, reason };
}
const deny = (risk, ruleId, reason) => outcome('block', risk, ruleId, reason);
const allow = (ruleId, reason) => outcome('allow', 'low', ruleId, reason);
const review = (ruleId, reason) => outcome('review', 'medium', ruleId, reason);

export function withinWorkspace(candidate, workspaceRoot) {
  const root = realpathSync(workspaceRoot);
  const rel = relative(root, candidate);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

export function resolveWorkspaceFile(inputPath, workspaceRoot) {
  if (typeof inputPath !== 'string' || !inputPath.trim() || inputPath.length > 512 || inputPath.includes('\0')) {
    return { ok: false, reason: 'A non-empty, bounded relative path is required.' };
  }
  if (isAbsolute(inputPath) || /^[A-Za-z]:[\\/]/.test(inputPath) || inputPath.includes('\\')) {
    return { ok: false, reason: 'Absolute paths and backslash paths are not permitted.' };
  }
  const segments = inputPath.split('/');
  if (segments.some(s => s === '..' || s === '.')) {
    return { ok: false, reason: 'Path traversal and dot-segments are not permitted.' };
  }
  if (segments.some(s => /^(\.env(?:\..*)?|\.git|\.ssh|id_rsa|id_ed25519|.*\.(?:pem|key|p12))$/i.test(s))) {
    return { ok: false, sensitive: true, reason: 'This path resembles a sensitive credential or configuration file.' };
  }
  const root = realpathSync(workspaceRoot);
  const candidate = resolve(root, inputPath);
  if (!withinWorkspace(candidate, root)) {
    return { ok: false, reason: 'Resolved path escapes the workspace.' };
  }
  try {
    const canonical = realpathSync(candidate);
    if (!withinWorkspace(canonical, root)) {
      return { ok: false, reason: 'Symlink resolves outside the workspace.' };
    }
  } catch (error) {
    if (error.code !== 'ENOENT') return { ok: false, reason: 'Path cannot be safely resolved.' };
    // A missing file can be authorized, then reported as a tool execution error.
    // The executor rechecks the canonical path before reading.
  }
  return { ok: true, candidate };
}

export function evaluatePolicy(tool, args, workspaceRoot) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return deny('high', 'INVALID_INPUT', 'Tool arguments must be an object.');
  }
  switch (tool) {
    case 'file.read': {
      const check = resolveWorkspaceFile(args.path, workspaceRoot);
      if (!check.ok) {
        return deny(check.sensitive ? 'critical' : 'high', check.sensitive ? 'DENY_SENSITIVE_FILE' : 'DENY_PATH_ESCAPE', check.reason);
      }
      return allow('ALLOW_WORKSPACE_READ', 'Requested path is inside the workspace and is not a restricted filename.');
    }
    case 'file.write': {
      const check = resolveWorkspaceFile(args.path, workspaceRoot);
      if (!check.ok) return deny(check.sensitive ? 'critical' : 'high', check.sensitive ? 'DENY_SENSITIVE_FILE' : 'DENY_PATH_ESCAPE', check.reason);
      if (!/^[a-z0-9][a-z0-9_-]{0,39}\.txt$/i.test(args.path) ||
          typeof args.content !== 'string' || args.content.length < 1 ||
          Buffer.byteLength(args.content, 'utf8') > 2000 || args.content.includes('\0')) {
        return deny('high', 'DENY_UNSAFE_WRITE', 'Only new, top-level .txt notes with 1–2,000 bytes of content can be reviewed.');
      }
      return review('REQUIRE_NOTE_APPROVAL', 'Creating a new note requires explicit approval of its filename and full content.');
    }
    case 'network.fetch': {
      if (args.method !== 'GET' || typeof args.url !== 'string' || args.url.length > 2048) {
        return deny('high', 'DENY_UNAPPROVED_EGRESS', 'Only bounded GET URLs are allowed.');
      }
      let url;
      try { url = new URL(args.url); } catch { return deny('high', 'DENY_UNAPPROVED_EGRESS', 'Malformed URL.'); }
      if (url.protocol !== 'https:' || url.username || url.password || url.hostname !== 'docs.example.test' || url.port) {
        return deny('critical', 'DENY_UNAPPROVED_EGRESS', 'Destination is not the trusted HTTPS documentation demo host.');
      }
      return allow('ALLOW_MOCK_DOCS', 'Trusted documentation destination; response will be simulated without network access.');
    }
    case 'shell.exec':
      return deny('critical', 'DENY_SHELL', 'Arbitrary shell execution is disabled in the MVP.');
    default:
      return deny('high', 'DENY_UNKNOWN_TOOL', 'Unregistered tool: no execution adapter is installed.');
  }
}
