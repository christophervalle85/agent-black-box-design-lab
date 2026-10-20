// Example integration for a tool you control. Run from repo root:
// node examples/instrument-tool.mjs
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { AuditStore } from '../src/audit.mjs';
import { guardedToolCall } from '../src/monitor.mjs';
import { createDemoAdapters } from '../src/tools.mjs';

const workspaceRoot = resolve('demo-workspace');
const store = new AuditStore(resolve('data/audit.jsonl'));
const adapters = createDemoAdapters(workspaceRoot);
const runId = randomUUID();

// Substitute your real agent's tool dispatcher here. Keep guardToolCall in the
// *only* code path able to invoke the adapter (no direct bypasses).
async function callAgentTool(tool, args) {
  return guardedToolCall({
    agentId: 'my-local-agent', runId, tool, args,
    store, workspaceRoot,
    execute: adapters[tool] ?? (async () => { throw new Error('Unsupported tool'); })
  });
}

console.log((await callAgentTool('file.read', { path: 'notes.txt' })).event);
console.log((await callAgentTool('shell.exec', { command: 'uname -a' })).event);
