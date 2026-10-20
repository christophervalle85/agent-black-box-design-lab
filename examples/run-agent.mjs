import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditStore } from '../src/audit.mjs';
import { runAgent, createOllamaClient } from '../src/agent.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const prompt = process.argv.slice(2).join(' ').trim() || 'Read notes.txt in the demo workspace and summarize it.';
const client = createOllamaClient();
const store = new AuditStore(join(root, 'data', 'audit.jsonl'));
console.log(`\nAgent Black Box · ${client.model}\nTask: ${prompt}\n`);
try {
  const run = await runAgent({ prompt, store, workspaceRoot: join(root, 'demo-workspace'), chat: args => client.chat(args), model: client.model });
  for (const event of run.events) console.log(`[${event.decision.toUpperCase()}] ${event.tool}: ${event.ruleId} (${event.outcome})`);
  console.log(`\n${run.answer}\n\nRun ID: ${run.runId} (${run.status})`);
} catch (error) {
  console.error('Agent could not run:', error.message);
  process.exitCode = 1;
}
