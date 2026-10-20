import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditStore } from '../src/audit.mjs';
import { runAgent, createOllamaClient } from '../src/agent.mjs';

async function fixture(fn) {
  const root = mkdtempSync(join(tmpdir(), 'blackbox-agent-'));
  const workspaceRoot = join(root, 'workspace'); mkdirSync(workspaceRoot);
  writeFileSync(join(workspaceRoot, 'notes.txt'), 'This is an intentionally harmless local demo note.');
  const store = new AuditStore(join(root, 'audit.jsonl'));
  try { await fn({ root, workspaceRoot, store }); } finally { rmSync(root, { recursive: true, force: true }); }
}
const toolCall = (name, args) => ({ type: 'function', function: { name, arguments: args } });

test('real multi-turn model protocol: allowed and blocked tool calls are audited before execution', () => fixture(async ({ root, workspaceRoot, store }) => {
  let messagesSeen;
  let chats = 0;
  const chat = async ({ messages, tools }) => {
    chats++;
    assert.deepEqual(tools.map(t => t.function.name), ['read_file', 'write_note', 'fetch_docs', 'run_shell']);
    if (chats === 1) return { role: 'assistant', content: '', tool_calls: [
      toolCall('read_file', { path: 'notes.txt' }),
      toolCall('read_file', { path: '.env' }),
      toolCall('run_shell', { command: 'pwd' }),
      toolCall('fetch_docs', { method: 'GET', url: 'https://unapproved.test/' }),
      toolCall('read_file', { path: '../outside.txt' }),
      toolCall('unknown.tool', { whatever: true })
    ] };
    messagesSeen = messages;
    return { role: 'assistant', content: 'Read demo file; all unsafe actions were blocked.' };
  };
  writeFileSync(join(root, 'outside.txt'), 'DO_NOT_READ_THIS');
  const result = await runAgent({ prompt: 'Inspect the workspace', chat, workspaceRoot, store });
  assert.equal(result.status, 'finished');
  assert.equal(result.toolCalls, 6);
  assert.equal(result.events.filter(e => e.decision === 'allow').length, 1);
  assert.equal(result.events.filter(e => e.decision === 'block').length, 5);
  assert.deepEqual(store.list({ runId: result.runId }).map(e => e.ruleId).sort(),
    ['ALLOW_WORKSPACE_READ','DENY_SENSITIVE_FILE','DENY_SHELL','DENY_UNAPPROVED_EGRESS','DENY_PATH_ESCAPE','DENY_UNKNOWN_TOOL'].sort());
  assert.ok(messagesSeen.some(m => m.role === 'tool' && m.content.includes('intentionally harmless')));
  assert.ok(messagesSeen.some(m => m.role === 'tool' && m.content.includes('DENY_SHELL')));
  assert.doesNotMatch(JSON.stringify(messagesSeen), /DO_NOT_READ_THIS/);
  assert.doesNotMatch(readFileSync(store.filename, 'utf8'), /intentionally harmless|DO_NOT_READ_THIS/);
}));

test('model-provided JSON string arguments are accepted by the policy engine', () => fixture(async ({ workspaceRoot, store }) => {
  let step = 0;
  const result = await runAgent({ prompt: 'read', store, workspaceRoot, chat: async () => (++step === 1)
    ? { role: 'assistant', tool_calls: [toolCall('read_file', '{"path":"notes.txt"}')] }
    : { role: 'assistant', content: 'Done.' } });
  assert.equal(result.events[0].decision, 'allow');
  assert.equal(result.answer, 'Done.');
}));

test('malformed model arguments fail closed and are logged', () => fixture(async ({ workspaceRoot, store }) => {
  let step = 0;
  const result = await runAgent({ prompt: 'read', store, workspaceRoot, chat: async () => (++step === 1)
    ? { role: 'assistant', tool_calls: [toolCall('read_file', '{bad JSON')] }
    : { role: 'assistant', content: 'Denied.' } });
  assert.equal(result.events[0].decision, 'block');
  assert.equal(result.events[0].ruleId, 'INVALID_INPUT');
}));

test('caps number of model-directed tool calls without executing overflow', () => fixture(async ({ workspaceRoot, store }) => {
  const calls = Array.from({ length: 13 }, () => toolCall('read_file', {path:'notes.txt'}));
  const result = await runAgent({ prompt: 'read', store, workspaceRoot, chat: async () => ({role:'assistant', tool_calls:calls}) });
  assert.equal(result.status, 'limit-reached');
  assert.equal(result.toolCalls, 0);
  assert.equal(store.list().length, 0);
}));

test('rejects oversized or empty prompts', () => fixture(async ({ workspaceRoot, store }) => {
  for (const prompt of ['', 'a'.repeat(2001)]) await assert.rejects(() => runAgent({prompt, store, workspaceRoot, chat: async () => ({role:'assistant'})}), TypeError);
}));

test('Ollama HTTP interface uses documented chat tools and checks installed models', async () => {
  const requests = [];
  const fakeFetch = async (url, options) => {
    requests.push({url, options});
    return new Response(JSON.stringify(url.endsWith('/api/tags') ? {models:[{name:'qwen3:4b-instruct'}]} : {message:{role:'assistant',content:'Okay'}}),
      {status:200,headers:{'Content-Type':'application/json'}});
  };
  const client = createOllamaClient({ fetchImpl: fakeFetch });
  assert.equal((await client.status()).ready, true);
  const message = await client.chat({ messages: [{role:'user',content:'Hi'}], tools: [] });
  assert.equal(message.content, 'Okay');
  const chatBody = JSON.parse(requests[1].options.body);
  assert.equal(chatBody.stream, false);
  assert.equal(chatBody.model, 'qwen3:4b-instruct');
  assert.deepEqual(chatBody.tools, []);
  assert.throws(() => createOllamaClient({url:'https://example.com:11434'}), /loopback/);
});
