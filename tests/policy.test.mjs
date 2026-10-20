import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { evaluatePolicy } from '../src/policy.mjs';

function fixture(fn) {
  const root = mkdtempSync(join(tmpdir(), 'blackbox-policy-'));
  const workspace = join(root, 'workspace'); mkdirSync(workspace);
  writeFileSync(join(workspace, 'safe.txt'), 'hello');
  writeFileSync(join(root, 'secret.txt'), 'private');
  try { fn(workspace, root); } finally { rmSync(root, { recursive: true, force: true }); }
}
const check = (tool, args, root) => evaluatePolicy(tool, args, root);

test('ordinary in-workspace file read is allowed', () => fixture(workspace => {
  assert.equal(check('file.read', { path: 'safe.txt' }, workspace).decision, 'allow');
}));
test('traversal and absolute paths fail closed', () => fixture((workspace, root) => {
  for (const path of ['../secret.txt', '/etc/passwd', './safe.txt', 'nested/../../secret.txt', 'C:\\temp\\key']) {
    assert.equal(check('file.read', { path }, workspace).decision, 'block');
  }
}));
test('sensitive file names are blocked', () => fixture(workspace => {
  for (const path of ['.env', 'config/.env.local', '.ssh/id_rsa', 'secrets/private.pem']) {
    assert.equal(check('file.read', { path }, workspace).ruleId, 'DENY_SENSITIVE_FILE');
  }
}));
test('symlink out of the workspace is blocked', () => fixture((workspace, root) => {
  symlinkSync(join(root, 'secret.txt'), join(workspace, 'shortcut.txt'));
  assert.equal(check('file.read', { path: 'shortcut.txt' }, workspace).decision, 'block');
}));
test('only allowlisted HTTPS GET mock destination is allowed', () => fixture(workspace => {
  assert.equal(check('network.fetch', { method: 'GET', url: 'https://docs.example.test/page' }, workspace).decision, 'allow');
  for (const args of [
    { method: 'POST', url: 'https://docs.example.test/page' },
    { method: 'GET', url: 'https://evil.test' },
    { method: 'GET', url: 'http://docs.example.test' },
    { method: 'GET', url: 'https://docs.example.test.evil.test' },
    { method: 'GET', url: 'https://admin:pass@docs.example.test' },
    { method: 'GET', url: 'https://127.0.0.1' }
  ]) assert.equal(check('network.fetch', args, workspace).decision, 'block');
}));
test('shell and unregistered tools are blocked', () => fixture(workspace => {
  assert.equal(check('shell.exec', { command: 'echo hello' }, workspace).ruleId, 'DENY_SHELL');
  assert.equal(check('unregistered.tool', { path: 'safe.txt' }, workspace).ruleId, 'DENY_UNKNOWN_TOOL');
  assert.equal(check('file.read', null, workspace).decision, 'block');
}));
