import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { createBlackBoxServer } from '../src/server.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = mkdtempSync(join(tmpdir(), 'bbx-browser-'));
const workspaceRoot = join(root, 'workspace');
mkdirSync(workspaceRoot);
writeFileSync(join(workspaceRoot, 'notes.txt'), 'Browser acceptance fixture.');
let modelRound = 0;
const agentClient = {
  model: 'browser-test:fixture',
  status: async () => ({ ready: true, reachable: true, model: 'browser-test:fixture' }),
  chat: async () => ++modelRound % 2 === 1
    ? { role: 'assistant', tool_calls: [{ type: 'function', function: { name: 'write_note', arguments: { path: `browser-note-${modelRound}.txt`, content: 'Exact browser-reviewed fixture.' } } }] }
    : { role: 'assistant', content: 'The guarded operation has finished.' }
};
const { server } = createBlackBoxServer({ workspaceRoot, dataFile: join(root, 'audit.jsonl'), agentClient });
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
const errors = [];
page.on('pageerror', error => errors.push(error.message));
try {
  const showcaseApiCalls = [];
  const watch = request => { if (request.url().includes('/api/')) showcaseApiCalls.push(request.url()); };
  page.on('request', watch);
  await page.goto(base + '/showcase');
  await page.getByRole('link', { name: 'Explore the cases', exact: true }).click();
  await page.getByRole('button', { name: /03.*One-time approval/ }).click();
  await page.getByRole('button', { name: 'Next step', exact: true }).click();
  assert.match(await page.locator('#step-title').textContent(), /suspended/);
  assert.match(page.url(), /case=human-approval/);
  assert.match(page.url(), /step=2/);
  await page.reload();
  assert.match(await page.locator('#step-title').textContent(), /suspended/);
  await page.locator('#scenario-timeline button').first().focus();
  await page.keyboard.press('End');
  assert.equal(await page.locator('#scenario-timeline button').last().getAttribute('aria-current'), 'step');
  await page.getByRole('button', { name: 'Restart case', exact: true }).click();
  assert.match(await page.locator('#step-title').textContent(), /create a note/);
  await page.getByRole('button', { name: /Native worker.*View boundary/ }).click();
  assert.match(await page.locator('#boundary-detail').textContent(), /synthetic/);
  await page.getByRole('button', { name: 'macOS', exact: true }).click();
  assert.equal(await page.locator('.evidence-record:visible').count(), 2);
  assert.equal(showcaseApiCalls.length, 0, 'The illustrative guide must never call the local API');
  page.off('request', watch);
  assert.equal((await (await fetch(base + '/api/events')).json()).events.length, 0);
  for (const width of [1440, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Showcase overflow at ${width}`);
  }
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto(base + '/');
  await page.getByRole('button', { name: 'Run scripted demo', exact: true }).click();
  await page.waitForFunction(() => document.querySelectorAll('#event-table tr').length === 9);
  await page.getByLabel('Decision').selectOption('block');
  assert.equal(await page.locator('#event-table tr').count(), 6);
  await page.locator('#event-table tr').first().focus();
  await page.waitForResponse(response => response.url().includes('/api/activity?'));
  await page.waitForTimeout(100);
  assert.equal(await page.locator('#event-table tr').first().evaluate(node => node === document.activeElement), true, 'Polling must preserve keyboard focus');
  await page.keyboard.press('Enter');
  assert.ok(await page.locator('#event-dialog').isVisible());
  await page.keyboard.press('Escape');
  assert.equal(await page.locator('#event-dialog').isVisible(), false);
  await page.getByRole('button', { name: 'AI agent', exact: true }).click();
  await page.locator('.skip').focus();
  await page.keyboard.press('Enter');
  assert.ok(await page.locator('#agent-view').isVisible(), 'Skip link must preserve the active view');
  await page.getByRole('button', { name: 'Run with local LLM', exact: true }).click();
  await page.getByRole('button', { name: 'Approve once', exact: true }).waitFor();
  assert.match(await page.locator('#agent-approvals').textContent(), /Exact browser-reviewed fixture/);
  await page.getByRole('button', { name: 'Approve once', exact: true }).focus();
  await page.waitForResponse(response => response.url().endsWith('/api/approvals'));
  await page.waitForTimeout(100);
  assert.equal(await page.getByRole('button', { name: 'Approve once', exact: true }).evaluate(node => node === document.activeElement), true);
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => document.querySelector('#agent-result-status').textContent === 'COMPLETE');
  await page.getByRole('button', { name: 'Run with local LLM', exact: true }).click();
  await page.locator('#agent-approvals h3').filter({ hasText: 'browser-note-3.txt' }).waitFor();
  await page.getByRole('button', { name: 'Deny request', exact: true }).waitFor();
  await page.getByRole('button', { name: 'Deny request', exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#agent-result-status').textContent !== 'RUNNING');
  assert.equal(await page.locator('#agent-result-status').textContent(), 'COMPLETE');
  for (const view of ['Session', 'Activity', 'Approvals', 'Policies', 'AI agent']) {
    await page.getByRole('button', { name: view, exact: true }).click();
    for (const width of [768, 390, 320]) {
      await page.setViewportSize({ width, height: 844 });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), `Console overflow in ${view} at ${width}`);
    }
  }
  await page.route('**/api/activity?*', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'Audit integrity verification failed; results withheld.' }) }));
  await page.reload();
  await page.locator('#data-status').filter({ hasText: /unavailable/i }).waitFor();
  assert.equal(await page.locator('#total-value').textContent(), '—');
  assert.equal(errors.length, 0, errors.join('\n'));
  console.log('PASS: walkthrough state, reload, boundary explorer, evidence filters, no API calls, responsive layouts, real demo, event inspector, one-time approval/denial, and unavailable-data state.');
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
  rmSync(root, { recursive: true, force: true });
}
