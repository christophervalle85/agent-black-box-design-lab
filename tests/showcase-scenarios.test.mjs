import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SCENARIOS, SHOWCASE_MODE, findScenario } from '../public/showcase-scenarios.mjs';

test('my showcase fixtures remain bounded, unique, and clearly illustrative', () => {
  assert.equal(SCENARIOS.length, 6);
  assert.equal(SHOWCASE_MODE.id, 'illustrative');
  assert.match(SHOWCASE_MODE.explanation, /not|never/i);
  const seen = new Set();
  for (const [index, scenario] of SCENARIOS.entries()) {
    assert.match(scenario.id, /^[a-z][a-z0-9-]+$/);
    assert.equal(scenario.number, String(index + 1).padStart(2, '0'));
    assert.ok(!seen.has(scenario.id));
    seen.add(scenario.id);
    assert.equal(findScenario(scenario.id), scenario);
    assert.ok(['policy', 'review', 'native', 'audit'].includes(scenario.kind));
    for (const key of ['outcome', 'title', 'subtitle', 'tool', 'target', 'rule', 'environment', 'evidence']) {
      assert.equal(typeof scenario[key], 'string');
      assert.ok(scenario[key].length > 2, `${scenario.id} needs ${key}`);
    }
    assert.match(scenario.source, /^https:\/\/github\.com\/christophervalle85\/agent-black-box-design-lab\/blob\/main\/docs\/[a-zA-Z0-9._-]+\.md$/);
    assert.ok(scenario.steps.length >= 3);
    assert.ok(Object.isFrozen(scenario.steps));
    assert.ok(Object.isFrozen(scenario));
    for (const step of scenario.steps) {
      assert.ok(Object.isFrozen(step));
      for (const field of ['phase', 'title', 'detail', 'signal']) {
        assert.equal(typeof step[field], 'string');
        assert.ok(step[field].trim().length > 3);
      }
    }
  }
  assert.equal(findScenario('../etc/passwd'), null);
  assert.equal(findScenario('__proto__'), null);
});

test('my scenario claims preserve the native proof boundary and one-time approval semantics', () => {
  const native = findScenario('native-boundary');
  assert.equal(native.kind, 'native');
  assert.match(native.evidence, /separate diagnostic build/i);
  assert.ok(native.steps.some(step => /byte-identical installed worker/i.test(step.detail)));
  const approval = findScenario('human-approval');
  assert.ok(approval.steps.some(step => /No real approval is issued/i.test(step.detail)));
  const audit = findScenario('audit-tamper');
  assert.equal(audit.rule, 'AUDIT_INTEGRITY_FAILURE');
  assert.equal(findScenario('restricted-file').rule, 'DENY_SENSITIVE_FILE');
  assert.equal(findScenario('shell-command').rule, 'DENY_SHELL');
  assert.equal(findScenario('path-traversal').rule, 'DENY_PATH_ESCAPE');
});
