import { SCENARIOS, SHOWCASE_MODE, findScenario } from './showcase-scenarios.mjs';

// Public presentation only: no fetch, approval, tool execution, or native probes.
const $ = id => document.getElementById(id);
const element = (tag, cls, value) => {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (value !== undefined) el.textContent = String(value);
  return el;
};
const notes = Object.freeze({
  'restricted-file': 'This Node policy protects calls routed through its guard, not every host file read or unsandboxed process.',
  'shell-command': 'The selected routed tool has no authority to execute arbitrary shell commands. This is not a host-wide shell monitor.',
  'human-approval': 'This is a storyboard, not an actual approval. A one-use decision only enables the reviewed note-creation attempt, which may still fail.',
  'path-traversal': 'The guard denies this attempted path escape before adapter dispatch; this does not prove immunity to every filesystem race.',
  'native-boundary': 'The OS denials are from a separately signed worker-source diagnostic, not a fresh probe of the byte-identical installed worker or a Node-parent sandbox.',
  'audit-tamper': 'The local HMAC verifier catches the changed fixture. Same-user compromise and independent evidence custody remain outside the guarantee.'
});
const shortTitles = Object.freeze({
  'restricted-file': 'Sensitive file',
  'shell-command': 'Shell attempt',
  'human-approval': 'Human review',
  'path-traversal': 'Path escape',
  'native-boundary': 'macOS diagnostic',
  'audit-tamper': 'Audit integrity'
});
function payloadFor(s) {
  if (s.kind === 'native') return 'TEST TYPE  signed worker-source diagnostic\nPROBES     host-private file + loopback\nBOUNDARY   macOS App Sandbox';
  if (s.kind === 'audit') return 'VERIFIER   audit.verify\nINPUT      tampered audit fixture\nCHECK      HMAC-linked records';
  const argument = s.tool === 'shell.exec' ? 'command' : 'path';
  return JSON.stringify({ tool: s.tool, arguments: { [argument]: s.target } }, null, 2);
}
function fromUrl() {
  const params = new URLSearchParams(window.location.search);
  const scenario = findScenario(params.get('case')) ?? SCENARIOS[0];
  const n = Number(params.get('step'));
  const step = Number.isInteger(n) && n >= 1 && n <= scenario.steps.length ? n - 1 : 0;
  return { scenario, step };
}
let { scenario: current, step: index } = fromUrl();
const caseButtons = new Map();
let stageButtons = [];
function updateUrl(push = false) {
  const url = new URL(window.location.href);
  url.searchParams.set('case', current.id);
  url.searchParams.set('step', String(index + 1));
  const path = url.pathname + url.search + url.hash;
  if (push) window.history.pushState(null, '', path);
  else window.history.replaceState(null, '', path);
}
function clearFeedback() { $('action-feedback').textContent = ''; }
function buildIndex() {
  const root = $('scenario-list');
  root.replaceChildren();
  for (const scenario of SCENARIOS) {
    const button = element('button', 'case-pick');
    button.type = 'button';
    button.append(
      element('span', 'case-pick-num', scenario.number),
      element('span', 'case-pick-name', shortTitles[scenario.id]),
      element('span', 'case-pick-outcome', scenario.outcome)
    );
    button.addEventListener('click', () => selectCase(scenario.id));
    caseButtons.set(scenario.id, button);
    root.append(button);
  }
}
function buildStages() {
  const root = $('scenario-timeline');
  root.replaceChildren();
  stageButtons = current.steps.map((step, position) => {
    const li = element('li');
    const button = element('button', 'stage-button');
    button.type = 'button';
    button.setAttribute('aria-label', 'Step ' + (position + 1) + ': ' + step.title);
    button.append(
      element('span', '', String(position + 1).padStart(2, '0')),
      element('strong', '', step.phase)
    );
    button.addEventListener('click', () => selectStep(position));
    li.append(button);
    root.append(li);
    return button;
  });
}
function render() {
  const step = current.steps[index];
  $('demo-mode-description').textContent = SHOWCASE_MODE.explanation;
  $('case-number').textContent = 'CASE ' + current.number + ' / ' + String(SCENARIOS.length).padStart(2, '0');
  $('case-category').textContent = current.environment.toUpperCase();
  $('case-outcome').textContent = current.outcome;
  $('case-title').textContent = current.title;
  $('case-subtitle').textContent = current.subtitle;
  $('request-payload').textContent = payloadFor(current);
  $('case-tool').textContent = current.tool;
  $('case-target').textContent = current.target;
  $('case-rule').textContent = current.rule;
  $('case-environment').textContent = current.environment;
  $('case-evidence').textContent = current.evidence;
  $('case-limitation').textContent = notes[current.id];
  $('case-source').href = current.source;
  $('step-phase').textContent = step.phase;
  $('step-position').textContent = String(index + 1).padStart(2, '0') + ' / ' + String(current.steps.length).padStart(2, '0');
  $('progress-label').textContent = 'STEP ' + (index + 1) + ' OF ' + current.steps.length;
  $('step-title').textContent = step.title;
  $('step-detail').textContent = step.detail;
  $('step-signal').textContent = step.signal;
  document.querySelector('.case-canvas').dataset.kind = current.kind;
  for (const [id, button] of caseButtons) button.setAttribute('aria-pressed', String(id === current.id));
  stageButtons.forEach((button, position) => {
    if (position === index) button.setAttribute('aria-current', 'step');
    else button.removeAttribute('aria-current');
  });
  $('previous-step').disabled = index === 0;
  const last = index === current.steps.length - 1;
  const nextCase = SCENARIOS[(SCENARIOS.indexOf(current) + 1) % SCENARIOS.length];
  $('next-step').textContent = last
    ? (nextCase === SCENARIOS[0] ? 'Return to case 01 →' : 'Next investigation →')
    : 'Next step →';
}
function selectCase(id, push = true) {
  const next = findScenario(id);
  if (!next) return;
  const changed = next.id !== current.id;
  current = next;
  index = 0;
  if (changed) buildStages();
  clearFeedback();
  render();
  updateUrl(push && changed);
}
function selectStep(n) {
  if (!Number.isInteger(n) || n < 0 || n >= current.steps.length) return;
  index = n;
  clearFeedback();
  render();
  updateUrl();
}
$('previous-step').addEventListener('click', () => selectStep(index - 1));
$('restart-case').addEventListener('click', () => selectStep(0));
$('next-step').addEventListener('click', () => {
  if (index < current.steps.length - 1) selectStep(index + 1);
  else selectCase(SCENARIOS[(SCENARIOS.indexOf(current) + 1) % SCENARIOS.length].id);
});
$('copy-case-link').addEventListener('click', async () => {
  const url = new URL(window.location.href);
  url.searchParams.set('case', current.id);
  url.searchParams.set('step', String(index + 1));
  try {
    await navigator.clipboard.writeText(url.toString());
    $('action-feedback').textContent = 'Link copied for this investigation step.';
  } catch {
    $('action-feedback').textContent = 'Copy unavailable. You can copy the case and step from the browser address.';
  }
});
window.addEventListener('popstate', () => {
  const next = fromUrl();
  const changed = current.id !== next.scenario.id;
  current = next.scenario;
  index = next.step;
  if (changed) buildStages();
  clearFeedback();
  render();
});
buildIndex();
buildStages();
render();
