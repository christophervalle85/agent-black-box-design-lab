import { SCENARIOS, SHOWCASE_MODE, findScenario } from './showcase-scenarios.mjs';

// Read-only public storytelling. No backend requests, approvals, audit writes or
// native probes. All observable values originate in documented scenario fixtures.
const $ = id => document.getElementById(id);
const create = (tag, className, label) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (label !== undefined) element.textContent = String(label);
  return element;
};

const limitations = Object.freeze({
  'restricted-file': 'The Node guard checks selected routed calls, not every file read by other host processes. This is not operating-system file isolation.',
  'shell-command': 'Arbitrary shell authority is unavailable through this routed tool interface. This does not demonstrate a host-wide execution monitor.',
  'human-approval': 'The public page issues no approval. One-time review applies only to a bounded note-creation request; the exclusive-create attempt can still fail.',
  'path-traversal': 'The guard denies this path before dispatch. The example does not establish protection against every filesystem race.',
  'native-boundary': 'The observed OS denials come from a separately signed worker-source diagnostic, not a fresh test of the byte-identical installed worker or a sandbox around the Node parent.',
  'audit-tamper': 'The local HMAC verifier catches this altered fixture. Same-user compromise and independently secured evidence custody remain outside this guarantee.'
});
const outcomes = Object.freeze({
  'restricted-file': {
    title: 'DENIED BEFORE FILE READ',
    explanation: 'The selected request matches the sensitive-file rule. The guarded adapter is never dispatched, so this routed call does not return the .env contents.'
  },
  'shell-command': {
    title: 'NO SHELL EXECUTION',
    explanation: 'The proposed shell command is rejected by the routed policy boundary. No shell adapter is dispatched for this request.'
  },
  'human-approval': {
    title: 'REVIEWED, NOT UNRESTRICTED',
    explanation: 'This storyboard follows one eligible note-creation request through one-use operator approval. The guarded adapter then attempts exclusive creation; approval does not guarantee that the write succeeds.'
  },
  'path-traversal': {
    title: 'ESCAPE DENIED',
    explanation: 'The relative path is rejected by the configured workspace boundary. The read adapter is not given an authorized path outside the demo workspace.'
  },
  'native-boundary': {
    title: 'OS DENIAL IN A SEPARATE DIAGNOSTIC',
    explanation: 'A separately signed worker-source diagnostic was denied access to a host-private file and loopback listener, while its own sandbox-managed scratch storage remained usable.'
  },
  'audit-tamper': {
    title: 'AUTHENTICITY CHECK FAILED',
    explanation: 'A deliberately changed fixture fails HMAC-linked audit verification. The documented local guard then refuses protected execution while integrity is compromised.'
  }
});
const requestNotes = Object.freeze({
  'restricted-file': 'Illustrative file-read request: no real credential file is opened by this page.',
  'shell-command': 'Synthetic command text only. There is no real installation destination or shell process.',
  'human-approval': 'This fixture identifies the reviewed filename, but does not include the note body. In the real local flow, the operator reviews the exact content before deciding.',
  'path-traversal': 'This relative path is a synthetic example. No actual workspace traversal is attempted here.',
  'native-boundary': 'This is a separate signed diagnostic fixture—not an agent-callable tool operation or a new test run.',
  'audit-tamper': 'This is a deliberately altered test fixture, not a record from a current local session.'
});
const stageLabels = Object.freeze({
  'restricted-file': ['Request', 'Policy match', 'Denied'],
  'shell-command': ['Request', 'No shell grant', 'Denied'],
  'human-approval': ['Request', 'Paused', 'One-use review', 'Create attempt', 'Audit'],
  'path-traversal': ['Request', 'Escape check', 'Denied'],
  'native-boundary': ['Signed build', 'Private file', 'Loopback', 'Scratch storage'],
  'audit-tamper': ['Baseline', 'Changed record', 'Verify', 'Contain']
});

function requestText(scenario) {
  // The native acceptance test and audit-verifier fixture are not tool calls.
  if (scenario.kind === 'native') {
    return 'FIXTURE    signed worker-source diagnostic\nATTEMPTS   host-private read + loopback connection\nBOUNDARY   macOS App Sandbox';
  }
  if (scenario.kind === 'audit') {
    return 'FIXTURE    modified local audit record\nCHECK      audit.verify\nCONTROL    HMAC-linked audit + checkpoint';
  }
  return JSON.stringify({
    tool: scenario.tool,
    arguments: { [scenario.tool === 'shell.exec' ? 'command' : 'path']: scenario.target }
  }, null, 2);
}

function getLocation() {
  const params = new URLSearchParams(window.location.search);
  const scenario = findScenario(params.get('case')) ?? SCENARIOS[0];
  const stepValue = params.get('step');
  const requestedStep = stepValue === null ? 1 : Number(stepValue);
  const step = Number.isInteger(requestedStep) && requestedStep >= 1 && requestedStep <= scenario.steps.length
    ? requestedStep - 1 : 0;
  return { scenario, step };
}
let { scenario: current, step: index } = getLocation();
let stageButtons = [];

function updateHistory(push) {
  const url = new URL(window.location.href);
  url.searchParams.set('case', current.id);
  url.searchParams.set('step', String(index + 1));
  const location = url.pathname + url.search + url.hash;
  if (push) window.history.pushState(null, '', location);
  else window.history.replaceState(null, '', location);
}
function feedback(message = '') { $('action-feedback').textContent = message; }

function buildStageButtons() {
  const list = $('scenario-timeline');
  list.replaceChildren();
  stageButtons = current.steps.map((step, position) => {
    const item = create('li');
    const button = create('button', 'stage-button');
    button.type = 'button';
    button.setAttribute('aria-label', 'Inspect stage ' + (position + 1) + ': ' + step.title);
    button.append(
      create('span', '', String(position + 1).padStart(2, '0')),
      create('strong', '', stageLabels[current.id][position])
    );
    button.addEventListener('click', () => selectStep(position));
    item.append(button);
    list.append(item);
    return button;
  });
}

function render() {
  const step = current.steps[index];
  const outcome = outcomes[current.id];
  $('demo-mode-description').textContent = SHOWCASE_MODE.explanation;
  $('case-picker').value = current.id;
  $('case-number').textContent = 'CASE ' + current.number + ' / ' + String(SCENARIOS.length).padStart(2, '0');
  $('case-category').textContent = current.environment.toUpperCase();
  $('case-title').textContent = current.title;
  $('case-subtitle').textContent = current.subtitle;
  $('case-outcome').textContent = current.outcome;
  $('request-payload').textContent = requestText(current);
  $('request-explainer').textContent = requestNotes[current.id];
  $('case-tool').textContent = current.tool;
  $('case-target').textContent = current.target;
  $('case-rule').textContent = current.rule;
  $('case-environment').textContent = current.environment;
  $('outcome-label').textContent = outcome.title;
  $('outcome-explanation').textContent = outcome.explanation;
  $('case-evidence').textContent = current.evidence;
  $('case-limitation').textContent = limitations[current.id];
  $('case-source').href = current.source;
  $('step-phase').textContent = step.phase;
  $('step-position').textContent = String(index + 1).padStart(2, '0') + ' / ' + String(current.steps.length).padStart(2, '0');
  $('step-title').textContent = step.title;
  $('step-detail').textContent = step.detail;
  $('step-signal').textContent = step.signal;
  $('progress-label').textContent = String(index + 1) + ' OF ' + String(current.steps.length) + ' STAGES';
  document.querySelector('.case-story').dataset.kind = current.kind;

  stageButtons.forEach((button, position) => {
    if (position === index) button.setAttribute('aria-current', 'step');
    else button.removeAttribute('aria-current');
  });
  $('previous-step').disabled = index === 0;
  $('next-step').disabled = index === current.steps.length - 1;
  $('next-case').textContent = (SCENARIOS.indexOf(current) === SCENARIOS.length - 1)
    ? 'Return to first case →'
    : 'Next investigation →';
}

function chooseCase(id, push = true) {
  const scenario = findScenario(id);
  if (!scenario) return;
  const changed = current.id !== scenario.id;
  current = scenario;
  index = 0;
  if (changed) buildStageButtons();
  render();
  updateHistory(push && changed);
  feedback('Showing ' + current.title + '.');
}
function selectStep(n) {
  if (!Number.isInteger(n) || n < 0 || n >= current.steps.length) return;
  index = n;
  render();
  updateHistory(false);
  feedback();
}

$('case-picker').disabled = false;
$('case-picker').addEventListener('change', value => {
  chooseCase(value.target.value);
});
$('previous-step').addEventListener('click', () => selectStep(index - 1));
$('next-step').addEventListener('click', () => selectStep(index + 1));
$('restart-case').addEventListener('click', () => selectStep(0));
$('next-case').addEventListener('click', () => {
  const scenario = SCENARIOS[(SCENARIOS.indexOf(current) + 1) % SCENARIOS.length];
  chooseCase(scenario.id);
});
$('copy-case-link').addEventListener('click', async () => {
  const url = new URL(window.location.href);
  url.searchParams.set('case', current.id);
  url.searchParams.set('step', String(index + 1));
  try {
    await navigator.clipboard.writeText(url.toString());
    feedback('Link copied for this case and stage.');
  } catch {
    feedback('Copy unavailable. This case and stage are represented in your browser address.');
  }
});
window.addEventListener('popstate', () => {
  const next = getLocation();
  const changed = current.id !== next.scenario.id;
  current = next.scenario;
  index = next.step;
  if (changed) buildStageButtons();
  render();
  feedback();
});
buildStageButtons();
render();
