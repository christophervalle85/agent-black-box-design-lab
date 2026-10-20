import { SCENARIOS, SHOWCASE_MODE, findScenario } from './showcase-scenarios.mjs';

const $ = id => document.getElementById(id);
const create = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
};

const initial = new URLSearchParams(window.location.search).get('case');
let current = findScenario(initial) ?? SCENARIOS[0];
let index = 0;

// This module only reads local fixture data and changes DOM nodes. It never
// calls a backend API, creates an approval, or rewrites audit records.
function chooseScenario(id) {
  const selected = findScenario(id);
  if (!selected) return;
  current = selected;
  index = 0;
  const url = new URL(window.location.href);
  url.searchParams.set('case', id);
  window.history.replaceState(null, '', url.pathname + url.search + url.hash);
  render();
}
function changeStep(next) {
  if (!Number.isInteger(next) || next < 0 || next >= current.steps.length) return;
  index = next;
  render();
}
function renderIndex() {
  const container = $('scenario-list');
  container.replaceChildren();
  for (const scenario of SCENARIOS) {
    const button = create('button', 'scenario-button');
    button.type = 'button';
    button.dataset.kind = scenario.kind;
    button.setAttribute('aria-pressed', String(scenario.id === current.id));
    if (scenario.id === current.id) button.classList.add('is-active');
    const number = create('span', 'scenario-num', scenario.number);
    const details = create('span', 'scenario-text');
    details.append(create('strong', '', scenario.title), create('small', '', scenario.outcome));
    const arrow = create('span', 'scenario-arrow', '↗');
    arrow.setAttribute('aria-hidden', 'true');
    button.append(number, details, arrow);
    button.addEventListener('click', () => chooseScenario(scenario.id));
    container.append(button);
  }
}
function renderTimeline() {
  const list = $('scenario-timeline');
  list.replaceChildren();
  current.steps.forEach((step, stepIndex) => {
    const item = create('li', stepIndex === index ? 'timeline-active' : '');
    const button = create('button', 'timeline-button');
    button.type = 'button';
    button.setAttribute('aria-current', stepIndex === index ? 'step' : 'false');
    button.append(
      create('span', 'timeline-index', String(stepIndex + 1).padStart(2, '0')),
      create('span', 'timeline-phase', step.phase),
      create('span', 'timeline-title', step.title)
    );
    button.addEventListener('click', () => changeStep(stepIndex));
    item.append(button);
    list.append(item);
  });
}
function render() {
  const step = current.steps[index];
  const atLastStep = index === current.steps.length - 1;
  const nextScenario = SCENARIOS[(SCENARIOS.indexOf(current) + 1) % SCENARIOS.length];
  $('demo-mode-description').textContent = SHOWCASE_MODE.explanation;
  $('case-number').textContent = `CASE ${current.number} / ${String(SCENARIOS.length).padStart(2, '0')}`;
  $('case-outcome').textContent = current.outcome;
  $('case-category').textContent = current.environment.toUpperCase();
  $('case-title').textContent = current.title;
  $('case-subtitle').textContent = current.subtitle;
  $('case-tool').textContent = current.tool;
  $('case-rule').textContent = current.rule;
  $('case-target').textContent = current.target;
  $('case-evidence').textContent = current.evidence;
  $('case-source').href = current.source;
  $('step-phase').textContent = step.phase;
  $('step-position').textContent = `${String(index + 1).padStart(2, '0')} / ${String(current.steps.length).padStart(2, '0')}`;
  $('step-title').textContent = step.title;
  $('step-detail').textContent = step.detail;
  $('step-signal').textContent = step.signal;
  $('progress-label').textContent = `STEP ${index + 1} OF ${current.steps.length}`;
  $('progress-fill').style.width = `${((index + 1) / current.steps.length) * 100}%`;
  $('previous-step').disabled = index === 0;
  $('next-step').textContent = atLastStep
    ? (nextScenario === SCENARIOS[0] ? 'Return to case 01 →' : 'Next case →')
    : 'Next step →';
  document.querySelector('.case-panel').dataset.kind = current.kind;
  renderIndex();
  renderTimeline();
}
$('previous-step').addEventListener('click', () => changeStep(index - 1));
$('restart-case').addEventListener('click', () => changeStep(0));
$('next-step').addEventListener('click', () => {
  if (index + 1 < current.steps.length) changeStep(index + 1);
  else chooseScenario(SCENARIOS[(SCENARIOS.indexOf(current) + 1) % SCENARIOS.length].id);
});
render();
