import { SCENARIOS, SHOWCASE_MODE, findScenario } from './showcase-scenarios.mjs';

const $ = id => document.getElementById(id);
const create = (tag, className, value) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
};
const CASE_NAMES = ['Sensitive file', 'Shell command', 'One-time approval', 'Path escape', 'Native sandbox', 'Audit tampering'];
let current = SCENARIOS[0];
let stepIndex = 0;
let renderedCase;

function readLocation() {
  const params = new URLSearchParams(location.search);
  const requested = params.get('case');
  current = findScenario(requested) ?? SCENARIOS[0];
  const requestedStep = Number(params.get('step') ?? 1);
  stepIndex = Number.isInteger(requestedStep) && requestedStep >= 1 && requestedStep <= current.steps.length ? requestedStep - 1 : 0;
  $('case-notice').textContent = requested && !findScenario(requested) ? 'That case was not found. Showing the sensitive-file case instead.' : '';
  render();
}
function updateLocation(push = false) {
  const url = new URL(location.href);
  url.searchParams.set('case', current.id);
  url.searchParams.set('step', String(stepIndex + 1));
  history[push ? 'pushState' : 'replaceState'](null, '', url.pathname + url.search + url.hash);
}
function chooseCase(id) {
  const selected = findScenario(id);
  if (!selected) return;
  current = selected;
  stepIndex = 0;
  $('case-notice').textContent = '';
  updateLocation(true);
  render();
}
function changeStep(next) {
  if (!Number.isInteger(next) || next < 0 || next >= current.steps.length) return;
  stepIndex = next;
  updateLocation();
  render();
}
for (const [index, scenario] of SCENARIOS.entries()) {
  const button = create('button', 'case-choice');
  button.type = 'button';
  button.dataset.case = scenario.id;
  button.setAttribute('aria-pressed', 'false');
  button.append(create('span', '', scenario.number), create('strong', '', CASE_NAMES[index]));
  button.addEventListener('click', () => chooseCase(scenario.id));
  $('scenario-list').append(button);
}
function renderTimeline() {
  if (renderedCase !== current.id) {
    $('scenario-timeline').replaceChildren();
    current.steps.forEach((step, index) => {
      const item = create('li');
      const button = create('button', '', step.phase);
      button.type = 'button';
      button.setAttribute('aria-label', `Step ${index + 1}: ${step.title}`);
      button.addEventListener('click', () => changeStep(index));
      button.addEventListener('keydown', event => {
        const target = event.key === 'ArrowRight' ? Math.min(current.steps.length - 1, index + 1)
          : event.key === 'ArrowLeft' ? Math.max(0, index - 1)
          : event.key === 'Home' ? 0 : event.key === 'End' ? current.steps.length - 1 : null;
        if (target === null) return;
        event.preventDefault();
        changeStep(target);
        $('scenario-timeline').querySelectorAll('button')[target].focus();
      });
      item.append(button);
      $('scenario-timeline').append(item);
    });
    renderedCase = current.id;
  }
  $('scenario-timeline').querySelectorAll('button').forEach((button, index) => {
    if (index === stepIndex) button.setAttribute('aria-current', 'step');
    else button.removeAttribute('aria-current');
    button.classList.toggle('visited', index < stepIndex);
  });
}
function render() {
  const step = current.steps[stepIndex];
  const fields = {
    'case-number': `CASE ${current.number} / 06`, 'case-title': current.title,
    'case-subtitle': current.subtitle, 'case-tool': current.tool,
    'case-target': current.target, 'case-category': current.environment,
    'case-outcome': current.outcome, 'case-rule': current.rule,
    'case-evidence': current.evidence, 'step-title': step.title,
    'step-detail': step.detail, 'step-signal': step.signal,
    'step-phase': step.phase, 'step-position': `${String(stepIndex + 1).padStart(2, '0')} / ${String(current.steps.length).padStart(2, '0')}`
  };
  for (const [id, value] of Object.entries(fields)) $(id).textContent = value;
  $('case-source').href = current.source;
  $('previous-step').disabled = stepIndex === 0;
  $('next-step').textContent = stepIndex === current.steps.length - 1 ? 'Next case →' : 'Next step →';
  $('next-step').setAttribute('aria-label', stepIndex === current.steps.length - 1 ? 'Next case' : 'Next step');
  document.querySelectorAll('[data-case]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.case === current.id)));
  renderTimeline();
}
$('previous-step').addEventListener('click', () => changeStep(stepIndex - 1));
$('restart-case').addEventListener('click', () => changeStep(0));
$('next-step').addEventListener('click', () => {
  if (stepIndex + 1 < current.steps.length) changeStep(stepIndex + 1);
  else chooseCase(SCENARIOS[(SCENARIOS.indexOf(current) + 1) % SCENARIOS.length].id);
});
let toastTimer;
function toast(message) {
  $('toast').textContent = message;
  $('toast').classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $('toast').classList.remove('visible'), 4500);
}
$('copy-case').addEventListener('click', async () => {
  const url = new URL(location.href);
  url.searchParams.set('case', current.id);
  url.searchParams.set('step', String(stepIndex + 1));
  url.hash = 'cases';
  try { await navigator.clipboard.writeText(url.href); toast('Link copied to this case and step.'); }
  catch { $('case-notice').textContent = `Copy this case link: ${url.href}`; }
});
window.addEventListener('popstate', readLocation);
readLocation();
// The guide is presentation-only. No local API is read or invoked here.
$('demo-mode-description').textContent = 'Documented behavior, reconstructed step by step. No tools run and no approvals are issued.';
document.body.dataset.mode = SHOWCASE_MODE.id;

const docs = 'https://github.com/christophervalle85/agent-black-box-design-lab/blob/main/docs/';
const boundaries = {
  client: { category: '01 / Request origin', title: 'A request is not permission.', description: 'A local model or MCP client proposes a tool call. The model can choose what to request, but a deterministic guard decides whether the trusted adapter may run.', limit: 'Scope: only explicitly routed calls are checked. Other agents and unrelated host processes are outside this boundary.', source: 'SECURITY.md' },
  guard: { category: '02 / Application enforcement', title: 'Check. Review. Dispatch.', description: 'The Node gateway validates a fixed tool allowlist and its arguments. Eligible new note writes pause for a one-time decision on the exact filename and content. Denied operations never reach the execution callback.', limit: 'Limit: Node and its controller remain unsandboxed. Local approval does not establish independent operator identity against same-user compromise.', source: 'MCP_GATEWAY.md' },
  worker: { category: '03 / Operating-system enforcement', title: 'A narrow native boundary.', description: 'In macOS required mode, a separately signed App Sandbox XPC worker handles only bounded synthetic note reads and exclusive writes in its own workspace. Signatures, peer identity, and workspace binding are verified first.', limit: 'Limit: this is not a general Node sandbox or arbitrary-file tool. The recorded isolation diagnostic is a separate worker-source build; public notarized distribution is not established.', source: 'v0.8-final-native-acceptance.md' },
  audit: { category: '04 / Evidence and custody', title: 'A record you can check.', description: 'A local HMAC chain authenticates audit records. A pending journal recovers exact interrupted writes. Signed receipts can be kept separately and compared against an earlier anchored history.', limit: 'Limit: same-user access to local keys can undermine provenance. Tamper evidence is not immutability, and manual receipt custody is not an automatic remote service.', source: 'AUDIT_TRUST.md' }
};
function selectBoundary(id) {
  const data = boundaries[id];
  $('boundary-category').textContent = data.category;
  $('boundary-title').textContent = data.title;
  $('boundary-description').textContent = data.description;
  $('boundary-limit').textContent = data.limit;
  $('boundary-source').href = docs + data.source;
  document.querySelectorAll('[data-boundary]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.boundary === id)));
}
document.querySelectorAll('[data-boundary]').forEach(button => button.addEventListener('click', () => selectBoundary(button.dataset.boundary)));
selectBoundary('guard');
const evidence = [...document.querySelectorAll('.evidence-record')];
document.querySelectorAll('[data-filter]').forEach(button => button.addEventListener('click', () => {
  const filter = button.dataset.filter;
  evidence.forEach(record => { record.hidden = filter !== 'all' && record.dataset.category !== filter; });
  document.querySelectorAll('[data-filter]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
  $('evidence-count').textContent = `${evidence.filter(record => !record.hidden).length} records`;
}));
function revealEvidenceHash() {
  const record = evidence.find(item => '#' + item.id === location.hash);
  if (!record) return;
  document.querySelector('[data-filter="all"]').click();
  record.open = true;
}
window.addEventListener('hashchange', revealEvidenceHash);
revealEvidenceHash();
const navigation = [...document.querySelectorAll('.site-nav a')];
const sections = navigation.map(link => document.querySelector(link.hash));
let scrollScheduled = false;
function updateNavigation() {
  const top = document.querySelector('.site-header').offsetHeight + 130;
  let selected = sections[0];
  for (const section of sections) if (section.getBoundingClientRect().top <= top) selected = section;
  navigation.forEach(link => {
    if (link.hash === '#' + selected.id) link.setAttribute('aria-current', 'location');
    else link.removeAttribute('aria-current');
  });
  scrollScheduled = false;
}
window.addEventListener('scroll', () => { if (!scrollScheduled) { scrollScheduled = true; requestAnimationFrame(updateNavigation); } }, { passive: true });
updateNavigation();
