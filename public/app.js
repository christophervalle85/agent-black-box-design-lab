const state = { activity: [], policies: [], approvals: [], filter: 'all', view: 'overview', selected: null };
const $ = id => document.getElementById(id);
const text = (node, value) => { node.textContent = String(value); };
const ago = timestamp => {
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(timestamp)) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return new Date(timestamp).toLocaleDateString();
};
const make = (tag, className = '', label = '') => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (label) node.textContent = label;
  return node;
};
const empty = (label = 'No activity to display') => {
  const box = make('div', 'empty-state');
  box.append(make('div', 'empty-icon', '◇'), make('strong', '', label), make('p', '', 'Run the demo agent to generate real policy decisions and explore its audit trail.'));
  return box;
};
const statusLabel = event => event.decision === 'review' ? 'Pending review' : event.decision === 'block' ? 'Blocked' : event.outcome === 'error' ? 'Failed' : event.outcome === 'simulated' ? 'Simulated' : 'Allowed';

async function fetchJson(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
async function refresh() {
  try {
    const response=await fetch('/api/audit/incidents');
    const incident=await response.json();
    text($('incident-status'),incident.actionable?('CRITICAL: '+incident.incidentCode):'None detected');
    text($('incident-guidance'),incident.actionable?
      'Audit evidence needs investigation. Protected tool execution is disabled; preserve records and do not reseal.':
      (incident.externalCheckpoint==='verified'?'External checkpoint matches the local history.':'Local chain verified. Independent checkpoint comparison is not configured.'));
    text($('audit-integrity-label'),incident.actionable?
      ('CRITICAL: '+incident.incidentCode):
      ('Verified HMAC chain · '+incident.records+' records · external '+incident.externalCheckpoint));
  }catch{ text($('audit-integrity-label'),'Integrity status unavailable — investigate'); text($('incident-status'),'Unknown'); text($('incident-guidance'),'Incident reporting unavailable.'); }
  const [ev, stats, pol] = await Promise.all([
    fetchJson('/api/activity?limit=300'), fetchJson('/api/stats'), fetchJson('/api/policies')
  ]);
  state.activity = ev.activity;
  state.policies = pol.policies;
  text($('total-value'), stats.total);
  text($('allowed-value'), stats.allowed);
  text($('blocked-value'), stats.blocked);
  text($('risk-value'), stats.highRisk);
  text($('nav-count'), stats.total);
  text($('audit-event-count'), `${stats.auditEvents} underlying audit events in current window`);
  text($('policy-count'), `${pol.policies.length} active`);
  render();
}
function renderRecent() {
  const parent = $('recent-activity');
  parent.replaceChildren();
  if (!state.activity.length) { parent.append(empty()); return; }
  for (const event of state.activity.slice(0, 6)) {
    const item = make('button', 'recent-event');
    item.type = 'button';
    const icon = make('div', `event-icon ${event.decision}`, event.decision === 'allow' ? '✓' : event.decision === 'review' ? '!' : '×');
    const main = make('div', 'event-main');
    main.append(make('strong', '', event.tool), make('small', '', `${event.agentId}  ·  ${event.ruleId}`));
    const side = make('div', 'event-side');
    side.append(make('span', `status ${event.decision}`, statusLabel(event)), make('small', '', ago(event.timestamp)));
    item.append(icon, main, side);
    item.addEventListener('click', () => showEvent(event));
    parent.append(item);
  }
}
function renderTable() {
  const body = $('event-table');
  body.replaceChildren();
  const filtered = state.activity.filter(item =>
    state.filter === 'all' || (state.filter === 'reviewed'
      ? item.events.some(e => e.decision === 'review')
      : item.decision === state.filter));
  if (!filtered.length) {
    const cell = make('td'); cell.colSpan = 7; cell.append(empty('No matching events'));
    const row = make('tr'); row.append(cell); body.append(row);
  }
  for (const event of filtered) {
    const row = make('tr');
    row.tabIndex = 0;
    row.setAttribute('aria-label', `Inspect ${event.tool} ${statusLabel(event)}`);
    const time = make('td', '', new Date(event.startedAt ?? event.timestamp).toLocaleTimeString());
    const toolCell = make('td');
    toolCell.append(make('span', 'tool-name', event.tool), make('span', 'tool-agent', event.agentId));
    if (event.auditEventCount > 1) toolCell.append(make('span', 'lifecycle-count', `${event.auditEventCount} linked events`));
    const decision = make('td'); decision.append(make('span', `status ${event.decision}`, statusLabel(event)));
    const risk = make('td'); risk.append(make('span', `risk-pill ${event.risk}`, `${event.risk} · ${event.riskScore}`));
    const rule = make('td', 'mono', event.ruleId);
    const outcome = make('td', '', event.outcome);
    row.append(time, toolCell, decision, risk, rule, outcome, make('td', '', '↗'));
    row.addEventListener('click', () => showEvent(event));
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); showEvent(event); } });
    body.append(row);
  }
  text($('table-foot'), `Showing ${filtered.length} tool requests · ${filtered.reduce((total, item) => total + item.auditEventCount, 0)} linked audit events · stored locally`);
}
function renderPolicies() {
  const parent = $('policy-list'); parent.replaceChildren();
  for (const policy of state.policies) {
    const item = make('div', 'policy-item');
    item.append(make('div', 'policy-item-icon', policy.id.startsWith('DENY') ? '⊘' : policy.id.startsWith('REQUIRE') ? '◷' : '✓'));
    const content = make('div');
    content.append(make('h3', '', policy.id), make('p', '', policy.description));
    item.append(content, make('span', 'policy-category', policy.category));
    parent.append(item);
  }
}
function render() { renderRecent(); renderTable(); renderPolicies(); }
function showEvent(event) {
  const content = $('dialog-content'); content.replaceChildren();
  text($('dialog-title'), event.tool);
  const body = make('div', 'dialog-body');
  const fields = [
    ['Decision', event.decision === 'review' ? 'AWAITING APPROVAL — no execution' : event.decision === 'block' ? 'BLOCKED — execution was prevented' : 'ALLOWED — passed pre-execution policy', event.decision === 'block' ? 'red-text' : event.decision === 'review' ? '' : 'green-text'],
    ['Policy rule', event.ruleId, 'mono'],
    ['Reason', event.reason],
    ['Risk assessment', `${event.risk.toUpperCase()} (${event.riskScore}/100)`],
    ['Input summary', event.input, 'mono'],
    ['Execution outcome', event.outcome],
    ['Result summary', event.summary],
    ['Agent / source', `${event.agentId} / ${event.source}`],
    ['Run ID', event.runId, 'mono'],
    ['Timestamp', new Date(event.timestamp).toLocaleString()],
    ['Elapsed', `${event.durationMs} ms`],
    ['Approval ID', event.approvalId ?? 'None', 'mono'],
    ['Tool request ID', event.id, 'mono'],
    ['Latest audit event ID', event.latestEventId ?? event.id, 'mono']
  ];
  for (const [title, value, color = ''] of fields) {
    const row = make('div', 'dialog-field');
    row.append(make('span', 'dialog-label', title), make('div', `dialog-value ${color}`, value));
    body.append(row);
  }
  // The audit stream is immutable: show the complete lifecycle behind this
  // single tool-request row rather than overwriting its historical decisions.
  const history = event.events ?? [event];
  if (history.length > 1) {
    const timeline = make('section', 'audit-timeline');
    timeline.append(make('h3', '', `Decision timeline · ${history.length} audit events`));
    for (const [index, step] of history.entries()) {
      const entry = make('div', 'audit-timeline-item');
      const header = make('div', 'audit-timeline-header');
      const title = step.decision === 'review' ? 'Approval requested' :
        step.ruleId === 'APPROVAL_DENIED' ? 'Approval denied' :
        step.ruleId === 'APPROVAL_GRANTED' ? 'Approval granted and action completed' :
        step.decision === 'block' ? 'Request blocked' : 'Action allowed';
      header.append(make('strong', '', `${index + 1}. ${title}`), make('time', '', new Date(step.timestamp).toLocaleTimeString()));
      entry.append(header, make('div', 'audit-timeline-detail', `${step.ruleId} · ${step.outcome}`),
        make('p', '', step.summary || step.reason));
      timeline.append(entry);
    }
    body.append(timeline);
  }
  content.append(body); $('event-dialog').showModal();
}
function navigate(view) {
  state.view = view;
  const labels = { overview: ['Security overview', 'Monitor every agent action. Understand every security decision.', 'Overview'], agent: ['Local AI agent', 'Give a real model a task and observe guarded tool calls in real time.', 'AI agent'], approvals: ['Human approvals', 'Inspect and authorize individual pending tool requests.', 'Approvals'], activity: ['Activity log', 'Explore decisions, risk classifications and execution outcomes.', 'Activity log'], policies: ['Security policies', 'Review the rules protecting instrumented tools.', 'Security policies'] };
  const [title, subtitle, crumb] = labels[view];
  text($('page-title'), title); text($('page-subtitle'), subtitle); text($('page-crumb'), crumb);
  for (const section of ['overview', 'agent', 'approvals', 'activity', 'policies']) $(section + '-view').classList.toggle('hidden', section !== view);
  for (const button of document.querySelectorAll('.nav-item')) button.classList.toggle('active', button.dataset.view === view);
}
let toastTimeout;
function toast(message) {
  text($('toast'), message); $('toast').classList.add('visible');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => $('toast').classList.remove('visible'), 4500);
}
async function runDemo() {
  const button = $('run-demo'); button.disabled = true;
  const initial = button.innerHTML;
  button.textContent = 'Running demo…';
  try {
    const data = await fetchJson('/api/demo/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    await refresh();
    toast(`Run completed: ${data.allowed} allowed · ${data.blocked} blocked · ${data.errors} failed`);
    navigate('activity');
  } catch (error) { toast(`Demo failed: ${error.message}`); }
  finally { button.disabled = false; button.innerHTML = initial; }
}
async function checkAgentModel() {
  try {
    const state = await fetchJson('/api/agent/status');
    text($('model-name'), state.model);
    $('model-led').classList.toggle('ready', state.ready);
    text($('model-status'), state.ready ? 'Connected · model installed and ready' : state.reachable ? 'Ollama connected · run ollama pull ' + state.model : 'Offline · start Ollama on localhost:11434');
  } catch { text($('model-status'), 'Unable to check Ollama status'); }
}
async function runRealAgent() {
  const prompt = $('agent-prompt').value.trim();
  if (!prompt) { toast('Enter a task first.'); return; }
  const button = $('run-agent'); button.disabled = true;
  text(button, 'Running… (model may take a while)');
  text($('agent-result-status'), 'RUNNING');
  text($('agent-answer'), 'Waiting for Ollama. Any write_note request will pause for a decision in the approval panel below…');
  $('agent-run-meta').replaceChildren(); $('agent-run-events').replaceChildren();
  try {
    const result = await fetchJson('/api/agent/run', {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ prompt })
    });
    text($('agent-answer'), result.answer);
    text($('agent-result-status'), result.status === 'finished' ? 'COMPLETE' : 'LIMIT REACHED');
    text($('agent-run-meta'), `${result.model} · ${result.toolCalls} audited tool calls · Run ${result.runId}`);
    const parent = $('agent-run-events');
    for (const ev of result.events) {
      const row = make('button', 'agent-run-event'); row.type = 'button';
      row.append(make('span', `status ${ev.decision}`, statusLabel(ev)), make('span', 'mono', ev.tool), make('span', '', ev.ruleId));
      row.addEventListener('click', () => showEvent(ev)); parent.append(row);
    }
    await refresh();
    toast(`Agent finished · ${result.toolCalls} tool calls recorded`);
  } catch (error) {
    text($('agent-result-status'), 'ERROR');
    text($('agent-answer'), `Agent could not run: ${error.message}`);
    toast(error.message);
    checkAgentModel();
  } finally { button.disabled = false; text(button, '✧ Run with local LLM ↗'); refreshApprovals().catch(() => {}); }
}
$('run-agent').addEventListener('click', runRealAgent);
$('check-model').addEventListener('click', checkAgentModel);
for (const preset of document.querySelectorAll('.preset-button')) preset.addEventListener('click', () => {
  $('agent-prompt').value = preset.dataset.prompt;
  $('agent-prompt').focus();
});
checkAgentModel();
for (const button of document.querySelectorAll('.nav-item')) button.addEventListener('click', () => navigate(button.dataset.view));
$('view-all').addEventListener('click', () => navigate('activity'));
$('run-demo').addEventListener('click', runDemo);
$('decision-filter').addEventListener('change', e => { state.filter = e.target.value; renderTable(); });
$('dialog-close').addEventListener('click', () => $('event-dialog').close());
$('event-dialog').addEventListener('click', e => { if (e.target === $('event-dialog')) $('event-dialog').close(); });

refresh().catch(error => toast(`Could not load audit data: ${error.message}`));
try {
  const stream = new EventSource('/api/stream');
  stream.addEventListener('open', () => { text($('connection-label'), 'Live monitoring'); });
  stream.addEventListener('audit', () => refresh().catch(() => {}));
  stream.addEventListener('error', () => { text($('connection-label'), 'Reconnecting'); });
} catch { text($('connection-label'), 'Offline'); }
// Safe fallback when SSE is unavailable.
setInterval(() => refresh().catch(() => {}), 30000);

async function refreshApprovals() {
  const data = await fetchJson('/api/approvals');
  state.approvals = data.pending;
  text($('approval-count'), state.approvals.length);
  for (const id of ['approvals-list', 'agent-approvals']) renderApprovals($(id));
}
function renderApprovals(parent) {
  parent.replaceChildren();
  if (!state.approvals.length) {
    const item = make('p', 'approval-empty', 'No pending requests. Run the "Approval test" preset to see a human review.');
    parent.append(item);
    return;
  }
  for (const approval of state.approvals) {
    const card = make('article', 'approval-card');
    card.append(make('div', 'approval-kicker', `WRITE NOTE · ${approval.agentId} · Expires ${new Date(approval.expiresAt).toLocaleTimeString()}`),
      make('h3', '', approval.filename),
      make('p', 'approval-caption', 'Exact content that will be written if you approve:'),
      make('pre', 'approval-content', approval.content));
    const buttons = make('div', 'approval-actions');
    for (const [decision, label] of [['deny', 'Deny request'], ['approve', 'Approve once']]) {
      const button = make('button', `approval-action ${decision}`, label);
      button.type = 'button';
      button.addEventListener('click', async () => {
        buttons.querySelectorAll('button').forEach(b => b.disabled = true);
        try {
          await fetchJson(`/api/approvals/${approval.id}/decision`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision })
          });
          toast(`Request ${decision === 'approve' ? 'approved' : 'denied'}`);
        } catch (error) { toast(`Approval failed: ${error.message}`); }
        await refreshApprovals().catch(() => {});
      });
      buttons.append(button);
    }
    card.append(buttons); parent.append(card);
  }
}
// Requests appear while /api/agent/run is still waiting for a human decision.
refreshApprovals().catch(() => {});
setInterval(() => refreshApprovals().catch(() => {}), 1500);
// External MCP gateways append audit events in a separate process. SSE is
// in-process only, so poll the read-only projection for these events as well.
setInterval(() => refresh().catch(() => {}), 3000);
