import { randomUUID } from 'node:crypto';
import { evaluatePolicy } from './policy.mjs';

const riskScore = { low: 10, medium: 45, high: 75, critical: 95 };

export function redact(text) {
  return String(text)
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_AWS_KEY]')
    .replace(/\bgh[pousr]_[a-zA-Z0-9_]{20,}\b/g, '[REDACTED_GITHUB_TOKEN]')
    .replace(/\bsk-[a-zA-Z0-9_-]{12,}\b/g, '[REDACTED_TOKEN]')
    .replace(/((?:api[_-]?key|authorization|password|token|secret)\s*[=:]\s*)([^\s&;,"']+)/gi, '$1[REDACTED]')
    .slice(0, 180);
}

export function describeInput(tool, args) {
  // Intentionally avoid logging full arguments, file contents or URL query strings.
  if (!args || typeof args !== 'object') return 'Invalid input';
  if (tool === 'file.write') return `new note: ${redact(args.path ?? '<missing>')} (content not logged)`;
  if (tool === 'file.read') return `path: ${redact(args.path ?? '<missing>')}`;
  if (tool === 'network.fetch') {
    let host = 'invalid URL';
    try { host = new URL(args.url).host; } catch { /* ignore malformed input */ }
    return `${redact(args.method ?? '?')} ${redact(host)}`;
  }
  if (tool === 'shell.exec') return 'Shell command requested (arguments not retained)';
  return 'Tool arguments not retained';
}

/**
 * Pre-execution guard for in-process tools. A callback is invoked only on ALLOW.
 * This cannot intercept calls that bypass the wrapper.
 */
export async function guardedToolCall({ agentId, runId, tool, args, execute, store, workspaceRoot, source = 'integration', requestApproval, signal, recordStart = false }) {
  if (typeof execute !== 'function') throw new TypeError('An execution callback is required.');
  // Audit integrity must be healthy before any trusted adapter can run.
  // Never execute first and discover a broken log after the side effect.
  store.verify();
  const policy = evaluatePolicy(tool, args, workspaceRoot);
  // A human approves these exact primitive values, not mutable model objects.
  const reviewedArgs = policy.decision === 'review' ? Object.freeze({ path: args.path, content: args.content }) : null;
  const start = performance.now();
  const event = {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    runId: String(runId), agentId: String(agentId), source,
    tool, input: describeInput(tool, args),
    decision: policy.decision, risk: policy.risk,
    riskScore: riskScore[policy.risk], ruleId: policy.ruleId,
    reason: policy.reason,
    outcome: policy.decision === 'block' ? 'blocked' : 'success',
    summary: policy.decision === 'block' ? 'Execution prevented by policy.' : '',
    durationMs: 0
  };

  if (policy.decision === 'allow' && recordStart) {
    event.approvalId = event.id; // stable request identity for lifecycle projection
    event.outcome = 'pending';
    event.summary = 'Policy allowed; downstream execution not complete.';
    store.add({ ...event }); // fail closed if audit is unavailable
    event.id = randomUUID();
    event.timestamp = new Date().toISOString();
  }

  if (policy.decision === 'review') {
    // A review record is persisted before the operator can authorize execution.
    event.approvalId = event.id;
    event.outcome = 'pending';
    event.summary = 'Awaiting one-time human approval. No execution yet.';
    store.add({ ...event });
    let response = { approved: false, reason: 'No approval service available; failed closed.' };
    if (typeof requestApproval === 'function') {
      try { response = await requestApproval({ id: event.approvalId, agentId, runId, tool, args: reviewedArgs, input: event.input }); }
      catch { response = { approved: false, reason: 'Approval service failed; denied.' }; }
    }
    event.id = randomUUID();
    event.timestamp = new Date().toISOString();
    // A cancellation wins even if an approval reply races with the abort.
    // Never leave a blocked write labelled APPROVAL_GRANTED or successful.
    const cancelledDuringApproval = signal?.aborted === true;
    const approved = response?.approved === true && !cancelledDuringApproval;
    event.decision = approved ? 'allow' : 'block';
    event.ruleId = cancelledDuringApproval ? 'MCP_CANCELLED' : approved ? 'APPROVAL_GRANTED' : 'APPROVAL_DENIED';
    event.reason = cancelledDuringApproval ? 'Client cancelled while awaiting human approval.' :
      approved ? 'The local operator approved this exact note creation.' : 'Human approval was not granted.';
    event.outcome = approved ? 'success' : 'blocked';
    event.summary = cancelledDuringApproval ? 'Cancellation prevented downstream execution.' :
      approved ? 'Human approval granted; executing controlled adapter.' : 'Note creation prevented: approval denied, unavailable, or expired.';
    if (event.decision === 'block') {
      event.durationMs = Math.round((performance.now() - start) * 10) / 10;
      store.add({ ...event });
      return { event, result: null };
    }
  }
  if (policy.decision === 'block') {
    event.durationMs = Math.round((performance.now() - start) * 10) / 10;
    store.add(event);
    return { event, result: null };
  }

  if (signal?.aborted) {
    event.decision = 'block'; event.outcome = 'blocked'; event.ruleId = 'MCP_CANCELLED';
    event.summary = 'Client cancelled before downstream execution.';
    store.add(event);
    return { event, result: null };
  }

  try {
    const result = await execute(reviewedArgs ?? args);
    // Completion and cancellation can race. Once dispatch began, a write
    // may already have committed even if the client no longer wants its
    // result. Record uncertainty instead of an incorrect successful reply.
    if (signal?.aborted) throw Object.assign(
      new Error('MCP request cancelled after execution started.'),
      { outcomeUnknown: true }
    );
    event.outcome = result?.simulated ? 'simulated' : 'success';
    event.summary = redact(result?.summary ?? 'Tool completed (output not recorded).');
    event.durationMs = Math.round((performance.now() - start) * 10) / 10;
    store.add(event);
    return { event, result: result?.value };
  } catch (error) {
    event.outcome = 'error';
    if (signal?.aborted || error?.outcomeUnknown === true) {
      event.ruleId = 'MCP_OUTCOME_UNKNOWN';
      event.reason = signal?.aborted
        ? 'The client cancelled after execution began. Side effects may have already occurred.'
        : 'Native or downstream acknowledgement was lost after dispatch; side effects may already have occurred.';
      event.summary = signal?.aborted
        ? 'Downstream was cancelled; execution outcome is uncertain, not safely rolled back.'
        : 'Downstream failed or timed out; write outcome unknown, not safely rolled back.';
    } else {
      event.summary = 'Execution failed; raw error details withheld from audit storage.';
    }
    event.durationMs = Math.round((performance.now() - start) * 10) / 10;
    store.add(event);
    return { event, result: null, error };
  }
}
