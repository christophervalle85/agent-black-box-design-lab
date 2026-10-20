import { randomUUID } from 'node:crypto';

/** In-memory, single-use, time-limited authorization requests.
 * Approval decisions never authorize a new tool invocation: the waiting guard
 * resumes exactly the callback and immutable args that created the request.
 */
export class ApprovalQueue {
  constructor({ timeoutMs = 90000 } = {}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new RangeError('timeoutMs must be positive');
    this.timeoutMs = timeoutMs;
    this.pending = new Map();
    this.closed = false;
  }

  wait({ id = randomUUID(), runId, agentId, tool, args, input }) {
    if (this.closed) return Promise.resolve({ approved: false, reason: 'Approval service stopped.' });
    if (this.pending.has(id)) throw new Error('Duplicate approval request.');
    // Only note creation is reviewable in v0.3. Do not expose arbitrary model
    // tool arguments in the review API.
    if (tool !== 'file.write') return Promise.resolve({ approved: false, reason: 'Unsupported approval operation.' });
    const request = Object.freeze({
      id, runId, agentId, tool, input,
      filename: args.path, content: args.content,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + this.timeoutMs).toISOString()
    });
    return new Promise(resolve => {
      const timer = setTimeout(() => this.finish(id, false, 'Approval timed out.'), this.timeoutMs);
      timer.unref?.();
      this.pending.set(id, { request, resolve, timer });
    });
  }

  list() { return [...this.pending.values()].map(({ request }) => request); }
  finish(id, approved, reason = '') {
    const record = this.pending.get(id);
    if (!record) return false;
    // Delete FIRST so the approval is consumed exactly once.
    this.pending.delete(id);
    clearTimeout(record.timer);
    record.resolve({ approved, reason: reason || (approved ? 'Approved by local operator.' : 'Denied by local operator.') });
    return true;
  }
  close() {
    this.closed = true;
    for (const id of [...this.pending.keys()]) this.finish(id, false, 'Approval service stopped.');
  }
}
