/**
 * Read-only projection over the append-only audit stream.
 * Each tool request has one visible row, but retains every lifecycle event.
 * Do not mutate the underlying events or collapse them on disk.
 *
 * Input is newest-first (the order returned by AuditStore.list).
 */
export function groupAuditEvents(events) {
  const byRequest = new Map();
  // The input is newest-first. Insertion order therefore tracks the most
  // recent lifecycle event of each request, even when requests interleave.
  for (const event of events) {
    const key = event.approvalId ? `approval:${event.approvalId}` : `event:${event.id}`;
    let group = byRequest.get(key);
    if (!group) {
      group = { id: event.approvalId ?? event.id, events: [] };
      byRequest.set(key, group);
    }
    group.events.push(event);
  }
  return [...byRequest.values()].map(group => {
    const latest = group.events[0];
    const history = group.events.reverse();
    return {
      ...latest,
      id: group.id, // stable request identity for both pending and resolved states
      latestEventId: latest.id,
      startedAt: history[0].timestamp,
      auditEventCount: history.length,
      events: history
    };
  });
}

/** Apply decision filters to the current state of each tool request, not every event. */
export function filterActivity(activity, decision) {
  if (!decision || decision === 'all') return activity;
  if (decision === 'reviewed') return activity.filter(item => item.events.some(e => e.decision === 'review'));
  return activity.filter(item => item.decision === decision);
}
