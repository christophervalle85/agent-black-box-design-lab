/*
 * v0.9 presentation fixtures. These timelines are illustrative reconstructions,
 * NOT live requests, freshly collected macOS evidence, or audit log records.
 * Keep this module dependency-free so the browser and Node tests share it.
 */
const doc = name => 'https://github.com/christophervalle85/agent-black-box-design-lab/blob/main/docs/' + name;

export const SHOWCASE_MODE = Object.freeze({
  id: 'illustrative',
  label: 'Illustrative walkthrough',
  explanation: 'These guided steps describe tested security behavior. Playing them does not invoke the MCP gateway, modify files, approve requests, or verify native enforcement.'
});

export const SCENARIOS = Object.freeze([
  {
    id: 'restricted-file', number: '01', kind: 'policy', outcome: 'BLOCKED',
    title: 'A secret the agent cannot read',
    subtitle: 'The model requests .env. Policy catches it before the adapter runs.',
    tool: 'file.read', target: '.env', rule: 'DENY_SENSITIVE_FILE',
    environment: 'Node policy guard', evidence: 'Documented policy test',
    source: doc('SECURITY.md'),
    steps: [
      { phase: 'REQUEST', title: 'The agent asks for a credential file',
        detail: 'The proposed tool call targets .env in the workspace.', signal: 'file.read  ·  path=.env' },
      { phase: 'EVALUATE', title: 'Sensitive path matched',
        detail: 'The deterministic policy rejects dot-env files before the tool adapter is called.', signal: 'DENY_SENSITIVE_FILE' },
      { phase: 'DECISION', title: 'Execution never begins',
        detail: 'The guarded call records a blocked decision. No .env contents are returned.', signal: 'BLOCKED  ·  no adapter dispatch' }
    ]
  },
  {
    id: 'shell-command', number: '02', kind: 'policy', outcome: 'BLOCKED',
    title: 'The shell command that never runs',
    subtitle: 'A model-produced install command hits a hard stop.',
    tool: 'shell.exec', target: 'curl … | sh', rule: 'DENY_SHELL',
    environment: 'Node policy guard', evidence: 'Documented policy test',
    source: doc('SECURITY.md'),
    steps: [
      { phase: 'REQUEST', title: 'A tool call proposes a shell command',
        detail: 'The model attempts to invoke shell.exec. The example deliberately contains no real destination.', signal: 'shell.exec  ·  curl … | sh' },
      { phase: 'EVALUATE', title: 'Unregistered execution authority is denied',
        detail: 'The policy has no permission path for arbitrary shell execution.', signal: 'DENY_SHELL' },
      { phase: 'DECISION', title: 'Denied before execution',
        detail: 'No shell adapter is dispatched. The requested command is not run.', signal: 'BLOCKED  ·  no shell process' }
    ]
  },
  {
    id: 'human-approval', number: '03', kind: 'review', outcome: 'REVIEWED',
    title: 'Approval is not a blank check',
    subtitle: 'One bounded write, one operator decision, one use.',
    tool: 'file.write', target: 'summary-demo.txt', rule: 'REQUIRE_NOTE_APPROVAL',
    environment: 'Node approval queue', evidence: 'Documented approval lifecycle',
    source: doc('MCP_GATEWAY.md'),
    steps: [
      { phase: 'REQUEST', title: 'The agent asks to create a note',
        detail: 'A new top-level text note is eligible for human review, not automatic execution.', signal: 'file.write  ·  summary-demo.txt' },
      { phase: 'PAUSE', title: 'Execution is suspended',
        detail: 'The exact filename and content are presented for explicit operator review.', signal: 'REQUIRE_NOTE_APPROVAL' },
      { phase: 'CONSENT', title: 'Operator approves once',
        detail: 'This storyboard follows the approval path. No real approval is issued by this page.', signal: 'APPROVED  ·  one request only' },
      { phase: 'EXECUTE', title: 'Only the reviewed write can resume',
        detail: 'The guarded adapter attempts exclusive creation. A preexisting file still causes failure.', signal: 'O_EXCL + O_NOFOLLOW' },
      { phase: 'AUDIT', title: 'The decision leaves a record',
        detail: 'The review and terminal outcome remain separate authenticated audit events.', signal: 'APPROVAL_GRANTED → terminal event' }
    ]
  },
  {
    id: 'path-traversal', number: '04', kind: 'policy', outcome: 'BLOCKED',
    title: 'Outside the workspace',
    subtitle: 'A relative path cannot become authority to escape.',
    tool: 'file.read', target: '../private/secrets.txt', rule: 'DENY_PATH_ESCAPE',
    environment: 'Node policy guard', evidence: 'Documented policy test',
    source: doc('SECURITY.md'),
    steps: [
      { phase: 'REQUEST', title: 'The model supplies parent traversal',
        detail: 'The proposed relative path tries to escape the configured demo workspace.', signal: 'file.read  ·  ../private/secrets.txt' },
      { phase: 'EVALUATE', title: 'Path normalization is not permission',
        detail: 'Dot-segment and boundary checks deny traversal before any filesystem read.', signal: 'DENY_PATH_ESCAPE' },
      { phase: 'DECISION', title: 'Request rejected',
        detail: 'The adapter does not receive an authorized read operation.', signal: 'BLOCKED  ·  no file read' }
    ]
  },
  {
    id: 'native-boundary', number: '05', kind: 'native', outcome: 'OS DENIAL',
    title: 'An actual sandbox boundary',
    subtitle: 'A separate signed diagnostic worker hits operating-system denial.',
    tool: 'native diagnostic', target: 'host-private file + loopback', rule: 'APP_SANDBOX',
    environment: 'macOS signed XPC worker-source diagnostic', evidence: 'Real-Mac acceptance; separate diagnostic build',
    source: doc('v0.8-final-native-acceptance.md'),
    steps: [
      { phase: 'PREPARE', title: 'A disposable worker-source build is signed',
        detail: 'The diagnostic uses the native notes-worker source and a separate signed test build; it is not the byte-identical installed worker.', signal: 'SIGNED DIAGNOSTIC BUILD' },
      { phase: 'PROBE', title: 'The worker attempts a forbidden read',
        detail: 'The OS refuses access to a host-private file outside the worker container.', signal: 'EPERM / EACCES' },
      { phase: 'PROBE', title: 'The worker attempts loopback access',
        detail: 'The reachable host listener cannot be contacted from the confined diagnostic worker.', signal: 'NETWORK DENIED' },
      { phase: 'VERIFY', title: 'Private container storage remains available',
        detail: 'The same worker-source build can write to its own sandbox-managed scratch directory.', signal: 'WORKER SCRATCH ALLOWED' }
    ]
  },
  {
    id: 'audit-tamper', number: '06', kind: 'audit', outcome: 'INTEGRITY ALERT',
    title: 'When the audit trail changes',
    subtitle: 'An altered HMAC-linked record fails verification instead of silently passing.',
    tool: 'audit.verify', target: 'tampered audit fixture', rule: 'AUDIT_INTEGRITY_FAILURE',
    environment: 'Local HMAC audit tests', evidence: 'Documented tamper detection',
    source: doc('AUDIT_TRUST.md'),
    steps: [
      { phase: 'BASELINE', title: 'Audit events are authenticated',
        detail: 'A sequence of local events is linked by HMAC and checked against its checkpoint.', signal: 'HMAC-SHA256 CHAIN' },
      { phase: 'MUTATE', title: 'A test record is modified',
        detail: 'A fixture changes an earlier record without recomputing valid protection metadata.', signal: 'RECORD CHANGED' },
      { phase: 'VERIFY', title: 'The chain no longer verifies',
        detail: 'Integrity verification reports the mismatch instead of accepting the altered record.', signal: 'INTEGRITY FAILURE' },
      { phase: 'CONTAIN', title: 'Protected operations fail closed',
        detail: 'The local guard refuses protected execution when audit integrity is compromised.', signal: 'EXECUTION BLOCKED' }
    ]
  }
].map(scenario => Object.freeze({ ...scenario, steps: Object.freeze(scenario.steps.map(step => Object.freeze(step))) })));

export function findScenario(id) {
  return SCENARIOS.find(scenario => scenario.id === id) ?? null;
}
