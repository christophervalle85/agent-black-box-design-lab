
// Framing for the legacy MCP stdio binding: one UTF-8 JSON-RPC message per line.
// Explicit byte bounds apply even to a peer that never sends a terminating newline.
export function readJsonLines(stream, { onMessage, onError, maxBytes = 131072 }) {
  const decoder = new TextDecoder('utf-8', {fatal:true});
  let buffer = '';
  let failed = false;
  function fail(message) {
    if (failed) return;
    failed = true;
    stream.off('data', consume);
    onError(new Error(message));
  }
  function consume(chunk) {
    if (failed) return;
    try { buffer += decoder.decode(chunk, {stream:true}); } catch { return fail('Invalid UTF-8 in MCP frame.'); }
    if (Buffer.byteLength(buffer) > maxBytes && !buffer.includes('\n')) return fail('MCP line exceeds limit.');
    for (;;) {
      const index = buffer.indexOf('\n');
      if (index < 0) break;
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      if (Buffer.byteLength(line) > maxBytes) return fail('MCP message exceeds limit.');
      if (!line.trim()) return fail('Empty MCP frame.');
      let message;
      try { message = JSON.parse(line); } catch { return fail('Malformed MCP JSON frame.'); }
      if (!message || Array.isArray(message) || typeof message !== 'object' || message.jsonrpc !== '2.0') return fail('Invalid MCP JSON-RPC envelope.');
      onMessage(message);
    }
    if (Buffer.byteLength(buffer) > maxBytes) fail('MCP frame exceeds limit.');
  }
  stream.on('data', consume);
  stream.on('end', () => {
    try { decoder.decode(); } catch { return fail('Truncated UTF-8 MCP frame.'); }
    if (buffer.trim()) fail('Truncated MCP frame.');
  });
  stream.on('error', error => fail(error.message));
  return () => stream.off('data', consume);
}

export function sendJsonLine(stream, message, maxBytes = 131072) {
  const line = JSON.stringify(message);
  if (Buffer.byteLength(line) > maxBytes) throw new Error('Outgoing MCP response exceeded size limit.');
  if (!stream.write(line + '\n')) {
    // A client that stops reading must not cause unbounded buffering.
    if (stream.writableLength > 2 * maxBytes) throw new Error('MCP output backpressure exceeded.');
  }
}

export class McpPeer {
  constructor(child, { timeoutMs = 12000 } = {}) {
    this.child = child;
    this.timeoutMs = timeoutMs;
    this.pending = new Map();
    this.nextId = 1;
    this.closed = false;
    this.unlisten = readJsonLines(child.stdout, {
      onMessage: response => {
        if (typeof response.method === 'string') {
          // The gateway advertises no sampling, roots, or elicitation capability.
          // Downstream MUST NOT initiate arbitrary requests against the host.
          if (Object.hasOwn(response, 'id')) this.close(new Error('Unsupported downstream server-to-client request.'));
          return;
        }
        const wait = this.pending.get(response.id);
        if (!wait) return;
        this.pending.delete(response.id);
        clearTimeout(wait.timer);
        wait.cleanup();
        if (Object.hasOwn(response, 'error')) wait.reject(new Error('Downstream MCP request failed.'));
        else if (!Object.hasOwn(response, 'result')) wait.reject(new Error('Malformed MCP response.'));
        else wait.resolve(response.result);
      },
      onError: error => this.close(error)
    });
    // A sandbox launch can fail before or during the first JSON-RPC write.
    // A closed stdin otherwise emits an unhandled EPIPE and crashes the gateway.
    child.stdin?.on('error', error => this.close(error));
    child.on('exit', () => this.close(new Error('Downstream MCP process exited.')));
    child.on('error', error => this.close(error));
  }

  request(method, params = {}, { signal } = {}) {
    if (this.closed) return Promise.reject(new Error('Downstream unavailable.'));
    if (this.pending.size >= 8) return Promise.reject(new Error('Too many downstream calls.'));
    if (signal?.aborted) return Promise.reject(new Error('MCP request cancelled.'));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const cancel = () => {
        const wait = this.pending.get(id);
        if (!wait) return;
        this.pending.delete(id);
        clearTimeout(wait.timer);
        wait.cleanup();
        // A downstream operation may ignore a cancellation notification.
        // Terminate the process and refuse further operations. Any already
        // performed side effect remains outcome-uncertain (not rolled back).
        this.close(new Error('Downstream cancelled; side-effect outcome uncertain.'));
        reject(new Error('MCP request cancelled; downstream terminated.'));
      };
      const cleanup = () => signal?.removeEventListener('abort', cancel);
      const timer = setTimeout(() => {
        this.pending.delete(id);
        cleanup();
        // A timed-out downstream write could still be running: kill the child,
        // refuse future calls, and never report the write as safely rolled back.
        this.close(new Error('Downstream MCP timeout; execution outcome uncertain.'));
        reject(new Error('Downstream MCP timeout; execution outcome uncertain.'));
      }, this.timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer, cleanup });
      signal?.addEventListener('abort', cancel, { once: true });
      try { sendJsonLine(this.child.stdin, { jsonrpc: '2.0', id, method, params }, 65536); }
      catch (error) { cancel(); reject(error); }
    });
  }
  notify(method, params = {}) {
    if (!this.closed) sendJsonLine(this.child.stdin, { jsonrpc: '2.0', method, params }, 65536);
  }
  close(error = new Error('MCP transport closed.')) {
    if (this.closed) return;
    this.closed = true;
    this.unlisten?.();
    for (const wait of this.pending.values()) { clearTimeout(wait.timer); wait.cleanup(); wait.reject(error); }
    this.pending.clear();
    if (!this.child.killed) this.child.kill('SIGTERM');
  }
}
