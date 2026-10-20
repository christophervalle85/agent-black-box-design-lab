import { createServer as createHttpServer } from 'node:http';
import { readFileSync, existsSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { evaluatePolicy } from './policy.mjs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AuditStore } from './audit.mjs';
import { POLICIES } from './policy.mjs';
import { runDemo } from './demo.mjs';
import { createOllamaClient, runAgent } from './agent.mjs';
import { ApprovalQueue } from './approvals.mjs';
import { createAuditedMacTransferController } from './macos-transfer-controller.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const appVersion = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const publicFiles = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'application/javascript; charset=utf-8'],
  '/styles.css': ['styles.css', 'text/css; charset=utf-8'],
  // My guided portfolio walkthrough is static and cannot call guarded tools.
  '/showcase': ['showcase.html', 'text/html; charset=utf-8'],
  '/showcase.js': ['showcase.js', 'application/javascript; charset=utf-8'],
  '/showcase.css': ['showcase.css', 'text/css; charset=utf-8'],
  '/showcase-scenarios.mjs': ['showcase-scenarios.mjs', 'application/javascript; charset=utf-8']
};

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(data));
}

export function createBlackBoxServer({ dataFile = join(root, 'data', 'audit.jsonl'), workspaceRoot = join(root, 'demo-workspace'), agentClient = createOllamaClient(), experimentalMacTransferReviews = false, experimentalMacTransferOperatorVerify = null } = {}) {
  if(typeof experimentalMacTransferReviews!=='boolean')
    throw Error('Experimental Mac transfer reviews must be an explicit boolean.');
  if(experimentalMacTransferOperatorVerify!==null &&
     (!experimentalMacTransferReviews ||
      typeof experimentalMacTransferOperatorVerify!=='function'))
    throw Error('Transfer verifier requires explicit experimental mode and a trusted function.');
  mkdirSync(workspaceRoot, { recursive: true });
  const store = new AuditStore(dataFile);
  const approvalQueue = new ApprovalQueue();
  // Explicit IN-PROCESS experiment only; disabled in the normal server CLI.
  // A model/MCP client cannot open or consume reviews over HTTP.
  const macTransfer = experimentalMacTransferReviews
    ? createAuditedMacTransferController({store}) : null;
  // Per-review decision lock; approval is never issued from an unchecked
  // HTTP Origin header, even in explicitly opted-in synthetic tests.
  const activeMacDecisions=new Map();
  // Ephemeral controller credential, file mode 0600. Rotate with every server start.
  // Not protection against hostile programs already running as the same OS user.
  const tokenFile = join(dirname(dataFile), 'mcp-controller-token');
  const controllerToken = randomBytes(32).toString('hex');
  writeFileSync(tokenFile, controllerToken, { mode: 0o600 });
  chmodSync(tokenFile, 0o600);
  let lastDemoStart = 0;
  let activeDemo = false;
  let activeAgent = false;
  let lastAgentStart = 0;
  const streams = new Set();
  const onEvent = event => {
    const message = `event: audit\ndata: ${JSON.stringify(event)}\n\n`;
    for (const res of streams) {
      if (res.writableEnded || res.destroyed) streams.delete(res);
      else res.write(message);
    }
  };
  store.on('event', onEvent);

  const server = createHttpServer(async (req, res) => {
    const host = req.headers.host ?? '';
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host)) return sendJson(res, 403, { error: 'Local host required.' });
    const url = new URL(req.url ?? '/', `http://${host}`);
    if (req.method === 'GET' && url.pathname === '/api/health') return sendJson(res, 200, { ok: true, version: appVersion, mode: 'local-only' });
    if (req.method === 'GET' && url.pathname === '/api/audit/incidents') {
      try {
        const current=store.verify();
        return sendJson(res,200,{state:'verified',severity:'none',records:current.records,
          externalCheckpoint:store.externalReceiptFile?'verified':'not-configured',
          actionable:false,message:'Authenticated audit chain verified.'});
      }catch(error){
        const recovery=/RECOVERY REQUIRED/i.test(error.message);
        const external=/CHECKPOINT (ROLLBACK|FORK)|identity|signing key|signature/i.test(error.message);
        return sendJson(res,503,{state:'blocked',severity:'critical',actionable:true,
          incidentCode:recovery?'RECOVERY_REQUIRED':external?'EXTERNAL_CHECKPOINT_MISMATCH':'AUDIT_INTEGRITY_FAILURE',
          message:'Protected operations are blocked. Preserve audit artifacts and investigate; never reseal.'});
      }
    }
    if (req.method === 'GET' && url.pathname === '/api/audit/integrity') {
      try { const {ok,records,head}=store.verify();return sendJson(res,200,{ok,records,head,algorithm:'HMAC-SHA256'}); }
      catch {return sendJson(res,503,{ok:false,error:'Audit integrity verification failed.'});}
    }
    if (req.method === 'GET' && ['/api/events','/api/activity','/api/stats'].includes(url.pathname)) {
      try { store.verify(); } catch {return sendJson(res,503,{error:'Audit integrity verification failed; results withheld.'});}
    }
    if (req.method === 'GET' && url.pathname === '/api/events') {
      return sendJson(res, 200, { events: store.list({ limit: url.searchParams.get('limit') ?? 300, decision: url.searchParams.get('decision'), runId: url.searchParams.get('runId') }) });
    }
    if (req.method === 'GET' && url.pathname === '/api/activity') {
      return sendJson(res, 200, { activity: store.activity({ limit: url.searchParams.get('limit') ?? 300, decision: url.searchParams.get('decision'), runId: url.searchParams.get('runId') }) });
    }
    if (req.method === 'GET' && url.pathname === '/api/stats') return sendJson(res, 200, store.stats());
    if (req.method === 'GET' && url.pathname === '/api/policies') return sendJson(res, 200, { policies: POLICIES });
    if (req.method === 'GET' && url.pathname === '/api/approvals') {
      return sendJson(res, 200, { pending: approvalQueue.list() });
    }
    if (macTransfer && req.method === 'GET' &&
        url.pathname === '/api/mac/transfers/pending') {
      try {
        return sendJson(res,200,{pending:macTransfer.controller.pending()});
      } catch {
        return sendJson(res,503,{error:'Transfer review audit integrity unavailable.'});
      }
    }
    const macDecisionMatch = macTransfer
      ? /^\/api\/mac\/transfers\/([0-9a-f-]{36})\/decision$/i.exec(url.pathname)
      : null;
    if(req.method === 'POST' && macDecisionMatch){
      // This is a *synthetic* operator-presence integration seam.
      // Same-origin JSON is only anti-CSRF, never operator authentication.
      // In ordinary and opt-in-without-verifier modes, approval is impossible.
      if(req.headers.origin !== 'http://'+host ||
         !String(req.headers['content-type']??'').startsWith('application/json'))
        return sendJson(res,403,{error:'Same-origin review required.'});
      if(!experimentalMacTransferOperatorVerify)
        return sendJson(res,403,{error:'Trusted operator verification is not configured.'});
      let raw='';
      try {
        for await(const chunk of req){
          raw+=chunk.toString('utf8');
          if(Buffer.byteLength(raw)>128)
            return sendJson(res,413,{error:'Decision body too large.'});
        }
      }catch{return sendJson(res,400,{error:'Could not read decision.'});}
      let body;
      try{body=JSON.parse(raw);}catch{return sendJson(res,400,{error:'Invalid decision JSON.'});}
      if(!body || typeof body!=='object' || Array.isArray(body) ||
         Object.keys(body).length!==1 ||
         !['approve','deny'].includes(body.decision))
        return sendJson(res,400,{error:'Decision must be approve or deny.'});
      const reviewId=macDecisionMatch[1];
      if(activeMacDecisions.has(reviewId))
        return sendJson(res,409,{error:'Transfer decision already in progress.'});
      let review;
      try {
        review=macTransfer.controller.pending().find(x=>x.reviewId===reviewId);
      }catch{return sendJson(res,503,{error:'Transfer audit unavailable.'});}
      if(!review)return sendJson(res,409,{error:'No pending transfer review.'});

      const abort=new AbortController();
      activeMacDecisions.set(reviewId,abort);
      const onClose=()=>abort.abort();
      res.once('close',onClose);
      // A native user-presence callback may prompt asynchronously. A dead
      // HTTP caller or a long-running prompt must not approve stale work.
      const timer=setTimeout(()=>abort.abort(),15_000);
      timer.unref?.();
      const aborted=new Promise(resolve=>{
        if(abort.signal.aborted)resolve(false);
        else abort.signal.addEventListener('abort',()=>resolve(false),{once:true});
      });
      try {
        // Only trusted IN-PROCESS callers can supply this function. It must
        // independently verify the operator and the exact reviewed metadata.
        // Tests inject a mock verifier; no native identity proof exists yet.
        const context=Object.freeze({
          reviewId:review.reviewId,intent:review.intent,decision:body.decision
        });
        const verified=await Promise.race([
          Promise.resolve().then(()=>experimentalMacTransferOperatorVerify(context,
            {signal:abort.signal})),
          aborted
        ]);
        if(abort.signal.aborted || res.destroyed)return;
        if(verified!==true)
          return sendJson(res,403,{error:'Operator verification denied.'});
        // Recheck the original unexpired pending review AFTER the verifier
        // completes, and require identical metadata (not just a matching id).
        const pending=macTransfer.controller.pending()
          .find(x=>x.reviewId===review.reviewId);
        if(!pending || JSON.stringify(pending.intent)!==JSON.stringify(review.intent))
          return sendJson(res,409,{error:'Review changed or expired.'});
        if(!macTransfer.controller.decide(review.reviewId,body.decision))
          return sendJson(res,409,{error:'No pending transfer review.'});
        return sendJson(res,200,{resolved:true,transferExecuted:false});
      }catch{
        if(!abort.signal.aborted && !res.destroyed)
          return sendJson(res,503,{error:'Operator verification or audit failed.'});
      }finally{
        clearTimeout(timer);
        res.off('close',onClose);
        activeMacDecisions.delete(reviewId);
      }
      return;
    }
    const decisionMatch = /^\/api\/approvals\/([0-9a-f-]{36})\/decision$/i.exec(url.pathname);
    if (req.method === 'POST' && decisionMatch) {
      if (req.headers.origin !== `http://${host}` || !String(req.headers['content-type'] ?? '').startsWith('application/json')) {
        return sendJson(res, 403, { error: 'Same-origin JSON request required.' });
      }
      let raw = '';
      try {
        for await (const chunk of req) {
          raw += chunk.toString('utf8');
          if (Buffer.byteLength(raw) > 256) return sendJson(res, 413, { error: 'Request is too large.' });
        }
      } catch { return sendJson(res, 400, { error: 'Could not read approval request.' }); }
      let body;
      try { body = JSON.parse(raw); } catch { return sendJson(res, 400, { error: 'Invalid JSON.' }); }
      if (body?.decision !== 'approve' && body?.decision !== 'deny') return sendJson(res, 400, { error: 'Decision must be approve or deny.' });
      if (!approvalQueue.finish(decisionMatch[1], body.decision === 'approve')) return sendJson(res, 409, { error: 'Approval is no longer pending.' });
      return sendJson(res, 200, { resolved: true });
    }
    if (req.method === 'POST' && url.pathname === '/api/mcp/approval') {
      // Only the trusted local MCP gateway may place requests in the approval queue.
      const credential = req.headers.authorization;
      const candidate = typeof credential === 'string' && credential.startsWith('Bearer ') ? credential.slice(7) : '';
      const valid = candidate.length === controllerToken.length &&
        timingSafeEqual(Buffer.from(candidate), Buffer.from(controllerToken));
      if (!valid || req.headers.origin !== undefined ||
          !String(req.headers['content-type'] ?? '').startsWith('application/json')) {
        return sendJson(res, 403, { error: 'Authorized local MCP gateway required.' });
      }
      let raw = '';
      try {
        for await (const chunk of req) {
          raw += chunk.toString('utf8');
          if (Buffer.byteLength(raw) > 4096) return sendJson(res, 413, { error: 'Request too large.' });
        }
      } catch { return sendJson(res, 400, { error: 'Invalid request body.' }); }
      let body;
      try { body = JSON.parse(raw); } catch { return sendJson(res, 400, { error: 'Invalid JSON.' }); }
      const uuid = /^[0-9a-f-]{36}$/i;
      if (!body || !uuid.test(body.id) || typeof body.runId !== 'string' || body.runId.length > 100 ||
          typeof body.agentId !== 'string' || body.agentId.length > 100 || body.tool !== 'file.write' ||
          evaluatePolicy(body.tool, body.args, workspaceRoot).decision !== 'review') {
        return sendJson(res, 400, { error: 'Request not eligible for approval.' });
      }
      if (approvalQueue.pending.size >= 8) return sendJson(res, 429, { error: 'Approval queue full.' });
      // If the MCP caller disappears, cancel the pending request. Never leave a
      // disconnected approval that could later unlock a write.
      let settled = false;
      const onClose = () => { if (!settled) approvalQueue.finish(body.id, false, 'Gateway disconnected.'); };
      res.on('close', onClose);
      try {
        const result = await approvalQueue.wait({ ...body, input: `MCP note: ${body.args.path} (content not logged)` });
        settled = true;
        if (!res.destroyed) sendJson(res, 200, result);
      } catch { if (!res.destroyed) sendJson(res, 503, { error: 'Approval unavailable.' }); }
      finally { settled = true; res.off('close', onClose); }
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/agent/status') {
      const status = await agentClient.status();
      return sendJson(res, 200, status);
    }


    if (req.method === 'GET' && url.pathname === '/api/stream') {
      if (streams.size >= 10) return sendJson(res, 429, { error: 'Too many event listeners.' });
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        'X-Content-Type-Options': 'nosniff'
      });
      res.write(': connected\n\n');
      streams.add(res);
      const heartbeat = setInterval(() => { if (!res.destroyed) res.write(': ping\n\n'); }, 20000);
      req.on('close', () => { clearInterval(heartbeat); streams.delete(res); });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/agent/run') {
      const origin = req.headers.origin;
      if (origin !== `http://${host}` || !String(req.headers['content-type'] ?? '').startsWith('application/json')) {
        return sendJson(res, 403, { error: 'Same-origin JSON request required.' });
      }
      if (activeAgent || Date.now() - lastAgentStart < 800) return sendJson(res, 429, { error: 'Another agent run is active or was started too recently.' });
      let raw = '';
      try {
        for await (const chunk of req) {
          raw += chunk.toString('utf8');
          if (Buffer.byteLength(raw) > 4096) return sendJson(res, 413, { error: 'Request is too large.' });
        }
      } catch { return sendJson(res, 400, { error: 'Could not read request body.' }); }
      let body;
      try { body = JSON.parse(raw); } catch { return sendJson(res, 400, { error: 'Invalid JSON request.' }); }
      if (!body || typeof body.prompt !== 'string' || !body.prompt.trim() || body.prompt.length > 2000) {
        return sendJson(res, 400, { error: 'Prompt must be 1–2,000 characters.' });
      }
      lastAgentStart = Date.now();
      activeAgent = true;
      try {
        const result = await runAgent({ prompt: body.prompt, store, workspaceRoot, chat: args => agentClient.chat(args), model: agentClient.model, approvalQueue });
        return sendJson(res, 200, result);
      } catch (error) {
        const unavailable = /Cannot reach Ollama|model .* unavailable|Ollama timed out/i.test(error.message);
        return sendJson(res, unavailable ? 503 : 502, { error: error.message });
      } finally { activeAgent = false; }
    }

    if (req.method === 'POST' && url.pathname === '/api/demo/run') {
      // Browsers cannot POST cross-origin with JSON without a CORS preflight.
      // Also compare the Origin explicitly to avoid local CSRF.
      const origin = req.headers.origin;
      if (origin !== `http://${host}` || !String(req.headers['content-type'] ?? '').startsWith('application/json')) {
        return sendJson(res, 403, { error: 'Same-origin JSON request required.' });
      }
      const now = Date.now();
      if (activeDemo || now - lastDemoStart < 500) return sendJson(res, 429, { error: 'A demo run is already active or was started too recently.' });
      lastDemoStart = now;
      activeDemo = true;
      try {
        const result = await runDemo({ store, workspaceRoot });
        return sendJson(res, 200, result);
      } catch {
        return sendJson(res, 500, { error: 'Demo execution failed.' });
      } finally {
        activeDemo = false;
      }
    }

    if (req.method === 'GET' && publicFiles[url.pathname]) {
      const [name, contentType] = publicFiles[url.pathname];
      const file = join(root, 'public', name);
      if (!existsSync(file)) return sendJson(res, 404, { error: 'File not found' });
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        'Referrer-Policy': 'no-referrer'
      });
      return res.end(readFileSync(file));
    }
    sendJson(res, 404, { error: 'Not found.' });
  });
  const originalClose = server.close.bind(server);
  server.close = callback => {
    approvalQueue.close();
    for(const pending of activeMacDecisions.values())pending.abort();
    activeMacDecisions.clear();
    macTransfer?.controller.close();
    for (const stream of streams) stream.end();
    streams.clear();
    store.off('event', onEvent);
    return originalClose(callback);
  };
  return { server, store, approvalQueue, tokenFile,
    macTransferHost:macTransfer?.host??null };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { server } = createBlackBoxServer();
  const port = Number(process.env.PORT ?? '4317');
  server.listen(port, '127.0.0.1', () => {
    console.log(`\n  AGENT BLACK BOX  v${appVersion}\n  Dashboard: http://localhost:${port}\n  Listening locally only. Ctrl+C to stop.\n`);
  });
}
