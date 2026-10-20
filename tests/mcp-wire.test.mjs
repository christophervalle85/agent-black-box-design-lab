import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PassThrough} from 'node:stream';
import {EventEmitter} from 'node:events';
import {readJsonLines,McpPeer,sendJsonLine} from '../src/mcp-wire.mjs';

const tick=()=>new Promise(resolve=>setImmediate(resolve));

test('MCP parser rejects malformed JSON and oversized unterminated frames',async()=>{
  const incoming=new PassThrough();const seen=[];const errors=[];
  readJsonLines(incoming,{maxBytes:100,onMessage:x=>seen.push(x),onError:e=>errors.push(e.message)});
  incoming.write('{"jsonrpc":"2.0","method":"ping"}\n');
  incoming.write('x'.repeat(120));
  await tick();
  assert.equal(seen.length,1);
  assert.match(errors[0],/limit/);
  const next=new PassThrough();const bad=[];
  readJsonLines(next,{onMessage:()=>assert.fail('should not accept malformed JSON'),onError:e=>bad.push(e.message)});
  next.write('{broken}\n');
  await tick();
  assert.match(bad[0],/Malformed/);
});

test('MCP peer enforces deadline, terminates unresponsive downstream and rejects future calls',async()=>{
  const child=new EventEmitter();child.stdout=new PassThrough();child.stdin=new PassThrough();child.killed=false;
  child.kill=()=>{child.killed=true;};
  const peer=new McpPeer(child,{timeoutMs:30});
  const hold = setTimeout(() => {}, 100); // keep synthetic peer test loop alive
  await assert.rejects(peer.request('tools/list'),/timeout|uncertain/i);
  clearTimeout(hold);
  assert.equal(child.killed,true);
  await assert.rejects(peer.request('tools/list'),/unavailable/i);
});

test('MCP line sender rejects oversized outbound data',()=>{
  const out=new PassThrough();
  assert.throws(()=>sendJsonLine(out,{jsonrpc:'2.0',id:1,result:'x'.repeat(300)},120),/exceeded/);
});

test('MCP parser rejects ill-formed UTF-8 rather than replacing malformed bytes',async()=>{
  const input=new PassThrough();const issues=[];
  readJsonLines(input,{onMessage:()=>assert.fail('must reject malformed UTF-8'),onError:e=>issues.push(e.message)});
  input.write(Buffer.from([0xc3,0x28,0x0a]));
  await tick();
  assert.match(issues[0],/UTF-8/);
});

test('MCP peer kills the downstream on cancellation after forwarding',async()=>{
  const child=new EventEmitter();child.stdout=new PassThrough();child.stdin=new PassThrough();child.killed=false;
  child.kill=()=>{child.killed=true;};
  const peer=new McpPeer(child,{timeoutMs:2000});
  const c=new AbortController();
  const request=peer.request('tools/call',{name:'write_note'}, {signal:c.signal});
  c.abort();
  await assert.rejects(request,/cancelled|uncertain/i);
  assert.equal(child.killed,true);
  await assert.rejects(peer.request('tools/list'),/unavailable/i);
});

test('broken downstream stdin fails a pending MCP request instead of emitting an uncaught EPIPE',async()=>{
  const {spawn}=await import('node:child_process');
  const {McpPeer}=await import('../src/mcp-wire.mjs');
  const child=spawn(process.execPath,['-e','process.stdin.destroy();process.exit(3)'],{stdio:['pipe','pipe','ignore']});
  const peer=new McpPeer(child,{timeoutMs:500});
  await assert.rejects(peer.request('initialize',{protocolVersion:'2025-11-25'}),/Downstream|EPIPE|closed|exited|failed/i);
  peer.close();
});
