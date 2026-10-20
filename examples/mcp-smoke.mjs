// Real stdio MCP client smoke test (no SDK, no LLM). Prints no secrets.
// Dashboard must be running for the optional approval test.
import { spawn } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readJsonLines, sendJsonLine } from '../src/mcp-wire.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const processGateway=spawn(process.execPath,[resolve(root,'src/mcp-gateway.mjs')],{cwd:root,stdio:['pipe','pipe','inherit']});
let nextId=1;
const outstanding=new Map();
processGateway.on('exit', () => {
  for (const p of outstanding.values()) {clearTimeout(p.timer);p.reject(Error('MCP gateway exited before completing request.'));}
  outstanding.clear();
});
processGateway.stdin.on('error', error => {
  for (const p of outstanding.values()) {clearTimeout(p.timer);p.reject(error);}
  outstanding.clear();
});
readJsonLines(processGateway.stdout,{onMessage:message=>{
  const p=outstanding.get(message.id);
  if(p){outstanding.delete(message.id);clearTimeout(p.timer);if(message.error)p.reject(Error(message.error.message));else p.resolve(message.result);}
},onError:error=>{for(const p of outstanding.values())p.reject(error);outstanding.clear();}});
function request(method,params={}){
  const id=nextId++;
  return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>{outstanding.delete(id);reject(Error('MCP request timed out.'));},process.argv.includes('--approval') ? 105000 : 15000);
    outstanding.set(id,{resolve,reject,timer});
    sendJsonLine(processGateway.stdin,{jsonrpc:'2.0',id,method,params});
  });
}
function notify(method){sendJsonLine(processGateway.stdin,{jsonrpc:'2.0',method});}
try{
  const init=await request('initialize',{protocolVersion:'2025-11-25',capabilities:{},clientInfo:{name:'blackbox-smoke-client',version:'0.4.0'}});
  console.log(`Connected via MCP ${init.protocolVersion}: ${init.serverInfo.name}`);
  notify('notifications/initialized');
  const list=await request('tools/list');
  console.log('Exposed MCP tools:',list.tools.map(t=>t.name).join(', '));
  const read=await request('tools/call',{name:'read_note',arguments:{path:'notes.txt'}});
  console.log('Demo read:', read.isError ? 'failed' : 'allowed');
  const deny=await request('tools/call',{name:'read_note',arguments:{path:'.env'}});
  console.log('Credential read:',deny.isError ? 'blocked correctly' : 'UNEXPECTED ALLOW');
  if(!read.isError && deny.isError){
    if(process.argv.includes('--approval')){
      const name='mcp-smoke-'+Date.now()+'.txt';
      console.log(`Approval test: request new file ${name}; approve or deny it in http://localhost:4317`);
      const result=await request('tools/call',{name:'write_note',arguments:{path:name,content:'Created by a real external MCP client, after one-time approval.'}});
      console.log('Approval result:',result.isError?'denied or failed':'approved and completed');
    }else console.log('PASS: real downstream MCP read and policy denial.');
  }else process.exitCode=1;
}catch(error){console.error('MCP smoke failed:',error.message);process.exitCode=1;}
finally{processGateway.stdin.end();processGateway.kill('SIGTERM');}
